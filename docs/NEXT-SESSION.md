# NEXT-SESSION.md — agentforge-redteam

**Last updated**: 2026-05-12 (late-night demo-prep session).

This file is the first thing to read at the start of any new session.
It supersedes the prior planning-era version. What's shipped, what's
broken, what to pick up next.

---

## Status

MVP shipped. The Week 3 demo recording is happening against a live
Co-Pilot at `https://104-248-232-22.sslip.io/ui` with HTTPS, real
agents, real findings persisting live to the UI. All code on `main`.

## Live URLs

| What | URL |
|---|---|
| Operator UI | `https://104-248-232-22.sslip.io/ui` |
| Healthz | `https://104-248-232-22.sslip.io/healthz` |
| Langfuse traces | `https://us.cloud.langfuse.com` (project `pk-lf-a5…`) |
| GitLab repo | `https://labs.gauntletai.com/cameroncandelori/agentforgeredteam` |

BasicAuth credentials live in `/etc/agentforge-redteam/redteam.env` on
the droplet (`WEB_UI_USER` / `WEB_UI_PASSWORD`). API keys (Anthropic,
OpenAI, Langfuse, AgentForge JWT secret) also there.

## Common commands

```bash
# Deploy current main to droplet (laptop side)
./deploy/push.sh

# Backend-only changes (skip the SPA rebuild)
./deploy/push.sh --skip-build

# Wipe all session data on droplet (kill_switch row preserved)
ssh root@104.248.232.22 'sudo -u agentforge-redteam sqlite3 /srv/agentforge-redteam/var/platform.db <<SQL
DELETE FROM human_approval_queue; DELETE FROM findings;
DELETE FROM regression_runs; DELETE FROM verdicts;
DELETE FROM attacks; DELETE FROM coverage_matrix;
DELETE FROM agent_steps; DELETE FROM run_manifests;
SQL
systemctl restart agentforge-redteam-web.service'

# Trigger a session via the JSON API (same shape the SPA POSTs)
set -a && source .env && set +a
curl -u "$WEB_UI_USER:$WEB_UI_PASSWORD" \
    -X POST https://104-248-232-22.sslip.io/sessions/start \
    -H "Content-Type: application/json" \
    -d '{"cost_cap_cents": 25, "target": "droplet_prod", "categories": ["prompt-injection-indirect"]}'

# Watch live counters
curl -u "$WEB_UI_USER:$WEB_UI_PASSWORD" \
    https://104-248-232-22.sslip.io/sessions/active | python3 -m json.tool

# Tail droplet logs
ssh root@104.248.232.22 'journalctl -u agentforge-redteam-web.service -f'

# Run a session locally (writes to ./var/platform.db, not droplet)
set -a && source .env && set +a
uv run agentforge-redteam start-session \
    --target droplet_prod --cost-cap-cents 25 \
    --categories prompt-injection-indirect --max-campaigns 5

# CI: laptop-side runner picks up any push automatically
git push origin <branch>
```

## What shipped today (most recent first)

```
d5d6347 fix(deploy): drop HTTP/2 from TLS listener — middlebox compat
f69e586 feat(deploy): TLS via Let's Encrypt against sslip.io hostname
337c5c3 chore(format): ruff format pass
6f82807 chore(lint): ruff auto-fix import + __slots__ ordering
23858eb fix(env): clarify LANGFUSE_HOST regional choice in .env.example
d351aee feat(spa): live polling, session status badge, live-activity card
902fcb7 feat(web): BackgroundTasks dispatch + /sessions/active live counters
579f648 feat(coverage): audit_log_evasion seed + canary suppression + recursion bump
4d27962 fix(documentation): strip markdown JSON fences from doc agent LLM output
d4d96f9 fix(judge): accept overall-verdict JSON, strip markdown fences, persist verdicts
4f3954d feat(agents): eager attacks/verdicts/coverage_matrix persistence
2075745 feat(target): integrate AgentForge Clinical Co-Pilot LLM endpoint
06b9356 chore(models): rename claude-sonnet-4-20250514 → claude-sonnet-4-6
1456984 fix(langfuse): migrate to v4 SDK
5651e98 chore(deps): add pyjwt for AgentForge sidecar JWT minting
781671e chore(gitignore): exclude Claude Code session state
```

13 commits via MR !2 + a few direct-to-main ops fixes after.

## Known debt — prioritized

### High

1. **Doc Agent persistence ordering** (`agents/documentation.py:455`).
   GitLab issue creation runs BEFORE the `INSERT INTO findings`. A
   GitLab 401 / network blip kills the session before the finding is
   persisted to SQLite. **Fix**: INSERT first, then GitLab call;
   UPDATE the row's `gitlab_issue_id` after GitLab succeeds.
   Surfaced today when a stale GITLAB_TOKEN crashed the doc agent and
   we had to clear the env to fall back to LocalFindingsSink.

2. **Canary modulo bug** (`agents/orchestrator.py`, search
   `canary_every_n_campaigns`). `campaigns_run % N == 0` fires on
   campaign 0 — first run of every session is a canary. Currently
   masked by `canary_every_n_campaigns: 9999` in
   `orchestrator_policy.yaml`. **Fix**: `campaigns_run > 0 and
   campaigns_run % N == 0`. Then drop N back to a sensible value (10
   or 20) so drift detection actually runs.

3. **Cost cap leakage**. The orchestrator halts when its tally reaches
   the cap, but the Doc Agent's LLM call (~3¢ per finding) runs AFTER
   that halt and pushes total spend over. Saw a 30¢-cap session land
   at 38¢. **Fix**: pre-budget the doc-agent cost when computing
   `proceed_or_halt`, or just subtract a 5¢ reserve from the
   effective cap.

### Medium

4. **`--categories` flag is captured but unused**
   (`session_runner.py:233` — `TODO(category-filter)`). The orchestrator
   enumerates from `rubrics/` directly. Wire it through so an operator
   can scope a run to one category.

5. **OpenAI mutation cost shows $0**. `red_team.generate_mutation` (88
   calls in one run) reported 0¢. Either `OpenAIClient` returns
   `cost_cents=0` for `gpt-4o-2024-08-06`, or the model id missed the
   `PRICING_TABLE`. Check `clients/openai_client.py` + `cost.py`.

6. **`/sessions/active` is in-memory per-uvicorn-worker**. Restart wipes
   the running-session set. Two workers each track their own. For the
   single-worker MVP it's fine; for prod move to a Redis-backed set
   or a `run_manifests.in_flight` boolean column.

7. **Worker process** (`web/app.py:_dispatch_session`). BackgroundTasks
   on the threadpool is fine for single-tenant demo; concurrent demos
   queue serially and could exhaust the threadpool. The architecture
   originally scoped a separate `agentforge-redteam-worker.service`
   that polls `run_manifests` for new rows — never built. Either build
   it or commit to BackgroundTasks + bump uvicorn `--limit-concurrency`.

### Low

8. **Restore HTTP/2 on a domain migration**. `deploy/nginx-tls.conf`
   currently disables h2 because of a middlebox issue with
   `104-248-232-22.sslip.io` from the operator's network. When we
   move off this IP / hostname, put `http2` back on the `listen`
   directives.

9. **Tests for eager persistence path**. New INSERT OR IGNORE in
   red_team / judge has tests that pass, but no test verifies the
   "INSERT happens mid-run before session end" property. Add an
   integration test that asserts SELECT count > 0 mid-LangGraph-run.

10. **Demo-time canary cadence**. With `canary_every_n_campaigns:
    9999`, the canary never fires. Once #2 is fixed, drop back to
    something like 10 — but the Sonnet 4.6 ground-truth cases may
    need re-authoring (Sonnet calibrates differently than the
    older Sonnet the cases were written against).

## Operator-led TODOs

- **Task #50** — demo video + social post: video should be in your
  hands by the time you read this; post wherever.
- **Task #59** — write up findings from the demo run for the
  deliverable. Real PASS verdicts are in `var/platform.db` on the
  droplet (or laptop's `var/platform.db`). Polished markdown reports
  in `/srv/agentforge-redteam/findings/` on droplet.
- **Task #62** — TLS ✅ shipped today.

## Architecture cheat sheet

- **Agents** (`src/agentforge_redteam/agents/`): orchestrator, red_team,
  judge, documentation. Each is an async fn taking `PlatformState` →
  `PlatformState` and registered as a LangGraph node by
  `graph_factory.build_production_graph`.
- **Eager persistence**: agents `INSERT OR IGNORE` to SQLite mid-run so
  the UI sees rows live. `agent_steps` populated by the audit wrapper;
  `attacks` / `verdicts` / `coverage_matrix` / `findings` /
  `human_approval_queue` by the agents themselves.
- **Web**: FastAPI at `/`, Vite-built Vue 3 SPA at `/ui/`,
  BackgroundTasks dispatcher hangs off `POST /sessions/start`.
  `/sessions/active` polled every 3s by the SPA for the live-activity
  card.
- **Target**: `HTTPTargetClient` in `graph_factory.py` mints HS256 JWTs
  against the AgentForge sidecar's `AGENTFORGE_JWT_SECRET`, POSTs to
  `https://143.244.157.90:9300/dashboard/turn`, parses SSE.
- **Deploy**: `./deploy/push.sh` (laptop side) — build + rsync + nginx
  config + alembic upgrade + service restart + smoke. Picks
  `nginx-tls.conf` automatically when the Let's Encrypt cert exists,
  else `nginx-http-only.conf`.
- **CI**: GitLab pipeline (`lint → type-check → test`) runs on a
  Docker-executor `gitlab-runner` registered to the laptop. Stays
  alive while laptop is awake. eval-judge job is tag-only and
  `allow_failure: true` until `ANTHROPIC_API_KEY` is a CI variable.

## Quick wins for the next 30 minutes (if that's all the time we have)

1. Fix #1 (Doc Agent ordering) — small refactor in `documentation.py`,
   adds resilience.
2. Fix #2 (canary modulo) — one-liner + drop policy back to `N=10`.
3. Fix #5 (OpenAI cost tracking) — likely a model-id mismatch in the
   `PRICING_TABLE`. 5-min diagnose, 1-line fix.

All three are isolated, well-tested, and add real robustness.
