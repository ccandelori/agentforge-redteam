# NEXT-SESSION.md — agentforge-redteam

**Last updated**: 2026-05-13 (post cost-reduction + cache verification).

This file is the first thing to read at the start of any new session.
It supersedes the prior planning-era version. What's shipped, what's
broken, what to pick up next.

---

## Status

MVP + cost-reduction + cache verification all shipped. Live platform
at `https://104-248-232-22.sslip.io/ui` with HTTPS. Five live evidence
packages under [`docs/EVIDENCE/`](EVIDENCE/) tell the story end-to-end:
initial wedge → mutation parser fix → halt persistence → cost batch
(partly inactive) → Judge cache verified engaging (95.5% hit rate on
Sonnet). Six promoted regression cases under `evals/regressions/`
across three attack categories. Bug-find-and-fix history in
[`docs/BUG_LEDGER.md`](BUG_LEDGER.md). All code on `main`.

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

## What shipped this session (2026-05-13, most recent first)

```
4e35a78 docs(evidence): session f044fd18 — cache verified + 3 new regression cases
4e87725 docs(ledger): record cache verification + integer-cent rounding gap
33598cf obs(cost): structured-log Anthropic usage block per call
c6f55a9 perf(judge): inline rubric YAML in system prompt to engage Anthropic cache
abea14d docs(evidence): session ebd35d75 — cost-reduction batch verification
59f93cb perf(cost): prompt caching + Doc Agent Haiku + Red Team accounting
5b2070c docs(evidence): post-fix verification run + 2 new clean regression cases
4a64f3f docs(ledger): add docs/BUG_LEDGER.md as the rolling bug record
60178c9 docs(evidence): add fixes-derived-from-this-session table
227753d fix(web): persist halt_reason on manifests + 30-min session timeout
30e44e6 docs(evidence): correct misframing of session 29488fc5 verdicts
3a65339 fix(red_team): parse JSON envelope from mutation LLM response
4375fe1 feat(regress): wire real HTTPTargetClient + Anthropic Judge in CLI
5a45141 docs(evidence): package live session 29488fc5 + measured cost numbers
be0edf5 docs(reviewer): surface deployed platform URL, retire stale claims
```

15 commits direct-to-main, all green (649 tests, ruff/mypy clean).
Evidence packaged across 5 live sessions in `docs/EVIDENCE/`. Bugs
found-and-fixed indexed in `docs/BUG_LEDGER.md`.

## Known debt — prioritized

For the bug-and-fix history (closed items with full bug/impact/
resolution narrative), see [`docs/BUG_LEDGER.md`](BUG_LEDGER.md). This
section lists what's still open.

### High

1. **Doc Agent persistence ordering** (`agents/documentation.py:455`).
   GitLab issue creation runs BEFORE the `INSERT INTO findings`. A
   GitLab 401 / network blip kills the session before the finding is
   persisted to SQLite. **Fix**: INSERT first, then GitLab call;
   UPDATE the row's `gitlab_issue_id` after GitLab succeeds.

2. **Canary modulo bug** (`agents/orchestrator.py`, search
   `canary_every_n_campaigns`). `campaigns_run % N == 0` fires on
   campaign 0 — first run of every session is a canary. Currently
   masked by `canary_every_n_campaigns: 9999` in
   `orchestrator_policy.yaml`. **Fix**: `campaigns_run > 0 and
   campaigns_run % N == 0`. Then drop N back to a sensible value (10
   or 20) so drift detection actually runs.

3. **Cost cap leakage** (still open, observed live in session
   `f044fd18`: $0.75 cap, $1.16 actual). The orchestrator halts when
   its tally reaches the cap, but the Doc Agent's LLM call (~3¢ per
   finding) runs AFTER that halt and pushes total spend over.
   **Fix**: pre-budget the doc-agent cost when computing
   `proceed_or_halt`, or just subtract a 5¢ reserve from the
   effective cap.

4. **Wedge root cause not diagnosed.** Session `29488fc5` hung
   silently between campaigns 5 and 6. Symptom is now bounded by the
   30-min wall-clock timeout (commit `227753d`), but the underlying
   cause (most likely a hung Anthropic API call or a LangGraph
   routing deadlock) is unknown. Did NOT recur in any subsequent
   session, but no diagnosis means we can't say it won't.

### Medium

5. **`--categories` flag is captured but unused**
   (`session_runner.py:233` — `TODO(category-filter)`). The orchestrator
   enumerates from `rubrics/` directly. Wire it through so an operator
   can scope a run to one category. ~1 hour fix.

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

8. **Multi-turn attacks not implemented.** State and attack schema
   model a single `payload` (`state.py:49`, `attack_library.py:23`),
   not a turn sequence. THREAT_MODEL.md and ARCHITECTURE.md describe
   multi-turn capability that the code doesn't actually have.
   Architectural change (~half day): extend `AttackRecord` to a
   sequence of turns, update Red Team and Judge to handle.

9. **Legacy stub graph.** `src/agentforge_redteam/graph.py`
   `compile_graph()` still returns stubs. Production uses
   `graph_factory.build_production_graph`, but a reviewer importing
   `compile_graph()` gets the fake path. Either delete `graph.py`
   or have it re-export `build_production_graph`. ~15 min.

### Low

10. **Restore HTTP/2 on a domain migration**. `deploy/nginx-tls.conf`
    currently disables h2 because of a middlebox issue with
    `104-248-232-22.sslip.io` from the operator's network. When we
    move off this IP / hostname, put `http2` back on the `listen`
    directives.

11. **Tests for eager persistence path**. INSERT OR IGNORE in
    red_team / judge has tests that pass, but no test verifies the
    "INSERT happens mid-run before session end" property. Add an
    integration test that asserts SELECT count > 0 mid-LangGraph-run.

12. **Demo-time canary cadence**. With `canary_every_n_campaigns:
    9999`, the canary never fires. Once #2 is fixed, drop back to
    something like 10 — but the Sonnet 4.6 ground-truth cases may
    need re-authoring.

13. **Cache savings invisible in integer-cent reports** (see
    `BUG_LEDGER.md` Diagnosis corrections). Real Anthropic bill is
    ~22% lower than the platform reports on cache-heavy sessions
    (96K cache-read tokens × $3/1M × 0.9 saving rate). Conservative
    side. Fix is to defer ROUND_CEILING to session boundaries; ~30
    min change in `cost.py`.

14. **Haiku 4.5 caching does NOT engage** because Doc + Orchestrator
    system prompts are 920-1572 tok, below Haiku's 2048-tok cache
    minimum. Same silent-ignore pattern as the original Judge bug.
    To fix: pad those system prompts past 2048 tok with useful
    context (similar to Judge's rubric inlining).

### Closed since last update

The following items from the previous version of this list have
been resolved. Full bug/impact/resolution in `docs/BUG_LEDGER.md`:

- ~~`OpenAI mutation cost shows $0`~~ — fixed in commit `59f93cb`,
  verified showing 6¢ in session `ebd35d75`.
- ~~`Anthropic prompt caching deployed but inactive`~~ — fixed in
  commit `c6f55a9`, verified engaging in session `f044fd18` (96K
  cache-read tokens, 95.5% Sonnet hit rate).
- ~~`halt_reason not persisted`~~ — fixed in commit `227753d`,
  verified end-to-end in sessions `e2590f4c`, `ebd35d75`, `f044fd18`.
- ~~`Red Team mutation JSON envelope sent to target`~~ — fixed in
  commit `3a65339`, verified by clean payloads in subsequent sessions.

## Operator-led TODOs (final-gate gating items)

These are the things only an operator can do. Everything else
remaining is described in "Known debt" above.

- **Demo video + social post** (Task #50) — operator-led, ~30 min
  recording + edit, plus posting. Suggested script: open
  `https://104-248-232-22.sslip.io/ui/`, kick off a session via the
  SPA, show the live-activity card updating, drill into a finding
  detail, show the kill switch, mention the regression-corpus
  replay path (`agentforge-redteam regress`). Three live evidence
  packages already document the underlying functionality.
- **Submit the gradebook entry** — point at the deployed UI URL,
  the GitLab repo, `docs/EVIDENCE/`, `docs/BUG_LEDGER.md`, and the
  6 polished/promoted findings. README's "MVP Status" section
  already lists the right links.

The earlier Task #59 ("write up findings from the demo run") is
covered by `docs/EVIDENCE/` (5 sessions, 9 findings, 6 promoted
regression cases). Task #62 (TLS) shipped previously.

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

1. Fix #5 (`--categories` scoping) — wire the captured arg through
   to the orchestrator. Operator can finally scope a session.
2. Fix #9 (legacy stub graph) — delete or re-export. Removes a
   misleading import path for reviewers.
3. Fix #1 (Doc Agent persistence ordering) — INSERT-then-update.
   Removes a real-but-rare data-loss path.

All three are isolated, well-tested, and add real robustness. None
are required to ship final, but each closes a sharp edge.
