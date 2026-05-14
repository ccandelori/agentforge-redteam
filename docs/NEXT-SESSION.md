# NEXT-SESSION.md — agentforge-redteam

**Last updated**: 2026-05-14 (post audit-response — Batches A/B/C).

This file is the first thing to read at the start of any new session.
It supersedes the prior planning-era version. What's shipped, what's
broken, what to pick up next.

---

## Status

MVP + audit response all shipped. Live platform at
`https://104-248-232-22.sslip.io/ui/` with HTTPS. **All 6 threat-model
categories** now have rubrics, ≥3 attack seeds each, and 10
judge-ground-truth cases each (60 total). Six promoted regression
cases in `evals/regressions/` (all anchored to MVP-judged attacks;
stretch promotions blocked on attack engineering, see Known Debt #4).
Regression replay runs cleanly from a fresh checkout (no FK errors,
no rubric-drift warnings — SHA-keyed rubric cache loads historical
bytes by content hash). Live evidence under
[`docs/EVIDENCE/`](EVIDENCE/) — 5 session packages + a regression
replay artifact. Bug-find-and-fix history (11 entries) in
[`docs/BUG_LEDGER.md`](BUG_LEDGER.md). 663 tests green;
ruff/format/mypy clean. All code on `main`.

For a fresh-checkout grader-friendly verification sequence, see the
"Verifying from a fresh checkout" section in
[`README.md`](../README.md).

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

## What shipped this session (2026-05-13/14, most recent first)

Audit-response batches:

```
7689883 feat(regression): SHA-keyed rubric cache + multi-turn full transcripts
679ecd6 docs(ledger): record Batch B status — ground truth done, stretch promotions blocked on attack engineering
9215f1a feat(eval): 30 new ground-truth cases (Cat 4/5/6) + doc-agent reserve test
a6be982 fix(audit-batch-a): regression replay clean + 6-cat surfacing
2a5842e ui(spa): rename Sessions page to History
a65769d feat(spa): Sessions + Regressions pages — Phase B inspectability
3705d7f docs(evidence): session b1a35acc — 6-category coverage + multi-turn live
fc354f6 feat(rubrics): add Categories 4/5/6 — 6 categories now fully represented
71074ba feat(red_team): adaptive multi-turn attacks with embedded conversation context
```

Earlier this session (cost reduction + cache verification):

```
fa781bb docs(ledger): record cost-cap leakage fix (entries 6 + 7)
6e39381 chore(format): ruff auto-format pass on orchestrator + anthropic_client
d73f2bc fix(cost): doc agent cents/dollars + budget gate doc-agent reserve
334b602 docs(session): refresh NEXT-SESSION.md after cost-reduction batch
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

24 commits direct-to-main, all green (663 tests, ruff/format/mypy clean).
Evidence packaged across 5 live sessions in `docs/EVIDENCE/` + a
regression replay artifact. Bugs found-and-fixed indexed in
`docs/BUG_LEDGER.md` (11 entries).

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

3. **Wedge root cause not diagnosed.** Session `29488fc5` hung
   silently between campaigns 5 and 6. Symptom is now bounded by the
   30-min wall-clock timeout (commit `227753d`), but the underlying
   cause (most likely a hung Anthropic API call or a LangGraph
   routing deadlock) is unknown. Did NOT recur in any subsequent
   session, but no diagnosis means we can't say it won't.

4. **Stretch-category regression promotions blocked on attack
   engineering.** Two live campaigns scoped to Cat 4/5/6 only
   (`f4bdbf6c` 100¢ cap, `a763e694` 200¢ cap) both halted at
   `no_progress` with **0 findings**. The deployed Co-Pilot defends
   the 9 stretch sub_attacks robustly. Need a focused
   attack-engineering pass (deeper multi-turn, better social
   engineering, less-defended target build) to land at least one
   stretch finding so it can be promoted to `evals/regressions/`.
   See `docs/BUG_LEDGER.md` "Diagnosis-only" section.

### Medium

5. **`/sessions/active` is in-memory per-uvicorn-worker**. Restart wipes
   the running-session set. Two workers each track their own. For the
   single-worker MVP it's fine; for prod move to a Redis-backed set
   or a `run_manifests.in_flight` boolean column.

6. **Worker process** (`web/app.py:_dispatch_session`). BackgroundTasks
   on the threadpool is fine for single-tenant demo; concurrent demos
   queue serially and could exhaust the threadpool. The architecture
   originally scoped a separate `agentforge-redteam-worker.service`
   that polls `run_manifests` for new rows — never built. Either build
   it or commit to BackgroundTasks + bump uvicorn `--limit-concurrency`.

7. **Legacy stub graph.** `src/agentforge_redteam/graph.py`
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

### Closed since last update (2026-05-13/14 — audit response)

The following items from earlier versions of this list have been
resolved. Full bug/impact/resolution in `docs/BUG_LEDGER.md`:

- ~~`Cost cap leakage`~~ — fixed in commit `d73f2bc` (doc agent
  cents/dollars + 5¢ doc-agent reserve in budget gate). Boundary
  unit test in commit `9215f1a` pins the reserve at the exact
  boundary. Verified live in session `86d8bace` (25¢ cap → $0.18
  actual).
- ~~`--categories flag captured but unused`~~ — wired through
  end-to-end in commit `a6be982` (orchestrator filter +
  graph_factory plumb + session_runner forward). Verified live
  in sessions `b1a35acc`, `f4bdbf6c`, `a763e694` (coverage_matrix
  shows only the requested categories ran).
- ~~`Multi-turn attacks not implemented`~~ — adaptive multi-turn
  with embedded conversation context shipped in commit `71074ba`,
  verified live in session `b1a35acc` (4 multi_turn_next calls,
  2 attacks with "Previously in this conversation:" prefix in
  attacks.payload). Full transcripts in
  `docs/EVIDENCE/2026-05-13-session-b1a35acc/multi_turn_transcripts.json`.
- ~~`Categories 4/5/6 not represented`~~ — 3 new rubrics + 9 new
  seeds in commit `fc354f6`; 30 new judge ground-truth cases (10
  per stretch) in commit `9215f1a`. Total: 6 rubrics, 27 seeds,
  60 ground-truth cases.
- ~~`Regression replay broken (FK errors, drift warnings)`~~ —
  fixed in commit `a6be982` (migration 0004 drops the FK,
  rubric_sha re-stamp on existing cases). Replay artifact captured
  in `docs/EVIDENCE/regression_replay/`.
- ~~`Harness records rubric_sha but doesn't load historical bytes`~~
  — fixed in commit `7689883` (SHA-keyed rubric cache module +
  harness wiring). Cache-hit unit test pins the new path; existing
  cache backfilled for the 6 promoted cases.
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
  recording + edit, plus posting. Detailed script:
  [`docs/DEMO_SCRIPT.md`](DEMO_SCRIPT.md) — walks through every
  reviewer concern in 4-5 minutes.
- **Submit the gradebook entry** — point at the deployed UI URL,
  the GitLab repo, `docs/EVIDENCE/`, `docs/BUG_LEDGER.md`, and the
  6 polished/promoted findings. README's "MVP Status" + "Verifying
  from a fresh checkout" sections give graders everything they
  need to verify claims.

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

1. Fix #7 (legacy stub graph) — delete `src/agentforge_redteam/graph.py`
   or have it re-export `build_production_graph`. Removes a
   misleading import path for reviewers. ~15 min.
2. Fix #1 (Doc Agent persistence ordering) — INSERT-then-update.
   Removes a real-but-rare data-loss path. ~30 min.
3. Fix #2 (canary modulo bug) — one-liner +
   `canary_every_n_campaigns: 10` policy bump. Then drift detection
   actually runs. ~15 min code; ground-truth re-baselining is the
   medium-effort follow-up.

All three are isolated, well-tested, and add real robustness. None
are required to ship final, but each closes a sharp edge.
