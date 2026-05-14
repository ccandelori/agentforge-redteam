# Demo script — agentforge-redteam

**Target length**: 4-5 minutes. Recorded against
`https://104-248-232-22.sslip.io/ui/`. Each section maps directly to
a reviewer concern from the audit.

## Pre-flight (do once, off-camera)

1. Have `.env` loaded so `WEB_UI_USER` / `WEB_UI_PASSWORD` are exported
   (you'll need them to log in to the BasicAuth-protected SPA).
2. Open a clean terminal in the repo root.
3. Open the SPA in a browser, sign in (the BasicAuth prompt fires once
   per browser session). Land on the **SESSION** page.
4. Confirm `/healthz` returns `{"status":"ok"}` if you want a 5-second
   liveness opener.
5. Wipe a fresh local DB so the regression replay demo is clean:
   `rm -f /tmp/regress_demo.db && PLATFORM_DB_PATH=/tmp/regress_demo.db uv run alembic upgrade head`

## Scene 1 — Intro (~30 s)

> "AgentForge Adversarial AI Security Platform — autonomous multi-agent
> red-teaming for the AgentForge Clinical Co-Pilot. Four LangGraph
> agents — Orchestrator, Red Team, Judge, Documentation — coordinate
> through a shared state machine. Independent model providers per role
> for conflict-of-interest separation: Claude Haiku for the
> Orchestrator, GPT-4o for the Red Team, Claude Sonnet for the Judge,
> Claude Haiku for the Documentation Agent."

Show the deployed UI's brand bar so the viewer sees this is live.

## Scene 2 — Six-category coverage (~45 s) — REVIEWER CONCERN #1

> "Reviewer asked: all 6 threat-model categories must be fully
> represented and easy to verify. Here's how to verify it."

- Click **COVERAGE** in the sidebar. Point at the category column —
  show all 6 distinct categories present:
  - data-exfiltration
  - dos-cost-amplification
  - identity-role-exploitation
  - prompt-injection-indirect
  - state-corruption
  - tool-misuse

- Cut to a terminal, run:
  ```bash
  ls rubrics/*.yaml | wc -l        # 6
  uv run python -c "import json, collections; \
    c = collections.Counter(s['category'] for s in \
    json.load(open('attack_library.json'))['attacks']); \
    print(dict(sorted(c.items())))"
  ```
  > "Six rubrics, 27 seeds across all six categories — minimum 3 per
  > stretch, 6 per MVP."

- One more terminal command for ground-truth coverage:
  ```bash
  for d in evals/judge_ground_truth/*/; do
    echo "$(basename "$d"): $(ls "$d" | wc -l | tr -d ' ') cases"
  done
  ```
  > "Ten judge-ground-truth cases per category, 60 total — the eval
  > harness can detect Judge drift across all six categories."

## Scene 3 — Live session, multi-turn, cost cap (~75 s) — REVIEWER CONCERNS #2 + #3 + multi-turn

Back to the **SESSION** page in the SPA.

> "Trigger a live session. Reviewer asked us to enforce the cost cap
> and to expand attack categories. Here's both at once."

- Set cost cap to **`30`** cents (use the input).
- Check **all 6 category checkboxes** (the audit specifically flagged
  that the UI used to expose only 3; now it's all 6).
- Click **START SESSION**. The "Session started" flash appears.
- Click into the **live activity card** that's now polling. Watch the
  step-by-step flow update: orchestrator → red_team call_target →
  judge evaluate_check_* → orchestrator (next campaign).

> "Multi-turn capability: when a seed's `max_turns: 3` is selected, the
> Red Team's mutation LLM gets prior turns as context and decides the
> next user message. Each turn embeds the prior conversation transcript
> into the payload so the stateless target sees a 'previously in this
> conversation' prefix."

(While the session runs in the background, narrate over the live
activity. When it halts within ~30-90 s, show the final cost line and
point out it's under the 30¢ cap.)

## Scene 4 — History page (~45 s) — REVIEWER CONCERN #4 (inspectability)

> "Reviewer asked us to make stored live run artifacts inspectable.
> Two new pages."

- Click **HISTORY**. Point at:
  - The just-completed session at the top
  - The `halt_reason` column (the one that just halted will show
    `no_progress`; older sessions show `budget_exhausted`,
    `dispatcher_timeout`, `dispatcher_crash:*`, etc.)
  - The `% used` column with progressive color (green / yellow / red)
  - The `Cost / Cap` columns proving the cap was respected

> "Every session ever dispatched on this platform, newest first.
> `halt_reason` and `ended_at` are persisted by the dispatcher on
> every terminal exit path — not just operator halt."

## Scene 5 — Findings detail + regression replay (~60 s) — REVIEWER CONCERN #5 (regression evidence)

- Click **FINDINGS** in the sidebar. Click any P3 finding to open the
  detail view.
- Show the polished prose, the framework mapping (OWASP / MITRE /
  HIPAA), and the sanitized evidence.

> "Three of these have been promoted to the regression corpus. The
> reviewer specifically asked: can a fresh checkout replay the corpus
> cleanly? Here it is."

Cut to terminal:
```bash
PLATFORM_DB_PATH=/tmp/regress_demo.db uv run agentforge-redteam regress \
    --target-sha demo-check --root evals/regressions
```

> "`held=6, regressed=0`. No FK errors, no rubric drift warnings — the
> SHA-keyed rubric cache loads the historical rubric bytes by content
> hash, so this scores against the rubric the Judge ACTUALLY used at
> promotion time, not the current rubric."

Click **REGRESSIONS** in the SPA. Point at the new rows that just
landed. Click **Detail** on any row to show the verdict_comparison
JSON drilled down.

## Scene 6 — Kill switch (~15 s)

- Click **HALT** in the sidebar. Big red button.
- Click it. Show the response: `{"status":"halted"}`.
- Show that any in-flight session would now be marked
  `halt_reason="operator_halt"` in the History view (or just narrate
  it — depends on whether you have an in-flight session).
- Click **RESUME** to clear it before the demo ends.

## Scene 7 — Outro (~20 s)

> "Continuous compliance with HIPAA §164.308(a)(1) AI-tool risk
> analysis. Six categories, 60 ground-truth cases, replayable
> regression corpus, full bug-and-fix history in
> `docs/BUG_LEDGER.md`, per-session evidence under
> `docs/EVIDENCE/`. All on `main` at the GitLab repo, deployed live
> at the URL you've been watching."

Optional one-line closer: hold the GitLab repo URL on screen for 3
seconds so viewers can pause-and-read.

---

## Reviewer-concern crosswalk

For the gradebook submission, here's exactly where each reviewer
concern is addressed in this demo:

| Reviewer concern | Demo scene | Repo evidence |
|---|---|---|
| All 6 threat-model categories represented | Scene 2 | `rubrics/*.yaml` (6 files), `attack_library.json` (27 seeds, 6 categories), `evals/judge_ground_truth/` (60 cases) |
| Cost cap enforcement | Scene 3 (cap honored), Scene 4 (% used column) | `agents/orchestrator.py:_DOC_AGENT_RESERVE_CENTS`, `tests/unit/test_orchestrator.py::test_orchestrator_node_doc_agent_reserve_halts_before_overshoot`, `docs/EVIDENCE/2026-05-13-session-86d8bace/` |
| Expanded attack categories | Scene 2 | Same as above + `prompts/redteam.md` multi-turn schema |
| Stored live run artifacts inspectable | Scene 4 (HISTORY) | `docs/EVIDENCE/` (5 packages), new `/sessions` API + `HistoryView.vue` |
| Regression replay inspectable + trustworthy | Scene 5 (replay + REGRESSIONS) | `docs/EVIDENCE/regression_replay/`, `src/agentforge_redteam/regression/rubric_cache.py`, alembic migration `0004` |
| Multi-turn attacks (THREAT_MODEL Cat 4 foundation) | Scene 3 (live session may pick a multi-turn seed) | `src/agentforge_redteam/agents/red_team.py:_run_multi_turn_attack`, `docs/EVIDENCE/2026-05-13-session-b1a35acc/multi_turn_transcripts.json` |

## What the demo does NOT show (and why that's OK)

- **Stretch-category findings live** — the deployed Co-Pilot defends
  Cat 4/5/6 attacks robustly; two scoped campaigns produced 0
  findings. Documented honestly in
  `docs/BUG_LEDGER.md` "Diagnosis-only" section. The eval-judge
  harness's 30 stretch ground-truth cases are the testable
  stretch-category proof; live promotions await better attack
  engineering.
- **A near-cap `budget_exhausted` halt live** — same blocker (the
  orchestrator halts on `no_progress` before reaching the budget gate
  at MVP attack-engineering scale). Unit test pins the budget-gate
  boundary instead.

Both are honest gaps documented in the BUG_LEDGER, not papered over.
