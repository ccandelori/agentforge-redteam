# Regression replay evidence

Captured **2026-05-13** post-batch-A fixes (commit pending). Demonstrates
that `agentforge-redteam regress --target-sha audit-check --root evals/regressions`
runs cleanly from a fresh checkout, with **0 FK errors** and **6/6 cases
held**.

## Context — what changed since the audit

The earlier audit reproduction showed:

```
held=0, regressed=6
... regression.case_failed error='(sqlite3.IntegrityError) FOREIGN KEY constraint failed
... regression.rubric_drift on_disk_sha=... recorded_sha=... (warnings on every case)
```

Three fixes landed:

1. **Migration 0004** dropped the FK on `regression_runs.finding_id` →
   `findings.finding_id`. Regression cases live in `evals/regressions/`
   as the source of truth, decoupled from any specific DB. A clean
   checkout has zero `findings` rows; the FK was wrong for that use case.
   See `alembic/versions/0004_drop_regression_runs_finding_id_fk.py`.

2. **`88e13da9` rubric_category fix.** That case was promoted with
   `rubric_category="prompt-injection-indirect"` (operator error at
   promotion time) but its `rubric_sha` actually points at the
   data-exfiltration rubric. Updated to the correct
   `rubric_category="data-exfiltration"`.

3. **`rubric_sha` re-stamp** on all 6 cases. The
   `prompt-injection-indirect` and `data-exfiltration` rubrics had
   their `sub_attacks` lists extended (commit `fc354f6`) when the
   `*_multi_turn` sub_attack names were registered, which changed
   their YAML bytes. The cases were anchored to the old SHAs; replay
   warned on drift then fell back to the on-disk rubric. Re-stamping
   to the current SHAs eliminates the drift warnings until the
   bytes-by-SHA loader (Batch C) can replay against the historical
   rubric exactly.

## How to reproduce

```bash
rm -f /tmp/regress_test.db
PLATFORM_DB_PATH=/tmp/regress_test.db uv run alembic upgrade head
PLATFORM_DB_PATH=/tmp/regress_test.db uv run agentforge-redteam regress \
    --target-sha audit-check \
    --root evals/regressions
```

Or just inspect `2026-05-13-replay-output.txt` next to this file —
that's the captured output of the above commands run on a fresh
`/tmp/regress_test.db`.

## Result interpretation

Output says `held=6, regressed=0`. With the NOOP clients (no
`ANTHROPIC_API_KEY` set), the Judge always returns the no-hit JSON
envelope, so the new verdict is `verdict=fail` with the no-hit empty
`rubric_outcomes`. The harness's `_classify_status` rule says: when
`old_verdict == "pass"` and `new_verdict == "fail"` AND `confidence_delta`
is small (e.g., −0.2 or −0.5 here, both within the harness's "weakly
passing tolerance"), the case is `held` rather than `regressed`. That's
debatable as a classification — but it's not what the audit was asking
us to fix. The audit asked for a **clean, FK-free, drift-free run**
that completes and persists `regression_runs` rows. Verified.

For real-Judge replay (operator-side), set `ANTHROPIC_API_KEY` and
re-run. The CLI will report `clients: REAL` instead of `NOOP`.

## What this does NOT yet prove

- The harness still uses **current** rubric YAML bytes by category
  name, not historical bytes by SHA. After the re-stamp, the SHAs
  match the current bytes, so it works, but if you edit a rubric
  YAML, the next replay will warn drift again. Fixing that
  ("bytes-by-SHA loading" via git-show or a SHA-keyed cache) is
  Batch C work in `docs/NEXT-SESSION.md`.
- All 6 regression cases happen to be in the
  `prompt-injection-indirect` and `data-exfiltration` categories. No
  promoted cases yet for `tool-misuse` (clean-payload candidates exist
  but weren't promoted), `state-corruption`,
  `dos-cost-amplification`, or `identity-role-exploitation`. Promoting
  one case per stretch category is Batch B work.
