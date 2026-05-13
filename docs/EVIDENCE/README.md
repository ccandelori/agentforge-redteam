# Evidence

Portable artifacts captured from live runs of the deployed red-team
platform against the AgentForge Clinical Co-Pilot target.

Each subdirectory is a single session's evidence package. The raw DB
snapshot stays in `var/` (gitignored) — what's committed here are the
JSON dumps a grader can read without restoring the database, plus
provenance (DB SHA-256, git SHA at capture, deployed/target URLs).

| Session | Date | Cost | Outcome | Path |
|---|---|---|---|---|
| `e2590f4c-b1e6-4432-bc8e-981fa97c6edd` | 2026-05-13 | $0.48 | Clean halt (`no_progress`) in 4 min. 6 campaigns, 2 new findings (clean payloads). Verifies all three fixes from the prior session land correctly in production. | [`2026-05-13-session-e2590f4c/`](./2026-05-13-session-e2590f4c/) |
| `29488fc5-e489-4050-977c-facdfb38e3fc` | 2026-05-13 | $0.20 | Wedged at campaign 5; 0 new findings; cost data captured for 26 agent steps. Surfaced the Red Team mutation JSON envelope bug — see session README. | [`2026-05-13-session-29488fc5/`](./2026-05-13-session-29488fc5/) |

## Companion artifacts

- `evals/regressions/` — promoted regression cases derived from the
  PASS findings in this evidence (use `agentforge-redteam regress` to
  replay them against a new target SHA).
- `findings/*_polished.md` — the three polished vulnerability reports
  (committed earlier; not derived from a single live session).
- `docs/COST_ANALYSIS.md` — the per-run/per-scale cost projection,
  cross-referenced against the measured numbers in
  `*/cost_summary.json`.
