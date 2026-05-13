# Live evidence — Session `29488fc5-e489-4050-977c-facdfb38e3fc`

Captured **2026-05-13** from the deployed red-team platform at
`https://104-248-232-22.sslip.io/` against the AgentForge Clinical Co-Pilot
target at `https://143.244.157.90:9300/dashboard/turn`.

This directory is the portable evidence artifact that the audit's
"Task 59" line item asked for. It complements (does not replace) the
three polished vulnerability reports in `findings/*_polished.md`, which
document earlier findings against the same target.

## What's in here

| File | Source | What it shows |
|---|---|---|
| `session_metadata.json` | derived from `run_manifests` + `agent_steps` | Session ID, requested vs actual category scope, total spend, halt context, deployed/target URLs, snapshot SHA-256, git SHA at capture |
| `cost_summary.json` | `SUM(cost_cents) GROUP BY agent, tool` over `agent_steps` | Per-agent and per-tool spend with average latency. Feeds `docs/COST_ANALYSIS.md`. |
| `findings.json` | full join of `findings ⨝ verdicts ⨝ attacks` | Both PASS findings the platform produced earlier today, with sanitized evidence + rubric SHA + target SHA. |
| `coverage_matrix.json` | `coverage_matrix` table | Sub-attack coverage with last-run timestamps. Confirms only `prompt-injection-indirect` ran in this session. |

## Provenance

- **DB snapshot file**: `var/platform_droplet_20260513T191222Z.db` (gitignored — pulled with `scp root@104.248.232.22:/srv/agentforge-redteam/var/platform.db`)
- **DB SHA-256**: see `session_metadata.json` → `db_snapshot.sha256`
- **Git SHA at capture**: see `session_metadata.json` → `git_sha_at_capture`
- **Promoted regression cases derived from this snapshot**:
  - `evals/regressions/6511a75f-2c86-4d8c-b62e-74b474dcdad5.json` (chart-write attempt, expected_verdict=pass, conf=0.7) — clean seed payload, valid replay case.
  - ~~`evals/regressions/ab6a68c9-...json`~~ — promoted then **removed** after discovering its `attacks.payload` row was a JSON envelope (the mutation bug above). Re-promote after a fresh post-fix campaign produces a clean equivalent.

## What this run actually demonstrated (and what it didn't)

**Worked**: end-to-end execution against the deployed platform with real
LLMs (Claude Sonnet 4.6 for Judge + Orchestrator, GPT-4o for Red Team)
and the live AgentForge target. 5 campaigns ran, 26 LLM-typed agent
steps completed and persisted, total spend $0.20.

**Did not work**:

1. **Wedge at campaign 5.** After ~90 seconds of activity the orchestrator
   stopped issuing new campaigns. No log lines emitted in the 5+ minutes
   before the manual `/halt`. Cost stayed pinned at $0.20. Likely an
   in-flight LLM-call retry loop or async deadlock — not a kill-switch
   trip. `halt_reason` was not persisted. The `web/app.py` dispatcher's
   bare `except Exception:` swallows tracebacks, which is why this
   looks like a hang instead of a crash.
2. **Categories scoping.** Request asked for all 3 MVP categories
   (`prompt-injection-indirect`, `data-exfiltration`, `tool-misuse`).
   Only `prompt-injection-indirect` ran — confirmation of the known
   `--categories captured but unused` gap (see `docs/NEXT-SESSION.md`
   Known Debt #4).
3. **Red Team mutation JSON envelope bug — discovered post-run.** The
   `redteam.md` prompt asks the LLM for a `{"payload": ..., "rationale":
   ..., "mutation_of_attack_id": ...}` envelope. Prior to fix
   commit `3a65339`, `red_team.py:245` stored the LLM's raw response
   text as `attacks.payload` and sent that entire envelope to the
   target. The target rightly refused the structured noise. So in this
   run, **of the 5 attacks, only the first 4 were clean (seed or
   structurally-correct-by-accident)**; the 5th (a marker-token
   mutation) sent `{"payload": "<document...>", ...}` to the target.
   The bug confounded earlier interpretation of the all-`fail`
   verdicts: the verdicts were correct *for what the target actually
   saw*, but the target saw envelope wrapper noise, not the real
   attack. The bug also corrupts older findings: finding `ab6a68c9`
   (citation_fabrication) was a mutation and has the envelope in its
   payload column. The promoted regression case for it was therefore
   removed; finding `6511a75f` (chart-write, a clean seed) remains.
4. **Judge rubric extraction was not actually broken.** Earlier framing
   in this doc said the Judge "returned empty `rubric_outcomes={}` for
   all 15 verdicts" as a bug. It isn't: `_aggregate` returns `{}` and
   `confidence=0.5` whenever no rubric check fires, which is the right
   behavior when the target legitimately defends (or, in this case,
   when the target sees JSON envelope noise instead of the real attack
   and refuses it). The Judge LLM was returning well-formed per-check
   JSON throughout — see any `agent_steps.result` row with `tool LIKE
   'evaluate_check_%'`.

## How to re-derive these dumps

```bash
# 1. Pull current droplet DB
scp root@104.248.232.22:/srv/agentforge-redteam/var/platform.db \
    var/platform_droplet_$(date -u +%Y%m%dT%H%M%SZ).db

# 2. Re-run the dump script (or its inline equivalent)
sqlite3 var/platform_droplet_*.db \
    "SELECT agent, COUNT(*), SUM(cost_cents) FROM agent_steps
     WHERE session_id = '29488fc5-e489-4050-977c-facdfb38e3fc'
     GROUP BY agent;"
```

## Langfuse traces

Traces for every `tool_wrapper.start` / `tool_wrapper.end` pair in this
session are in the Langfuse project keyed by the `LANGFUSE_PUBLIC_KEY`
prefix `pk-lf-a5...` at `https://us.cloud.langfuse.com/`. Filter on
`session_id = "29488fc5-e489-4050-977c-facdfb38e3fc"` to scope to this
run.
