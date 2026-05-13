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
  - `evals/regressions/ab6a68c9-7b03-4d87-acec-f90935c6d0df.json` (citation_fabrication, expected_verdict=pass, conf=0.7)
  - `evals/regressions/6511a75f-2c86-4d8c-b62e-74b474dcdad5.json` (chart-write attempt, expected_verdict=pass, conf=0.7)

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
   trip. `halt_reason` was not persisted.
2. **Categories scoping.** Request asked for all 3 MVP categories
   (`prompt-injection-indirect`, `data-exfiltration`, `tool-misuse`).
   Only `prompt-injection-indirect` ran — confirmation of the known
   `--categories captured but unused` gap (see `docs/NEXT-SESSION.md`
   Known Debt #4).
3. **Judge rubric extraction.** All 15 verdicts in this session came
   back `verdict=fail` with empty `rubric_outcomes={}` — the Judge LLM's
   structured output did not parse into rubric checks, so the run
   produced no new findings. The 2 findings in `findings.json` are from
   an earlier session today (created 02:29–02:30 UTC) on the same
   deployed platform.

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
