# Live evidence — Session `f044fd18-734e-415b-88bd-d4a937227b66`

Captured **2026-05-13** ~30 min after session `ebd35d75`. First run
against the deployed platform after commits `c6f55a9` (Judge
rubric-into-system refactor) and `33598cf` (`anthropic.usage`
structured logging) shipped to the droplet.

This is the **cache-engagement verification run**. Three things make
it the strongest evidence package in this directory:

1. **Cache engagement directly observed**, not inferred from cost
   deltas (which integer-cent rounding hides).
2. **9 new findings** across 3 attack families not previously in
   `evals/regressions/` — 3 promoted to expand the regression corpus.
3. **Honest measurement of platform-vs-real-bill divergence** — the
   platform reports $1.16 but the real Anthropic bill is ~$0.90 once
   you account for cache reads at 0.1× rate.

## Cache verification (the headline)

`docs/EVIDENCE/2026-05-13-session-f044fd18/anthropic_usage_excerpts.txt`
captures 100 `anthropic.usage` log lines from this session
(`journalctl -u agentforge-redteam-web.service | grep anthropic.usage`).
Aggregate stats:

| Model | Calls captured | Cache hits | Cache-read tokens | Cache-write tokens |
|---|---|---|---|---|
| `claude-sonnet-4-6` (Judge) | 66 | **63 (95.5%)** | 96,081 | 4,719 |
| `claude-haiku-4-5-20251001` (Doc + Orch) | 34 | **0 (0%)** | 0 | 0 |

**Sonnet caches almost every call** — the rubric-into-system refactor
(commit `c6f55a9`) cleanly engages Anthropic's cache, exactly as
designed. The 3 cache writes correspond to 3 distinct rubric-category
prefixes (one per category that ran in this session).

**Haiku doesn't cache at all** — confirms the `Haiku 4.5 cache minimum
is 2048 tokens` finding documented in `docs/BUG_LEDGER.md` Diagnosis
corrections. Doc Agent (~1572 tok) and Orchestrator (~920 tok)
prompts are below that threshold. The `cache_control` block is sent
but silently ignored. To get Haiku caching, those system prompts
would need to be padded above 2048 tokens (out of scope for this
batch).

## Real cost vs reported cost

Platform reported: **$1.16** (sum of integer-cent `cost_cents`
across 149 `agent_steps`).

Estimated real Anthropic bill on the Sonnet portion only:

| Sonnet token segment | Tokens | Rate | Cost |
|---|---|---|---|
| Cache reads (96,081 tok) | 96,081 | $3/1M × 0.1 | $0.0288 |
| (Same tokens uncached, hypothetical) | 96,081 | $3/1M × 1.0 | $0.2882 |
| **Cache savings on this session** | — | — | **~$0.2594** |

Platform's reported cost over-estimates the real Anthropic bill by
~$0.26 (~22% of reported total) on this session. Conservative side —
the cost cap halts earlier than the operator's real budget warrants —
but worth knowing about. See `docs/BUG_LEDGER.md` Diagnosis corrections
("Cache savings invisible in platform's own integer-cent cost
tracking") for the explanation and the path-to-fix if it ever matters.

## Cost-cap overshoot (separate known issue)

This session was triggered with a $0.75 cap and reported $1.16 — a
~$0.40 overshoot. That's the cost-cap leakage bug from
`docs/NEXT-SESSION.md` Known Debt #3 (Doc Agent runs after the
orchestrator's halt-on-budget check). Out of scope for this batch.

## What this run produced (numbers)

| Metric | Value |
|---|---|
| Total reported cost | $1.16 |
| Estimated real Anthropic bill (Sonnet portion adjusted) | ~$0.90 |
| Wall clock | 8 min 43 s |
| Campaigns | 9 |
| Findings | 9 (all P3, all clean payloads) |
| Halt reason | `budget_exhausted` |

Per-agent breakdown:

| Agent | Calls | Reported ¢ | Avg latency |
|---|---|---|---|
| orchestrator | 25 | 25 | 1.29 s |
| red_team | 41 | 16 | 5.12 s |
| judge | 66 | 66 | 2.97 s |
| documentation | 18 | 9 | 3.93 s |
| **Total** | **149** | **116** | — |

## New regression cases promoted

3 representative findings promoted to expand `evals/regressions/`
beyond the citation-fabrication-only coverage we had before:

| New case | Sub-attack family | Rubric anchored to |
|---|---|---|
| [`b08513e4-...json`](../../../evals/regressions/b08513e4-40cf-4170-a550-75b5a1d241ca.json) | `marker_token_reproduction` (BANANA) | prompt-injection-indirect |
| [`88e13da9-...json`](../../../evals/regressions/88e13da9-5901-4147-b815-07f190c3fe69.json) | data-exfiltration (cross-patient diabetes report) | **data-exfiltration** (first non-PII rubric in corpus) |
| [`4181c078-...json`](../../../evals/regressions/4181c078-4842-4a2d-948b-7a7bb7ac709d.json) | `system_prompt_revelation` | prompt-injection-indirect |

Total `evals/regressions/` is now **6 cases across 3 attack categories**.

The other 6 findings from this session were left in `findings/`
(local-sink output) but not promoted — they're variants of the same
patterns already covered above.

## Provenance

- DB snapshot: `var/platform_droplet_<timestamp>.db` (gitignored)
- DB SHA-256 + git SHA at capture: see `session_metadata.json`
- `anthropic_usage_excerpts.txt`: raw log lines, 100 entries
- Cross-references: `2026-05-13-session-29488fc5/` (initial wedge),
  `2026-05-13-session-e2590f4c/` (post-mutation-fix), and
  `2026-05-13-session-ebd35d75/` (post-cost-batch-but-cache-inactive)
  for the full delta story.
