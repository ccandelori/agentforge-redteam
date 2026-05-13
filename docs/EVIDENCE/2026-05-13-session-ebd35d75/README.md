# Live evidence — Session `ebd35d75-66d4-4dbf-a186-ade0ff90d6de`

Captured **2026-05-13** ~30 min after session `e2590f4c`. First run
against the deployed platform after commit `59f93cb` shipped the
cost-reduction batch (Doc Agent → Haiku, Red Team accounting fix,
Anthropic prompt caching).

This evidence package documents an **honest mixed result**: two of
three fixes work cleanly in production; one is deployed-but-inactive
because of a precondition we missed.

## What this run actually verifies

| Fix | Pre-fix | Post-fix | Effect | Verdict |
|---|---|---|---|---|
| **Doc Agent: Sonnet → Haiku** (`59f93cb`) | 5¢ / 4 calls (1.25¢/call), avg latency 9.79 s | 2¢ / 4 calls (0.50¢/call), avg latency 3.81 s | **−60% cost, 2.5× faster** | **Working as designed** |
| **Red Team accounting** (`59f93cb`) | 0¢ / 17 calls (broken — `cost_estimator` not passed to `call_tool`) | 6¢ / 16 calls (~0.4¢/call) | Previously-hidden ~12% of session cost now correctly attributed | **Working as designed** |
| **Anthropic prompt caching on Judge** (`59f93cb`) | 32¢ / 32 calls (1.00¢/call) | 30¢ / 30 calls (1.00¢/call) | **No change** at sub-cent precision | **Deployed but inactive** — see below |

### Why the Judge cache didn't engage

`prompts/judge.md` is **3,197 chars ≈ 799 tokens**. Anthropic's cache
minimum for Claude Sonnet 4.6 is **1024 tokens**. Below that, the
`cache_control` block is sent in the request but silently ignored by
the API — there is no error, just no cache. The per-call Judge cost
in this session is identical to the pre-fix session at integer-cent
precision, which is consistent with no caching engaging.

This was a **silent precondition violation**: the patch is correct;
it just doesn't have any prefix long enough to cache. Real fix
options are described in `docs/BUG_LEDGER.md` under "Diagnosis
corrections."

## What this run produced

| Metric | Value |
|---|---|
| Total cost | $0.48 (cap $0.75) |
| Wall clock | 3 min 17 s |
| Campaigns | 6 |
| Findings | 2 (`88e8c6f5`, `c0ed03b4` — both citation_fabrication variants) |
| Halt reason | `no_progress` (clean orchestrator policy halt) |

### Findings — not promoted

Both findings are slight variants of `dc448e8d` (already in
`evals/regressions/` from session `e2590f4c`). Same payload family
(citation fabrication on dose recommendations), same target response
shape, same verdict. Promoting them adds redundant coverage to the
regression corpus without exercising new attack surface, so we **left
them in `findings/` but did not promote**.

If a future session produces a finding in a category we don't yet
cover (e.g. `tool-misuse` mutations, `data-exfiltration` PHI bleed),
that's worth promoting.

## What "the headline cost stayed the same" actually means

Naively reading `total_cost_cents = 48` for both sessions suggests
nothing changed. The breakdown shows otherwise:

```
documentation:  5¢ → 2¢   (real -3¢)   - Haiku swap
judge:          32¢ → 30¢ (real -2¢)   - within rounding noise
orchestrator:   11¢ → 10¢ (real -1¢)   - within rounding noise
red_team:       0¢ → 6¢   (was hidden) - accounting was broken
─────────────────────────────────────────────────────────────
TOTAL:          48¢ → 48¢ but this is more accurate
```

The honest read is: **~6¢ of real savings on the visible side, ~6¢ of
newly-surfaced previously-hidden cost on the Red Team side**. They
cancel in the headline. The platform now reports a number that
matches what the Anthropic + OpenAI bill will actually show.

## Provenance

- DB snapshot: `var/platform_droplet_<timestamp>.db` (gitignored)
- DB SHA-256 + git SHA at capture: see `session_metadata.json`
- Companion sessions for delta comparison:
  - [`2026-05-13-session-29488fc5/`](../2026-05-13-session-29488fc5/) (pre-fix wedge)
  - [`2026-05-13-session-e2590f4c/`](../2026-05-13-session-e2590f4c/) (first post-mutation-fix verification)
