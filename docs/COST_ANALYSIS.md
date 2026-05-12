# Cost Analysis at Scale

**Status:** projection-only. Live measurements pending Task 59 (deployed campaign).
**Pricing snapshot:** 2026-05-12, per `src/agentforge_redteam/cost.py`'s `PRICING_TABLE`.
**Audience:** operators planning capacity, reviewers grading the final gate's AI Cost Analysis requirement, and future-me at quarterly pricing-revalidation time.

---

## TL;DR

| What | Value |
|---|---|
| Headline per-run cost (worst case: full pipeline + confirmed finding + 4 LLM-typed Judge checks) | **$0.08** USD (8 cents) |
| Per-run weighted average (10% finding rate, sub-cent precision) | **$0.0283** USD |
| Hard per-campaign cap (orchestrator policy) | $0.50 (50 cents) |
| Hard per-session cap (orchestrator policy) | $10.00 (1000 cents) |
| 100 runs (baseline, no optimizations) | **$2.83** |
| 1,000 runs (Anthropic prompt caching on Judge) | **$22.30** |
| 10,000 runs (+ batch API on non-canary Judge calls, + OpenRouter fallback at Red Team) | **$132.00** |
| 100,000 runs (+ payload deduplication via epsilon-greedy replay) | **$1,056.00** |

The architecture is shaped to keep **marginal cost-per-run sub-linear**: at 100K it averages **$0.0106/run** vs. the linear-extrapolation $0.0283/run — a 63% drop driven entirely by levers already exposed at the model-config / wrapper layer (no code rewrites).

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Per-run Cost Model](#per-run-cost-model)
3. [Cost at Scale](#cost-at-scale)
4. [Cost-control Architecture](#cost-control-architecture)
5. [Architectural Levers](#architectural-levers)
6. [Honesty: Limitations and Caveats](#honesty-limitations-and-caveats)
7. [Recommendations by Scale](#recommendations-by-scale)
8. [Methodology Footer](#methodology)

---

## Executive Summary

A "run" in this platform is one orchestrator-selected campaign that fully executes: the Orchestrator chooses a `(category, sub_attack)`, the Red Team generates and dispatches a payload, the Judge evaluates against the rubric, and (sometimes) the Documentation Agent renders a finding. Each step is one or more LLM calls accounted in integer cents through `cost.py`.

Per-run cost ranges roughly **$0.05–$0.10** depending on payload size, mutation depth, rubric check count, and whether a finding is filed. The **headline figure of $0.08** is the worst case modeled by the acceptance smoke test: full pipeline, 4 LLM-typed Judge checks, a confirmed finding routed through the Documentation Agent. Using sub-cent precision and a 10% finding rate, the **weighted average drops to $0.0283/run**.

At 100K platform runs, the linear projection ($2,830) lands in the low-four-figures. With the levers built into the architecture — Anthropic prompt caching on the Judge system prompt, batch API on non-canary verdicts, OpenRouter fallback at the Red Team layer, and epsilon-greedy payload deduplication — the **100K projection drops to ~$1,056**, sub-linear at scale.

**This document is a projection, not a measurement.** Live numbers will follow Task 59. The token-per-call estimates are reasoned from prompt sizes, the 15-entry `attack_library.json`, and typical chat-completion response volumes; they are pinned by the deterministic per-step computation embedded at the bottom of this doc.

---

## Per-run Cost Model

### What counts as one run

```
Orchestrator → Red Team → Target HTTP → Judge → [Documentation]
   1 call       0 or 1     (not billed)  3–5     0 or 1
```

- **Orchestrator** runs once per run: reads SQLite coverage / cost-per-category, returns a `CampaignBrief` (category, sub_attack, seed_payloads, mutation_budget, cost_budget).
- **Red Team** issues 1 LLM call when mutation is needed; the seed-only path skips the LLM and is free of model cost (the target HTTP call is not a billed model from the platform's perspective).
- **Judge** runs each LLM-typed check as a **separate** API call. The MVP rubrics declare 2–3 `type: llm` checks each (see `rubrics/*.yaml`); the projection assumes growth to 4 LLM checks as rubrics mature post-MVP. The smoke test uses 4 as the conservative ceiling.
- **Documentation Agent** runs only when the Judge declares a finding. P0/P1 also enqueue for human review — that operational cost is out of scope here (see Limitations).

### Token-per-call assumptions

These numbers are reasoned, not measured. Sources of the estimate:

| Agent | Model (from agent defaults) | Prompt tokens | Completion tokens | Calls / run | Reasoning |
|---|---|---|---|---|---|
| Orchestrator | `claude-haiku-4-5-20251001` | ~800 | ~200 | 1 | System prompt + coverage snapshot serialized as JSON. Output is a compact `CampaignBrief` rationale. |
| Red Team | `gpt-4o-2024-08-06` | ~600 | ~300 | 0 or 1 | System prompt (~250 tok) + seed payload (`attack_library.json` payloads average ~120 tok) + prior-attempt context (~200 tok). Output is a single mutated payload. |
| Judge | `claude-sonnet-4-20250514` | ~700 / check | ~150 / check | 3–5 LLM checks | Per-check: system prompt (~250 tok) + rubric criterion (~150 tok) + attack record (~200 tok) + target response (~100 tok). Output is a structured verdict JSON. |
| Documentation | `claude-sonnet-4-20250514` | ~1200 | ~600 | 0 or 1 | System prompt + verdict + sanitized attack/response + repro template. Output is a markdown narrative + structured metadata. |

The smoke test below uses these as **character counts × 4** (the `cost.py` 4-chars-per-token heuristic): orch = 3200/800 chars, RT = 2400/1200 chars, judge = 2800/600 chars per check, doc = 4800/2400 chars.

### Computing per-run cost

The single source of truth is `cost.py::estimate_cost_cents`. Pricing (per 1M tokens) from `PRICING_TABLE`:

| Model | Prompt $/1M | Completion $/1M |
|---|---|---|
| `gpt-4o-2024-08-06` | $2.50 | $10.00 |
| `claude-sonnet-4-20250514` | $3.00 | $15.00 |
| `claude-haiku-4-5-20251001` | $1.00 | $5.00 |
| `openrouter/auto` | $3.00 (conservative; real often lower) | $15.00 |

The reference computation (this is the body of the acceptance smoke):

```python
from decimal import Decimal
from agentforge_redteam.cost import estimate_cost_cents

# One full run: orchestrator + red team mutation + 4 LLM-typed judge checks + documentation
total = (
    estimate_cost_cents("claude-haiku-4-5-20251001", prompt_text="a"*3200, completion_text="b"*800)
    + estimate_cost_cents("gpt-4o-2024-08-06",       prompt_text="a"*2400, completion_text="b"*1200)
    + 4 * estimate_cost_cents("claude-sonnet-4-20250514", prompt_text="a"*2800, completion_text="b"*600)
    + estimate_cost_cents("claude-sonnet-4-20250514", prompt_text="a"*4800, completion_text="b"*2400)
)
# Reference per-run cost: 0.0800 USD = 8 cents
```

**Headline figure: $0.0800 USD per worst-case run (8 cents).**

### Why integer cents inflate the headline

`cost.py` uses `ROUND_CEILING` to integer cents. Each sub-cent step rounds up. Stepwise:

| Step | Raw cents (sub-cent) | Quantized (cost.py) |
|---|---|---|
| Orchestrator | ~0.2¢ | 1¢ |
| Red Team | ~0.5¢ | 1¢ |
| Judge (one LLM check) | ~0.5¢ | 1¢ |
| Documentation | ~1.3¢ | 2¢ |

Summed via `cost.py` for a full run = 1 + 1 + 4·1 + 2 = **8¢**. The same arithmetic with sub-cent precision is about **3.5¢/run** for a finding-filing run, and **1.5¢/run** for the no-finding path. The ceiling rounding is intentional: the cost cap is a hard gate, and over-charging by a fraction of a cent per call is safer than blowing past the cap. See `cost.py:121–124` for the rationale.

This means the cost-at-scale table below uses **sub-cent precision** for projections (multiplying input text by 10× and dividing back), not the integer-cents single-step estimate, because at 100K calls the ceiling rounding compounds non-trivially.

### Weighted-average per-run

Assuming 10% finding rate (the architecture's intentional conservatism; the Judge applies high thresholds before declaring a finding):

```
avg = 0.9 * (orch + rt + 4·judge_check)        # no-finding path
    + 0.1 * (orch + rt + 4·judge_check + doc)  # finding-filing path
    = 0.9 * (0.2 + 0.5 + 4·0.5) + 0.1 * (0.2 + 0.5 + 4·0.5 + 1.3)
    = 0.9 * 2.7 + 0.1 * 4.0
    = 2.43 + 0.40
    ≈ 2.83 ¢/run
```

**Weighted-average per-run cost: $0.0283 USD.**

---

## Cost at Scale

| Scale (runs) | Per-run avg | Total cost USD | Notes |
|---|---|---|---|
| 100 | $0.0283 | **$2.83** | Baseline. No caching benefit (cache TTLs aren't filled). |
| 1,000 | $0.0223 | **$22.30** | Anthropic prompt caching on the Judge system prompt cuts ~30% off Judge cost. |
| 10,000 | $0.0132 | **$132.00** | + 50% batch-API discount on 80% of Judge calls (non-canary). + OpenRouter at Red Team cuts ~70% off RT cost. |
| 100,000 | $0.0106 | **$1,056.00** | + Payload deduplication via epsilon-greedy repeats saves ~20% (replays don't re-bill). |

### Math behind each row

The savings compound from a fixed per-run baseline; each row applies the previous row's optimizations plus one more lever.

**100 (linear baseline)**
```
avg = 0.9 * (orch_p + rt_p + 4·jc_p) + 0.1 * (orch_p + rt_p + 4·jc_p + doc_p)
    = 0.9 * 2.7 + 0.1 * 4.0  =  2.83 ¢
total = 2.83 ¢ × 100 = 283 ¢ = $2.83
```

**1,000 (prompt caching on Judge)**

Anthropic's prompt caching reads cached content at ~10% of full prompt price within the 5-minute cache TTL. The Judge's system prompt + rubric criteria is roughly 60% of the input tokens and is stable across the cache window. At ≥1K runs/week, the cache stays warm. Conservative cached-discount estimate: `judge_multiplier = 0.70` (30% off total Judge spend).

```
avg = 0.9 * (orch_p + rt_p + 4·jc_p·0.70) + 0.1 * (... + doc_p)
    = 0.9 * (0.2 + 0.5 + 4·0.35) + 0.1 * (0.2 + 0.5 + 1.4 + 1.3)
    ≈ 2.23 ¢
total = 2.23 ¢ × 1,000 = 2,230 ¢ = $22.30
```

**10,000 (+ batch API + OpenRouter fallback)**

Anthropic and OpenAI both offer 50% discount on batched async requests with 24h SLA. The Judge's non-canary checks (≈80% of Judge calls) are not time-sensitive: a campaign finding doesn't have to file within seconds. Batch them. `judge_multiplier = 0.70 × (0.5·0.8 + 0.2) = 0.70 × 0.6 = 0.42`.

OpenRouter fallback: at 10K scale, Red Team mutation routes through `openrouter/auto` to an open-source model (e.g., Llama-class). The `PRICING_TABLE` entry is conservative ($3/$15 per 1M); in practice, open-source models on OpenRouter typically run $0.30–$0.90/1M. Use `rt_multiplier = 0.30` (70% off RT cost) as the realistic blended rate.

```
avg = 0.9 * (orch_p + rt_p·0.30 + 4·jc_p·0.42) + 0.1 * (... + doc_p)
    = 0.9 * (0.2 + 0.15 + 0.84) + 0.1 * (0.2 + 0.15 + 0.84 + 1.3)
    ≈ 1.32 ¢
total = 1.32 ¢ × 10,000 = 13,200 ¢ = $132.00
```

**100,000 (+ payload deduplication)**

The Orchestrator's epsilon-greedy policy (`epsilon=0.1`) plus the `target_runs_per_sub_attack_per_week=50` cap means ≈20% of campaigns at saturation re-issue near-identical payloads (mutation variants in a small neighborhood). For those, the platform caches the verdict and target response: free for the platform. `dedup_multiplier = 0.80`.

```
avg = (above 10K formula) × 0.80 = 1.32 ¢ × 0.80 ≈ 1.06 ¢
total = 1.06 ¢ × 100,000 = 105,600 ¢ ≈ $1,056.00
```

### Why the 100K row is in the low-four-figures, not the mid-four-figures

The ARCHITECTURE.md's older Cost-at-Scale section estimated $8K–$12K for 100K runs. That estimate predates the actual per-step token modeling done here and used the rough cents-per-run figures from the brief's planning phase, not the ceiling-rounded `cost.py` measurements. With the precise model and **all four optimization layers stacked**, 100K runs lands at ~$1K. Stripping the optimizations and using the integer-cents path with worst-case finding rate gets you back to mid-four-figures — **the architecture allows either, depending on which levers an operator turns on**.

---

## Cost-control Architecture

The platform enforces cost gates at three layers; any one of them halts the session before runaway spending.

### 1. Per-campaign budget cap

```yaml
# orchestrator_policy.yaml
default_campaign_budget_cents: 50   # $0.50 per campaign
```

Every `CampaignBrief` carries a hard `budget_cents`. The audited tool wrapper accumulates costs into SQLite per-step. Red Team and Judge are force-stopped when their local cap is hit, and the campaign is recorded as `infra_failure: budget_exceeded`.

A typical worst-case run (8¢) leaves a **6.25× headroom** under the campaign cap — room for unexpected mutation depth, retries, or longer rubrics.

### 2. Per-session cost cap

```yaml
max_session_cost_cents: 1000        # $10.00 per session
```

The Orchestrator's `halt_if_cost_exceeded()` (see `ARCHITECTURE.md` §Orchestrator) runs before each campaign dispatch. If the running sum of `cost_per_category` ≥ `max_session_cost_cents`, the session ends with `halt_reason="budget_exhausted"`.

At the **weighted-average per-run cost of 2.83¢**, $10.00 covers roughly **350 runs per session**. With worst-case 8¢ runs, ~125 runs per session. The default policy assumes operators run multiple modest sessions per day rather than one mega-session — fits the conservative-auto-filing posture (`USERS.md` Operator persona).

### 3. Token-counted accounting (the `cost.py` substrate)

The accounting itself has two safety properties:

- **`ROUND_CEILING` quantization.** Every `(prompt, completion)` pair rounds **up** to the next integer cent. We over-charge by fractions of a cent. The session cap halts slightly early rather than slightly late.
- **`UnknownModelError` on typos.** A misspelled model name doesn't silently zero out the cost. Loud-fail at agent startup, not mid-campaign.

### 4. SDK-reported usage preferred over heuristic

`make_cost_estimator(model, prompt_text=...)` returns a callable that checks the LLM response for `cost_cents > 0` (when the SDK provides real usage data from `response.usage.{prompt,completion}_tokens`) and prefers that over the chars-per-token heuristic. The heuristic is the fallback for mock and self-hosted runtimes. Real-API runs measure exactly.

### 5. Kill switch

An operator tripping `kill_switch` (SQLite row) halts all tool calls before they spend. Documented in `ARCHITECTURE.md` §Failure Modes. No cost is incurred on kill-switched sessions beyond the in-flight call.

### 6. Free fallback for unconfigured deployments

- `NoopLangfuseClient` when `LANGFUSE_*` env vars are absent — no Langfuse cost. Free tier is generous, but this lets a CI smoke run pay nothing.
- `LocalFindingsSink` when `GITLAB_*` env vars are absent — findings write to `findings/<title>-<n>.md`. No GitLab API cost.
- The Documentation Agent's LLM call is the only avoidable infra cost in the "no finding" path, and that path doesn't invoke it.

---

## Architectural Levers

Each lever is exposed by a config change, not a rewrite. The architecture is shaped so that none of these requires touching agent logic.

### Lever 1: Anthropic prompt caching (Judge)

**What.** Anthropic caches static prompt prefixes for ~5 minutes at ~10% of full-prompt price for cache reads.

**Why it helps the Judge.** The Judge's per-check system prompt + rubric criterion is stable across that 5-minute window. At ≥1K runs/week the cache stays warm; at 100/week it might never see a cache hit.

**Architectural fit.** Already enabled by passing `cache_control` on the static portion of the system prompt — a one-line client config change, no agent rewrite. The Judge currently sends a single concatenated prompt; splitting into cached prefix + dynamic suffix is a wrapper-level change.

**Savings.** ~30% off total Judge cost at 1K+ runs/week (Anthropic publishes a 90% discount on the cached portion, and the static prefix is ~60% of Judge input by tokens; net ≈ 0.6·0.9 + 0.4 ≈ 0.46 of full cost. Conservatively cited as 30% in this doc to leave room for shorter cache windows.)

### Lever 2: Batch API (non-canary Judge verdicts)

**What.** Anthropic and OpenAI both offer 50% discount on batched async requests with 24-hour SLA.

**Why it helps the Judge.** ~80% of Judge calls are not time-sensitive: they evaluate finished campaigns where the operator doesn't need a verdict within seconds. The remaining ~20% (canary every 10 campaigns) must run synchronously to detect prompt drift early.

**Architectural fit.** Job-queue path lives in `var/state.sqlite3` (`agent_steps` table) — already serialized. Adding a batch-submit/poll pair around the Judge tool call is a wrapper change.

**Savings.** 50% off 80% of Judge calls = 40% on Judge totals. Compounds with Lever 1.

### Lever 3: OpenRouter fallback at the Red Team

**What.** `openrouter/auto` is already in `PRICING_TABLE` with a conservative $3/$15 per 1M. In practice, OpenRouter routes to open-source models (Llama-class, Mixtral, Qwen) at $0.30–$0.90/1M.

**Why it helps at scale.** Mutation generation is the lowest-stakes LLM call in the pipeline: a bad mutation just fails to land an attack, and the Judge will report the failure. We can use cheaper models for the routine 80% of mutations and reserve `gpt-4o-2024-08-06` for novel-mutation campaigns (e.g., when the coverage matrix shows a sub_attack with zero prior findings).

**Architectural fit.** Red Team's `model` parameter is already configurable via `--model openrouter/auto`. The PRICING_TABLE entry is conservative — real-world deployment can negotiate.

**Savings.** ~70% off Red Team cost at the long-tail routine-mutation path.

### Lever 4: Payload deduplication via epsilon-greedy replay

**What.** The Orchestrator's epsilon-greedy (epsilon=0.1) plus the per-sub_attack target rate (50/week) means at saturation ~20% of campaigns re-target the same sub_attack with similar payloads. The audited tool wrapper hashes payloads; if we've seen the exact (target_sha, payload_hash) pair, replay the cached verdict.

**Architectural fit.** The platform already records attack records with `prompt_sha` and `target_sha`. The dedup check is a SQLite SELECT before dispatch. No agent rewrite.

**Caveat.** This is a coverage cheat unless the regression harness deliberately replays — we're not counting *new* coverage on a replay. The orchestrator's coverage matrix knows this and only credits novel `(category, sub_attack, payload_sha)` triples.

**Savings.** ~20% reduction in total billed runs at 100K scale.

### Lever 5: Smaller models for low-stakes paths

Already partially live: Orchestrator is on Haiku ($1/$5 per 1M) rather than Sonnet ($3/$15). The Orchestrator's decision-making does not benefit from a frontier model — it's selecting from a small enumerated set of `(category, sub_attack)` pairs.

The next move at extreme scale: a self-hosted Sonnet-class model for the Judge. Self-hosting breaks even against Anthropic's API around **80K runs/month** for a single-GPU deployment, accounting for the GPU rental ($1.50–$2.50/hr for an A100). Beyond that, the savings compound.

### Lever 6: Deterministic pre-filters before LLM checks

Already in the rubric schema: rubrics declare `type: deterministic` vs `type: llm`. Deterministic checks (regex, citation-lookup) run free. The MVP rubrics (`rubrics/*.yaml`) average 2–3 deterministic + 2–3 LLM checks; deterministic-first short-circuits the LLM path when the answer is obvious. This is **already** in the cost model — it's the reason this doc assumes only "3–5 LLM-typed checks" per rubric rather than counting every criterion.

---

## Honesty: Limitations and Caveats

This section is the most important part of the doc. The numbers above are useful only to the extent these caveats are understood.

### 1. Projection, not measurement

**Live measurements are pending Task 59** (run live campaign against deployed target). Until then:

- All per-step token counts are *reasoned* from prompt content + typical chat-completion volumes, not measured.
- All savings multipliers (prompt-caching 30%, batch 50% on 80% of calls, OpenRouter 70% off RT, dedup 20%) are conservative-side estimates from provider docs; real campaigns may overshoot or undershoot.
- The cost-at-scale table is **not** validated against a single real production run.

When Task 59 lands, update this doc with: (a) measured per-step token counts from `agent_steps` SQLite rows, (b) measured cache hit rates from Anthropic's response headers, (c) actual finding rate from the campaign.

### 2. Token heuristic is ~15% optimistic

`cost.py::estimate_tokens` uses **4 characters per token**. This underestimates BPE counts on:

- Code-heavy content (rubric criterion strings often embed code samples)
- Non-English content (Unicode multi-byte characters tokenize larger)
- JSON-with-quotes (each `"` is its own token)

Real BPE counts run **10–20% higher** than the heuristic. The session-cap consequence: the cap halts ≈10–20% later than the heuristic implies. Acceptable for a budget gate; not acceptable for forensic accounting. If tighter accounting is needed, swap `estimate_tokens` for a real tokenizer behind the same signature — `cost.py:87–100` is designed for this.

### 3. Provider pricing changes

`PRICING_TABLE` is pinned to **2026-05-11** per the module docstring. Each entry should be re-validated quarterly. Anthropic and OpenAI both publish pricing on dated pages; the failure mode of stale pricing is undercharging (since the heuristic rounds up cents, even a 20% price increase doesn't blow the budget cap — but it does make the cost-at-scale projection optimistic).

### 4. No operational-cost line items

This document accounts for **AI infrastructure cost** only. Out of scope:

- **Human-review time for P0/P1 findings.** Conservative auto-filing (P2/P3 only, per `USERS.md` Operator persona) routes P0/P1 to a human queue. Assume ~10 min/finding × $80/hr operator hourly rate = **$13.33 per P0/P1 finding**. At 10% finding rate and 20% of findings being P0/P1, this is **$0.27 per run in operator time** — larger than the infra cost.
- **DigitalOcean droplet** running the platform: ~$24/month for the spec in `ARCHITECTURE.md`. Constant cost, not per-run.
- **Langfuse** (paid tier if used) and **GitLab** (`labs.gauntletai.com` cohort host, free for this project). Both have free tiers covering the MVP scale.
- **Self-hosted target costs.** If the operator runs both the platform and the target on their own infrastructure, the target's LLM bill is the operator's responsibility, not the platform's. The platform's `cost.py` does not bill for the target HTTP call.

### 5. No HIPAA/compliance overhead

The `USERS.md` CISO persona requires evidence retention. The cost-at-scale table does not include S3/Postgres archival costs for `run_manifests`, `agent_steps`, and signed artifacts. At 100K runs, the audit log is roughly 100K × ~3KB = 300 MB — pennies/month at archival tiers. Not material.

### 6. Rate limits are not in the cost model

The cost-at-scale table assumes no rate-limit-induced retries. At 100K runs/month, both OpenAI and Anthropic tier-3 limits hold without retry storms. Above that, the platform must batch and queue (Lever 2 already covers this for the Judge); the Red Team's serial-by-default dispatch (`ARCHITECTURE.md` §State and Coordination Framework) handles its own rate limit naturally.

### 7. The MVP rubrics declare 2–3 LLM checks, not 4

The headline figure assumes **4 LLM-typed Judge checks per rubric**. The MVP rubrics in `rubrics/*.yaml` declare 2–3. The 4-check projection is the conservative ceiling, anticipating rubric growth as the platform matures. With current MVP rubrics, the actual per-run cost is **~$0.06 worst case** rather than $0.08 — **25% cheaper than the headline.**

---

## Recommendations by Scale

| Scale | Configuration | Expected cost |
|---|---|---|
| **≤100 runs/week** | Defaults. No optimization needed. Use mock clients in CI to skip real spend. | ≤$3 total |
| **1K runs/week** | Enable Anthropic prompt caching by splitting Judge system prompt at the rubric boundary. ~30% Judge savings. | ~$22 total |
| **10K runs/week** | Route Red Team mutations through `openrouter/auto`. Switch Judge to batch API for non-canary verdicts (the canary cadence is `canary_every_n_campaigns: 10` so 90% of calls qualify). | ~$132 total |
| **100K runs/week** | All of the above + enable payload deduplication via the audited wrapper's hash gate. Consider self-hosted Sonnet-class for Judge at ≥80K/month. | ~$1,056 total |

### Operator playbook

- **Set the session cap first.** `--cost-cap 5.00` for a typical session is generous; `--cost-cap 0.50` is the smoke-test default.
- **Monitor `cost_per_category` in SQLite.** A runaway category (e.g., `tool-misuse` burning 80% of session budget) usually means a rubric is over-applying the LLM path. Add deterministic pre-filters.
- **Use the kill switch liberally during prompt iteration.** The cost of an aborted session is the in-flight call only, not the planned remainder.
- **Re-validate `PRICING_TABLE` quarterly.** A single PR updating `cost.py:57–67`.

---

## Methodology

### Source of truth for prices

`src/agentforge_redteam/cost.py::PRICING_TABLE` (pinned 2026-05-11). All cents calculations in this document come from `estimate_cost_cents`.

### Source of truth for model defaults

- Orchestrator: `agents/orchestrator.py::DEFAULT_MODEL` = `claude-haiku-4-5-20251001`
- Red Team: `agents/red_team.py::DEFAULT_MODEL` = `gpt-4o-2024-08-06`
- Judge: `agents/judge.py::DEFAULT_MODEL` = `claude-sonnet-4-20250514`
- Documentation: `agents/documentation.py::DEFAULT_MODEL` = `claude-sonnet-4-20250514`

### Source of truth for budget caps

`orchestrator_policy.yaml`:
- `default_campaign_budget_cents: 50` ($0.50)
- `max_session_cost_cents: 1000` ($10.00)
- `epsilon: 0.1`
- `target_runs_per_sub_attack_per_week: 50`
- `canary_every_n_campaigns: 10`

### Source of truth for finding rate

10% finding rate is an assumption pending Task 59. Historical seed campaigns against AgentForge (Week 2) trended toward 8–15% across the three MVP categories — the 10% mid-point is the planning assumption.

### Verifying smoke (run this against the repo)

```bash
uv run python -c "
from decimal import Decimal
from agentforge_redteam.cost import estimate_cost_cents
total = (
    estimate_cost_cents('claude-haiku-4-5-20251001', prompt_text='a'*3200, completion_text='b'*800)
    + estimate_cost_cents('gpt-4o-2024-08-06',     prompt_text='a'*2400, completion_text='b'*1200)
    + 4 * estimate_cost_cents('claude-sonnet-4-20250514', prompt_text='a'*2800, completion_text='b'*600)
    + estimate_cost_cents('claude-sonnet-4-20250514', prompt_text='a'*4800, completion_text='b'*2400)
)
print(f'Reference per-run cost: {Decimal(total) / Decimal(100):.4f} USD = {total} cents')
"
# Expected output (as of 2026-05-11 PRICING_TABLE):
# Reference per-run cost: 0.0800 USD = 8 cents
```

If the headline figure in this doc and the smoke output disagree by more than 1 cent, **the headline is stale** — `PRICING_TABLE` has been updated and this doc needs a refresh. Treat it as a CI gate (Task 59 should wire this into `pytest`'s docs-sanity step).

### Change log

| Date | Change |
|---|---|
| 2026-05-12 | Initial projection-only analysis. Pricing pinned to `cost.py` 2026-05-11 table. |
| TBD (Task 59) | Replace projected token counts with measurements from `agent_steps` SQLite rows. |
