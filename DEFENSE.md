# Architecture Defense — AgentForge Adversarial AI Security Platform

**Date**: 2026-05-11
**For**: Week 3 Architecture Defense checkpoint (~4h after kickoff)
**Companion documents**: `ARCHITECTURE.md` (the architecture), `THREAT_MODEL.md` (the surface), `USERS.md` (the operators), `DIAGRAMS.md` (the visuals), `presearch.md` (the pre-work).

This document is the defense substrate. It answers the questions a reviewer is most likely to ask, lays out the counter-arguments to alternative architectures, and surfaces honest limitations rather than hiding them.

---

## Elevator Pitch (30 seconds)

> AgentForge is a Clinical Co-Pilot integrated into OpenEMR. We're building a multi-agent platform that continuously red-teams it. Four agents with distinct trust levels and different LLM providers — Red Team on GPT-4o, Judge on Claude Sonnet, Orchestrator on Haiku, Documentation on Sonnet — coordinate through a LangGraph state machine. Every finding maps to OWASP LLM Top 10 2025, MITRE ATLAS v5.4.0, and HIPAA §164 sections, so a hospital CISO can defend it. Humans stay in the loop only on P0/P1 filing and low-confidence verdicts. The architecture satisfies the new HIPAA §164.308 AI-tool-risk-analysis requirement finalizing this month.

## Elevator Pitch (2 minutes)

The problem: hospital AI security testing today is manual, shallow, and stale. A pentester tests a feature once, files a report, and moves on; the test set goes outdated within weeks as new attack techniques emerge. Meanwhile, the new HIPAA Security Rule (NPRM finalizing May 2026) puts AI tools explicitly in scope of §164.308 risk analysis — so health systems need *continuous*, *documented* AI security testing as a compliance artifact. Manual pentests can't satisfy that requirement at the cadence the rule implies.

The platform: four autonomous agents. The **Red Team Agent** (GPT-4o) generates and mutates attacks against the live AgentForge target. The **Judge Agent** (Claude Sonnet 4.6) evaluates whether each attack succeeded, using structured YAML rubrics that produce reproducible verdicts per (target SHA, rubric SHA, model version). The **Orchestrator Agent** (Claude Haiku 4.5) reads platform state from SQLite and decides what to test next by coverage gap and historical severity. The **Documentation Agent** (Claude Sonnet 4.6) writes vulnerability reports and files them as GitLab issues — autonomously for P2/P3 with high confidence, queued for human approval on P0/P1.

The defensibility: Red Team and Judge are on **different providers** to break model-family correlation in attack and evaluation — the brief explicitly calls out that an agent that both generates and evaluates is compromised by design. Rubrics are versioned YAML to detect Judge drift. Every tool call routes through one audited wrapper that writes to SQLite (for the Orchestrator's decision loop) and Langfuse (for human-readable traces). Confirmed findings auto-promote into a regression harness that re-runs them against every new target build. Cost scales sub-linearly with architectural levers — prompt caching, deterministic pre-filters, batch APIs, optional open-source Red Team — projected at $8–12 for 100 runs, mid-four-figures for 100K.

---

## The Brief's Hard Problems → Our Architectural Response

The brief explicitly names five hard problems. Each gets a direct answer.

### Hard Problem 1: Adversarial Robustness

> "Systems that perform well under normal usage can behave very differently under adversarial pressure... Defenses built around a small number of known examples rarely hold as attackers adapt... You need an agent whose job is to probe, mutate, and escalate."

**Our response**: The Red Team Agent is built around **mutation**, not a static payload list. Each campaign starts from seed payloads in `attack_library.json` but the agent generates variants via LLM mutation. Partially-successful attacks trigger up to N mutation rounds within the campaign's cost budget. The attack library is versioned and refreshable from OWASP LLM Top 10 updates and MITRE ATLAS additions.

**Defensibility**: the mutation budget is hard-capped per campaign (prevents runaway), variants are de-duplicated by hash (prevents trivial cycles), and the Judge sees the final payload, not the mutation history (prevents bias).

### Hard Problem 2: Evaluation & Regression

> "Finding a vulnerability once is not enough... The judge must be independent of the attack engine — an agent that both generates attacks and evaluates them is compromised by design."

**Our response**: Three concrete mechanisms.

1. **Provider independence**: Red Team on OpenAI GPT-4o; Judge on Anthropic Claude Sonnet 4.6. Different training data, different refusal patterns, different blind spots.
2. **Structured rubrics, not free-form prompts**: every Judge verdict is structured JSON filling a versioned YAML rubric. Verdicts are reproducible per (target SHA, rubric SHA, model version). A re-run on the same target with the same rubric must produce the same verdict (within model-temperature tolerance).
3. **Regression harness**: every confirmed finding auto-promotes to a deterministic test case in `evals/regressions/<id>.json`. The harness replays every test against every new target SHA using the **original** rubric (not the latest, to make regression results attributable to target change, not platform evolution).

**Defensibility**: a regression test that "passes because the model behavior changed" is detected by the version-pinning mechanism.

### Hard Problem 3: Visibility & Observability

> "This is the role of an orchestrator agent: one that reads the state of the system — coverage gaps, high-severity open findings, recent regressions — and decides where to direct the red team agent's attention."

**Our response**: A SQLite state store with a denormalized `coverage_matrix` table. The Orchestrator reads it on every campaign-dispatch decision and selects the next attack by coverage-weighted prioritization with epsilon exploration (default 0.1). Langfuse holds human-readable inter-agent traces; the Orchestrator does **not** query Langfuse — it queries SQLite, for sub-100ms decision latency and zero third-party-dependency in the decision loop.

**Defensibility**: every decision the Orchestrator makes is auditable — the audit log records the coverage state at the moment of dispatch.

### Hard Problem 4: Cost, Scale, & Model Constraints

> "Large frontier models can become prohibitively expensive when used for continuous security testing at scale... Some commercial LLMs are intentionally trained to avoid offensive security workflows."

**Our response**: Two parts.

**On scale**: the architecture is shaped to keep cost sub-linear via six levers (prompt caching for Judge, deterministic pre-filters before LLM checks, smaller models for routine campaigns, batch API for non-time-sensitive regressions, payload-hash caching, optional open-source Red Team). Projected: $8–12 at 100 runs, mid-four-figures at 100K.

**On model refusals**: the Red Team is on GPT-4o today; if its refusal rate exceeds 20% on legitimate attack categories, the architecture supports a single-config swap to an open-source model via OpenRouter (DeepSeek-V3 or Qwen 2.5 72B). No rewrite. A deterministic content filter on Red Team output catches genuinely-harmful generation independent of provider policy.

**Defensibility**: we measured the architectural impact of each cost lever, not just the unit cost.

### Hard Problem 5: Discovery, Remediation, & Trust

> "An agent that confidently documents a false positive wastes engineering time. An agent with the ability to push fixes without review can introduce entirely new vulnerabilities."

**Our response**: Four explicit human-in-the-loop gates.

1. **P0/P1 filing** — Documentation Agent never autonomously files P0 or P1. Human approval required.
2. **Low confidence** — any severity, if Judge confidence is below threshold, queues for human approval.
3. **Target allowlist additions** — no agent can add to `targets.yaml`. Operator-only action.
4. **Kill switch** — SQLite-backed flag, checked by every agent before every tool call. Operator can halt the platform instantly.

The Documentation Agent **does not push fixes**. It files vulnerability reports as GitLab issues. The AgentForge dev team owns remediation.

**Defensibility**: every decision the platform makes autonomously is bounded by what could go wrong if it's wrong, and the gates are placed where the asymmetric cost of being wrong is highest.

---

## Anticipated Questions and Prepared Answers

Grouped by topic. Each Q is phrased as a defender would ask it, sharply.

### On the multi-agent architecture

**Q: Why four agents and not one agent with multiple tools?**

A single agent that generates attacks, evaluates them, and writes reports has a structural conflict of interest: it will drift toward declaring its own work successful. The brief is explicit on this. Real-world human red teams separate generation from evaluation across people; we do the same across agents. Additionally, the four agents have different trust levels (Red Team's output is treated as adversarial; Documentation must be conservative), different decision authority (Orchestrator picks campaigns; Judge picks verdicts), and different runtime costs (Orchestrator runs many times cheap; Documentation runs once expensive). Combining them collapses these distinctions.

**Q: Why provider independence between Red Team and Judge? Different models from the same provider would be cheaper.**

Same-provider models share training data, alignment training, and often refusal heuristics. A Judge from the same family as the Red Team will systematically miss the same attacks. Different providers — OpenAI for Red Team, Anthropic for Judge — break that correlation. The cost is dual-provider account complexity ($0 extra at our scale) and slightly more secrets management. The benefit is the brief's required "independent Judge" property is structurally enforced, not just claimed.

**Q: A pipeline (generate → evaluate → file) would be simpler. Why a graph?**

A pipeline runs whatever the previous stage emits. It can't *adapt*. The Orchestrator's job — read coverage state, allocate budget, pick the next thing to test — has no clean place in a pipeline. A graph with conditional edges lets the Orchestrator make state-driven decisions and lets regressions trigger on independent events (new target SHA, time-based, aging findings). The brief specifically rules out the pipeline shape.

### On the Judge

**Q: How do you know the Judge is right?**

Three layers. First, **30–50 hand-curated ground-truth cases** across the 3 MVP attack categories (known-pass, known-fail, known-partial). Judge accuracy on this set is a CI gate. Second, **canary cases injected into every orchestrator session** — if the Judge fails the canaries mid-run, the Orchestrator halts and surfaces drift. Third, **human-overridden Judge verdicts feed back as new ground-truth cases**, so the Judge improves over time without re-prompting.

**Q: What if the Judge drifts toward passing everything?**

That's the canary-failure case. The canaries include known-pass cases the Judge should pass and known-fail cases it should fail; if either side fails, that's drift. The Orchestrator halts and pages the operator. We accept that the canary set itself could be wrong, so we periodically re-evaluate canaries against current rubrics during operator-led review.

**Q: Why YAML rubrics? Why not let the Judge LLM judge freely?**

A free-form Judge prompt produces verdicts that drift with prompt phrasing and model version. A YAML rubric defines the verdict schema and the specific checks; the Judge LLM fills the schema, it doesn't write it. Verdicts are reproducible per (target SHA, rubric SHA, model version). Rubric updates are diffable in git. The cost is upfront rubric-authoring time; the benefit is regression reproducibility.

### On the Red Team

**Q: What if GPT-4o refuses to generate adversarial content?**

Two answers. First, we use "authorized security research" framing in the Red Team system prompt — frontier models will generally engage with adversarial generation when the context is properly scoped. Second, if refusal rate exceeds 20% on legitimate in-scope categories during MVP testing, we swap to an open-source model via OpenRouter (DeepSeek-V3 or Qwen 2.5 72B). Single config change. No architectural rewrite. The Red Team's interface to the rest of the system is provider-agnostic.

**Q: What if the Red Team generates genuinely harmful content — child-safety, CBRN, real exploits?**

Every Red Team output passes through a deterministic content filter before reaching `call_target`. The filter refuses out-of-scope categories. The filter is rule-based, not LLM-judged — because LLMs can be tricked into approving harmful content, hard rules cannot. The Red Team's system prompt constrains its scope to the threat-model categories; the filter is a defense-in-depth backstop.

**Q: Static payloads work for known categories. Why add mutation cost?**

Because static payloads age. A jailbreak that worked last quarter is patched this quarter. A test that "passes" with the patched payload looks like a passing test, but the underlying vulnerability class may still be exploitable with a variant. Mutation is what catches "the surface marker was filtered, not the class fixed."

### On the Orchestrator

**Q: How does the Orchestrator decide what to test next?**

Coverage-weighted prioritization with epsilon exploration. Within MVP categories, sub-attacks are weighted by `severity_history / (1 + days_since_last_run)`. With probability epsilon (default 0.1), the Orchestrator picks an unrun sub-attack uniformly instead of the highest-weighted candidate — pure exploration. Stretch categories receive zero budget until MVP categories meet target coverage.

**Q: Why Haiku for the Orchestrator? Won't a smarter model make better decisions?**

The Orchestrator's decision is a constrained selection over structured state (coverage matrix, budget, canary outcomes). It runs many times per session (once per campaign). Haiku is fast, cheap, and good enough at structured-output policy work. Using Sonnet here would add cost on every campaign with negligible decision-quality benefit. The decision *logic* is deterministic (weights, epsilon) — the LLM's role is to read the structured state and emit the campaign brief.

**Q: What if the Orchestrator picks the same category every time?**

Epsilon exploration prevents pure greedy. And the no-progress detector halts the session after N campaigns with no new findings, on the assumption that we've exhausted the current threat model and should re-tune (add new sub-attacks, update rubrics, or rebalance budgets).

### On state and observability

**Q: Why SQLite for state? Postgres would scale better.**

MVP is single-tenant. SQLite covers it with no network dependency, transactional safety, and sub-100ms queries. The schema is intentionally simple enough that migration to Postgres is mechanical if scale demands it (multi-tenancy, parallel sessions). Premature Postgres adds ops complexity for no MVP benefit.

**Q: Why split SQLite and Langfuse? Pick one.**

They serve different roles. SQLite is the Orchestrator's queryable substrate — fast, deterministic, no third-party dependency in the decision loop. Langfuse is the human-facing trace store — pretty UI, tree-view of sessions, generation provenance. Trying to make Langfuse the Orchestrator's state store would couple the platform to Langfuse's API quirks and inject latency into every decision. Trying to make SQLite the human-facing observability would mean building our own trace viewer. Use the right tool.

**Q: What if SQLite and Langfuse get out of sync?**

The audited tool wrapper writes to both with a shared `step_id` before and after the tool call. A reconciliation pass runs as a SQLite-side maintenance task and surfaces mismatches. In practice, the failure mode is "Langfuse write timed out" — the SQLite write is the source of truth; the Langfuse miss surfaces in the audit reconciliation.

### On HITL and trust

**Q: Why require human approval for P0/P1? Isn't autonomous filing the point?**

The point is autonomous *operation*, not autonomous *high-stakes decisions*. A false-positive P0 filed to an external system damages trust in the platform and wastes engineering time on a non-issue. A false-positive P2 is recoverable (re-classify, close as not-an-issue). The asymmetric cost of being wrong drives the asymmetric routing. As Judge accuracy on P0/P1 ground-truth cases is demonstrated, the threshold can be loosened.

**Q: What does the kill switch actually do?**

It's a SQLite-backed boolean flag. Every agent checks it via the audited tool wrapper before every tool call. If tripped, the tool raises `KillSwitchTripped`, the LangGraph node fails, the campaign is recorded as `killed`, and no partial writes occur. The CLI exposes `agentforge-redteam halt`; the Web UI has a big red button. We chose flag-check-before-tool rather than process-kill so that audit log integrity is preserved.

**Q: How do you prevent the platform itself from being misused — turned against systems it shouldn't attack?**

Three mechanisms. First, `targets.yaml` is a git-committed allowlist; the platform refuses any URL not on the list, and no agent can edit the file. Second, the GitLab token is scoped to the AgentForge project only — no write access elsewhere. Third, audit log records every dispatch and every tool call; if the platform were ever pointed at the wrong target, the audit trail surfaces it immediately. The agents themselves do not have any capability to extend their own permissions.

### On compliance and clinical context

**Q: How does this satisfy HIPAA?**

The HIPAA Security Rule NPRM (December 2024, finalizing May 2026) explicitly puts AI tools in scope of §164.308(a)(1) risk analysis. This platform produces the artifact that satisfies that requirement: documented, continuous, framework-tagged AI security testing of AgentForge with a queryable audit trail. Findings carry HIPAA `§164` section references so the CISO can map them directly to compliance controls. The platform itself does not process real ePHI — it uses Synthea synthetic data — so the platform is not itself a HIPAA system, but it produces the compliance evidence for the system that is.

**Q: Why use HIPAA at all in a portfolio piece?**

Because the target is clinical AI. A threat model for a clinical AI tool that doesn't ground in HIPAA is incomplete. And the May 2026 finalization is genuine timing — the buying story for this kind of platform changes substantially this month.

### On the project itself

**Q: How are you going to build this in 4 days?**

The bottleneck isn't lines of code, it's deciding what to skip. The MVP is the four agents in a single LangGraph with the 3 MVP attack categories — not all six. No public web UI for MVP — that's Final. No multi-target — that's post-cohort. The deterministic surfaces (rubric loader, schemas, cost cap, allowlist, severity rubric) are TDD'd. The LLM loops are eval-driven, not unit-tested. Phased deployment: droplet + CI cron for MVP, web UI for Final.

**Q: What's the hardest part of the build?**

The Judge ground-truth dataset. 30–50 hand-curated cases across 3 categories — known-pass, known-fail, known-partial — built before any agent code runs. Without it, Judge accuracy is unmeasurable and the rest of the platform calibrates against a Judge we can't trust. I expect this to take ~4 hours of careful authoring.

**Q: What's the riskiest assumption?**

GPT-4o's refusal rate on healthcare-AI red-teaming. I haven't measured it as of today; if it's higher than 20%, I swap to OpenRouter. The architecture supports the swap as a config change, but if I discover this on Tuesday I lose a few hours to provider integration.

---

## Counter-Arguments to Alternative Architectures

The brief explicitly rules out a single-agent or pipeline shape. Here are the alternatives a defender might still propose, and the responses.

### "Use AutoGen / CrewAI / AutoGPT instead of LangGraph"

These frameworks bundle a lot of opinion (role descriptors, conversation patterns) that we don't need. We need a state machine with conditional routing — that's LangGraph's core. AgentForge itself already uses LangGraph; cognitive overhead is lower. Reusing the same primitives across both systems makes the codebase legible to anyone familiar with one half.

### "Just use a commercial AI security tool (HiddenLayer, Lakera, Prompt Security)"

Three reasons. First, this is a portfolio piece — building the thing is the point. Second, those tools are generic; the AgentForge target has clinical-specific surfaces (chart-write, citation registry, ePHI in observability) that a generic tool doesn't model. Third, no commercial tool maps findings to MITRE ATLAS + OWASP LLM Top 10 + HIPAA §164 simultaneously in the audit-evidence form clinical compliance teams need.

### "Run a static OWASP LLM Top 10 test suite (e.g., DeepTeam, PromptFoo, Garak) against it"

Those tools are valuable substrate — we'd even reference their attack patterns. But they're static test suites: they don't mutate, they don't have a Judge independent of the attack engine, they don't read coverage state, and they don't produce structured vulnerability reports with framework-mapped severity. They satisfy the brief's "static test runner" anti-pattern that the brief explicitly rules out.

### "Use a single Claude or GPT-4 agent with subagent delegation via tools"

This is the natural Pythonic answer and looks tempting. The problem is twofold. (1) Subagent calls via tools share the parent agent's context window — the "Judge subagent" sees the parent's reasoning about why this attack should succeed. That's the conflict-of-interest problem under a different name. (2) The parent agent's decisions about *when* to call the Judge subagent are governed by the same model that generated the attack — there's no architecturally enforced separation. Multi-agent with provider independence breaks both.

### "Build a UI-first system — operators manually trigger attacks; the platform just tracks results"

This is exactly what we're trying to escape. It scales linearly with operator hours. It doesn't satisfy "continuous." It doesn't satisfy "without a human in the loop for every step." The CISO buying story requires autonomy.

### "Skip the Documentation Agent; just dump findings as logs"

Findings as raw logs are not actionable. The AgentForge dev team has to fix vulnerabilities, and they need: reproduction steps, severity, framework mapping, suggested remediation, evidence references. A human writing those reports averages 1–2 hours per finding. At the cadence the platform produces findings, that's the rate-limiting step. The Documentation Agent collapses report-writing time to seconds while keeping HITL on the high-stakes filing decision.

---

## Known Limitations and Honest Tradeoffs

This section is the "we know what we're not solving" section. Showing self-awareness here is more credible than pretending the platform is complete.

| Limitation | Why we accepted it | What would fix it |
|---|---|---|
| Single-tenant MVP | Time. Multi-tenancy requires auth, isolation, per-tenant SQLite/Postgres. | Postgres migration + tenant scoping in queries. Post-cohort. |
| Frontier-model dependency for Red Team | Self-hosting open-source models on a GPU droplet adds ops burden during the 4-day clock. | Ollama / vLLM on a GPU droplet; eliminates frontier-model cost. |
| Synthea synthetic data only | Real PHI testing requires a BAA, clinical IT environment, and full HIPAA-compliant platform. Out of scope for portfolio. | BAA execution + production-grade compliance for the platform itself. |
| Judge ground truth is hand-curated, small (30–50) | We are the only authors. Larger ground truth requires SMEs. | Recruit security engineers / clinicians; expand to 200+. |
| No production-protection (runtime defense) | The platform is a *testing* tool, not a runtime guardrail. | Runtime defense is AgentForge's own concern; platform tests whether it holds. |
| English-only attack library | Multilingual injection is a real category we don't probe. | Add multilingual seed payloads to the library; rubric updates for cross-language judge checks. |
| LLM-based mutation can stagnate | We cap mutation budget per campaign; pure-LLM exploration of payload space is bounded. | Hybrid approach: genetic-algorithm mutation over payload tokens for some sub-attacks. |
| No analog for nation-state-level adversary | Cannot credibly simulate human-creative sophisticated adversaries with LLMs alone. | Manual red-team supplements; platform is the floor, not the ceiling. |
| Cost projection is pre-measurement | Projections at 100K runs are estimates, not measurements. | First MVP run produces real per-component cost data; projection refines. |
| MITRE ATLAS technique IDs partially unverified | Several IDs (T0036, T0048, T0070) cited from training-era memory; web-search verified the load-bearing ones. | Verify all cited IDs against atlas.mitre.org before locking the threat model. |

---

## What the Defense Demo Shows

If the architecture defense is a live demo (not just a document review), the order to walk:

1. **The four documents are written**: presearch (planning substrate), threat model (mapped to frameworks), users (operator personas + architecture justification), architecture (the design itself + tradeoffs + cost analysis). Total: ~1,800 lines across four files. Open the repo and show the file tree.

2. **The architecture diagram** (Diagram 3 from `DIAGRAMS.md`): walk through one campaign in sequence. Operator triggers session → Orchestrator reads state → dispatches Red Team → Red Team attacks target → Judge evaluates → Documentation files or queues. Each agent is on the slide; each provider is on the slide.

3. **The trust independence** (Diagram 9, trust boundaries): show that the Red Team and Judge live on different providers, and that the Judge never sees the Red Team's reasoning. This is the brief's headline requirement.

4. **The HITL gates** (Diagram 8): show that P0/P1 always require approval, that the kill switch exists, that the target allowlist is git-controlled. This is the trust story for the CISO.

5. **The cost analysis**: show the per-campaign cost breakdown (Diagram 11), the projection at 100/1K/10K/100K runs, and the six architectural levers that make scaling sub-linear.

6. **The framework mapping**: open `THREAT_MODEL.md`'s Category 1 section and show the framework-mapping table — OWASP LLM01:2025, MITRE AML.T0051, HIPAA §164.308. Show that findings will carry these tags in the GitLab issue body.

7. **The honest limitations**: open this document's limitations table. Most architecture defenses fail by overclaiming. We claim less than we could and document the gaps.

If time runs short, drop items 4–6 (the visuals tell those stories well enough on their own). The non-negotiable items are 1, 2, 3, and 7.

---

## One-Page Summary (the cheat sheet)

> **What it is**: Multi-agent platform that continuously red-teams the AgentForge Clinical Co-Pilot.
>
> **Agents**: Red Team (GPT-4o), Judge (Claude Sonnet 4.6, different provider), Orchestrator (Haiku), Documentation (Sonnet).
>
> **Coordination**: LangGraph state graph + Pydantic typed messages. Single graph for MVP, supervisor pattern available for Final.
>
> **State**: SQLite for Orchestrator decisions and audit; Langfuse for human-readable traces.
>
> **Rubrics**: Versioned YAML, per attack category. Judge fills the schema. Verdicts reproducible per (target SHA, rubric SHA, model version).
>
> **Regression**: every confirmed finding auto-promotes to a deterministic test, re-run against every new target SHA using the **original** rubric.
>
> **HITL**: P0/P1 filing approval, low-confidence approval, target allowlist additions, kill switch.
>
> **Cost**: $0.08/campaign (no finding), $0.12/campaign (with finding). $8–12 at 100 runs. Sub-linear scaling via 6 architectural levers.
>
> **Compliance**: Satisfies the new HIPAA §164.308(a)(1) AI-tool-risk-analysis requirement finalizing May 2026.
>
> **Frameworks tagged on every finding**: OWASP LLM Top 10 2025, OWASP Web Top 10 2025, MITRE ATLAS v5.4.0, NIST AI 600-1, HIPAA §164.
>
> **Filing target**: GitLab issues in the AgentForge project, so findings feed the fix cycle.
>
> **Honest limitations**: Single-tenant MVP, frontier-model dependency, Synthea-only, small ground truth, no production-protection.


---

## Companion documents

- [`README.md`](./README.md) — quickstart + project overview
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — system design and agent roles
- [`THREAT_MODEL.md`](./THREAT_MODEL.md) — attack surface, in-scope vs out-of-scope
- [`USERS.md`](./USERS.md) — operator and CISO journeys
- [`DIAGRAMS.md`](./DIAGRAMS.md) — Mermaid + ASCII system diagrams
- [`presearch.md`](./presearch.md) — initial scoping notes

*Source of truth for the operational schema: `rubrics/SCHEMA.md`.
Source of truth for the data contracts: `src/agentforge_redteam/state.py`.*
