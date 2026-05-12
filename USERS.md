# Users — AgentForge Adversarial AI Security Platform

**Date**: 2026-05-11
**Document status**: living. Updated when a new user workflow or use case is identified.

This document describes the **operators of the adversarial platform** — the people who use it, the workflows it slots into, the use cases it satisfies, and the explicit justification for why an autonomous multi-agent architecture is the right solution rather than a static test suite, a single agent, a linear pipeline, or a manual penetration test.

This is *not* a threat model. The attackers of AgentForge are documented in `THREAT_MODEL.md`. This document is about the people who run the platform that defends against those attackers.

---

## Why this document matters

The brief asks for explicit justification of automation. Hospital security organizations have spent decades buying tools that promise automation and then sit in a dashboard nobody reads. The case for this platform has to survive that skepticism: *who actually uses it, when, and what would they do without it?*

The answer is shaped by three observations:

1. **AI security testing today is mostly manual.** Hospital security teams run one-time prompt-injection tests when a new AI feature ships. Coverage is shallow, results are not reproducible, and the test set goes stale within weeks as new attack techniques surface.
2. **The HIPAA Security Rule NPRM finalizing in May 2026 explicitly puts AI tools in scope of §164.308 risk analysis.** Healthcare orgs are about to need *continuous*, *documented* AI security testing as a compliance artifact. Manual pentests cannot satisfy that requirement at the cadence the rule implies.
3. **Single-agent LLM red-teaming has a known conflict-of-interest problem.** An agent that both generates attacks and evaluates whether they succeeded will, by design, drift toward declaring its own work successful. Real-world red teams separate these roles across humans for the same reason.

These three facts together describe a market gap that an autonomous, multi-agent, continuous adversarial platform fills.

---

## Primary user — Healthcare AI Security Engineer

The platform's primary operator. This is the person whose job is to ensure that AI clinical tools meet the security bar before deployment and to monitor them in production.

### Profile

- **Role**: Application security engineer, AI security specialist, or red-team lead embedded in a hospital IT security org or health-system AppSec team.
- **Reports to**: CISO or VP of Information Security.
- **Skill model**: Strong web AppSec background, familiar with OWASP frameworks and pentest methodology. Often less deep in LLM internals and prompt engineering — they understand the threat categories but rely on tooling for actual attack generation.
- **Time allocation**: Splits attention across many systems. Cannot dedicate weeks to one AI feature.

### Goals

- Catch high-severity AI vulnerabilities **before** they ship to production.
- Maintain a regression suite that prevents previously-fixed vulnerabilities from re-appearing.
- Produce reproducible evidence of testing for compliance (HIPAA §164.308(a)(1) risk analysis).
- Stay current with emerging attack techniques (OWASP LLM Top 10 updates, MITRE ATLAS additions, published jailbreak research) without manually re-testing every new technique against every AI feature.

### Pain points without the platform

- **Coverage shallowness.** Manual testing covers a handful of known prompt-injection payloads against a handful of features. Most of the attack surface is untested.
- **Reproducibility.** A vulnerability found during ad-hoc testing is hard to reproduce. The fix is often shipped without a deterministic test that would catch its return.
- **Staleness.** A test suite built today is outdated by next quarter. New techniques surface weekly. Re-testing every old vulnerability against the latest payload variants is mechanical work no human wants to do.
- **Judge bias.** When the same engineer who generated the attack also evaluates whether it succeeded, results drift toward success. The engineer wants the attack to work because they spent time crafting it.
- **Reporting overhead.** Writing up a vulnerability finding — repro steps, severity rationale, suggested remediation — takes longer than finding the vulnerability. Engineers skip the writeup, lose institutional memory.

### Primary workflow with the platform

1. **Initial setup**: clones the platform, configures the AgentForge target URL in `targets.yaml`, provides API keys for Anthropic and OpenAI, points the platform at a GitLab project for issue filing.
2. **Threat model review**: reads `THREAT_MODEL.md`, confirms attack categories and severity rubrics align with their org's priorities. Adjusts the coverage budget per category in the orchestrator config.
3. **Ground-truth curation**: contributes hand-curated test cases to the Judge's ground-truth dataset for any attack category specific to their org's clinical workflow.
4. **Continuous operation**: the platform runs autonomously on a schedule (nightly by default). The engineer is *not* the runner — they're the reviewer.
5. **Daily triage**: reviews vulnerability reports filed overnight. High-confidence P0/P1 findings have been queued for their approval; low-confidence findings have been autonomously triaged or queued. The engineer approves, downgrades, or rejects.
6. **Fix loop**: when AgentForge ships a fix, the regression harness runs automatically. The engineer reviews regressions if any appear, otherwise the loop is hands-off.
7. **Coverage review** (weekly): reviews the coverage matrix dashboard to see which categories the orchestrator has been spending time on, which are under-tested, and adjusts category budgets if needed.
8. **Compliance reporting** (monthly / quarterly): exports a coverage and findings summary for the CISO's audit-evidence file.

### Specific scenarios

- A new AgentForge feature ships. The engineer adds its endpoints to `targets.yaml`, lets the orchestrator's exploration policy probe them for a week, then reviews findings. Without the platform, they would have run two days of manual tests once and moved on.
- A new jailbreak technique is published (e.g., a paper at USENIX or BlackHat). The engineer adds it to the attack library. The Red Team Agent learns to generate variants. The platform reports whether AgentForge is vulnerable, across all attack surfaces, by morning. Manual equivalent: days.
- A fix lands for a previously-found P1 PHI-leak vulnerability. The regression harness runs. Either it passes (the fix held) or it fails (regression detected — the engineer is paged immediately). Without the platform, the engineer might not retest until the next quarterly review.

---

## Secondary user — Hospital CISO / VP of Information Security

The accountable owner. Not the daily operator, but the person whose risk register and board reporting depends on the platform's output.

### Profile

- **Role**: Chief Information Security Officer or equivalent.
- **Reports to**: CIO or directly to executive leadership; presents to the board.
- **Skill model**: Strong on governance, risk, compliance, and security operations. Not hands-on with prompts or LangGraph code.
- **Time allocation**: Reviews summaries, not findings.

### Goals

- Be able to answer the board's question "*are we testing our AI for security and what have we found?*" with concrete metrics, not adjectives.
- Satisfy the HIPAA Security Rule §164.308(a)(1) risk-analysis requirement for AI tools (mandatory once the 2026 NPRM finalizes).
- Have a documented, auditable trail showing the org's AI security posture over time.
- Justify the security team's budget by showing measurable risk reduction.

### Workflow with the platform

1. **Quarterly review**: pulls the coverage report and findings trend chart. Sees a chart of P0/P1 findings discovered, fixed, and regressing over time. Sees coverage-budget allocation across attack categories.
2. **Incident response**: when an AgentForge vulnerability is reported externally (researcher, customer, news article), checks whether the platform's regression suite already covers that pattern. If not, that's a gap — the engineer adds it.
3. **Audit support**: when the org is audited (HIPAA, SOC 2, internal), provides the audit trail (run manifests, findings, fixes, regression results) as compliance evidence.
4. **Budget defense**: presents to executive leadership using the trend data — "we found and fixed N high-severity AI vulnerabilities this quarter; here is the cost-per-finding."

### Specific scenarios

- The board asks "how do we know our clinical AI is secure?" The CISO opens the platform's dashboard, shows coverage across the OWASP LLM Top 10, points at the regression-suite history, names the most recent P0 finding and its fix-validation timestamp. Answer in minutes, with evidence, not weeks of preparation.
- An external researcher reports a prompt-injection bug in AgentForge. The CISO checks the platform — was this category covered? If yes, why didn't the platform find it (gap to close)? If no, why wasn't it covered (prioritization question for the security engineer)?
- The HIPAA auditor asks for evidence that AI tools were included in the §164.308 risk analysis. The CISO exports the platform's last-quarter coverage and findings report.

---

## Tertiary user — AgentForge Product / Engineering Team

The team whose code is being attacked. They are not the buyers of the platform, but they are an important secondary consumer of its output.

### Profile

- AgentForge engineers, tech leads, and product manager.
- Skill model: deep on AgentForge internals, varying depth on security.
- Time allocation: feature work is the day job; security fixes are interruptions.

### Goals

- Catch security regressions in their own PRs before they ship.
- Have actionable vulnerability reports — clear reproduction steps, suggested remediation, evidence — not vague flags.
- Avoid being blocked by security issues at release time.

### Workflow with the platform

1. **Pre-merge CI gate**: a lightweight subset of the platform's regression suite runs on every PR against a staging deployment. If a previously-fixed vulnerability re-appears, the PR is blocked. If a new P0 is found, the PR is flagged for security review.
2. **Vulnerability report consumption**: when a P0/P1 vulnerability is filed as a GitLab issue, the report contains: reproducible attack sequence, expected vs. observed behavior, severity, OWASP/MITRE/HIPAA framework tags, suggested remediation. The engineer fixes from the issue without needing to context-switch to a security person.
3. **Fix validation loop**: ships a fix on a feature branch; the regression harness runs automatically; if it passes, the engineer merges with confidence.

### Specific scenarios

- An engineer adds a new agent tool. The platform's orchestrator picks up the new tool surface from the next coverage scan and tests it within a few days. The engineer doesn't have to remember to ask the security team to test it.
- An engineer's PR refactors the prompt-injection defense. The regression harness runs the full injection suite. If the refactor introduced a regression, the PR fails; the engineer fixes before merge.

---

## Quaternary user — AI Safety Researcher

External or internal. Not part of the hospital's day-to-day operations, but a contributor of new attack techniques and a consumer of platform data for research.

### Profile

- Academic, independent researcher, or member of an AI safety org.
- Skill model: deep on adversarial AI; less deep on healthcare specifics.

### Workflow

1. **Contribute attack techniques**: submits new attack patterns to the platform's attack library. The library is versioned; contributions are reviewable.
2. **Run evaluations**: uses the platform's existing infrastructure to evaluate a new technique against an AI target with established ground truth.
3. **Export research data**: exports anonymized findings and coverage data for research papers (with appropriate review for PHI safety).

---

## Specific Use Cases (across personas)

1. **Pre-release security gate** — the platform runs as a CI gate. Block merges or deployments that introduce P0 regressions.
2. **Continuous overnight stress testing** — no human in the loop. Orchestrator picks the next attack campaign, Red Team probes, Judge evaluates, Documentation files high-confidence findings autonomously. Morning review surfaces what needs human attention.
3. **New-attack-technique evaluation** — a published technique (e.g., a new jailbreak from a paper) is added to the attack library; the platform reports whether the target is vulnerable across all relevant attack surfaces.
4. **Compliance reporting** — exports a coverage and findings summary mapped to HIPAA §164 sections for the audit-evidence file.
5. **Regression validation after a fix** — a previously-fixed vulnerability is re-tested against every new target build. Regression detection without manual re-testing.
6. **Coverage analysis** — the coverage matrix surfaces under-tested categories. The operator rebalances category budgets.
7. **Cost forecasting** — the platform's cost model projects the spend for N runs at the current architecture. Used to budget for the next quarter.
8. **Cross-target testing (future)** — the same platform, the same agents, applied to a different AI clinical tool (not just AgentForge). The threat model and rubrics are reused; only the target surface inventory differs.

---

## Why Automation? Why Multi-Agent?

The architecture-defense answer. This section is the load-bearing justification for every design choice in `ARCHITECTURE.md`.

### Why not manual penetration testing?

Manual pentest is the status quo. It fails on four axes:

- **Coverage**: a human pentester tests a handful of known techniques. Hundreds of variants and combinations go untested.
- **Cadence**: a human pentest happens annually or per-release, not continuously. Drift between tests is invisible.
- **Cost**: a pentester at consultant rates costs $50–250k per engagement. At the cadence the new HIPAA rule implies, this is prohibitive.
- **Consistency**: two different pentesters produce different findings on the same system. Comparability across runs is poor.

A pentester *should still be in the loop* — to triage low-confidence findings, to handle novel attack categories, to interpret clinical-judgment edge cases. But they should not be the runner.

### Why not a static test suite?

A static suite of known attack payloads is the natural next step. It also fails:

- **Static payloads age.** A jailbreak that worked last quarter is patched this quarter. The test passes for the wrong reason — not because the underlying vulnerability category is closed, but because the specific payload's surface markers were filtered.
- **No mutation.** Real adversaries mutate. A partially-successful attack should be probed for variants. A static suite cannot do that.
- **No exploration.** A static suite tests what it knows. It does not probe categories it doesn't yet have payloads for.

### Why not a single agent?

A single LLM agent that generates attacks, evaluates them, and writes reports fails on two axes:

- **Conflict of interest.** An agent that both generates an attack and judges whether it succeeded will, by design, drift toward declaring its own work successful. This is the same reason human red teams separate generation from evaluation across people.
- **Context contamination.** An agent that holds the full attack-context in its window when grading is not evaluating with a fresh mind. The Judge must see the attack and the target's response, *not* the Red Team's reasoning about why this attack should work.

### Why not a linear pipeline?

A pipeline (generate → execute → evaluate → file) is a natural shape for a small system. It still fails the brief's requirements:

- **Pipelines don't adapt.** The Orchestrator's job — read coverage state, prioritize, allocate budget — has no clean place in a pipeline. The system runs whatever the previous stage produced, not whatever it should be probing next.
- **Pipelines don't escalate.** A partially-successful attack in a pipeline is "complete" — the next stage runs. There is no separate agent whose job is to take a half-broken attack and generate ten mutations.
- **Pipelines don't allocate.** Pipelines treat every input as equivalent. The Orchestrator's coverage-weighted prioritization has no analog.

### Why these four specific agents?

The brief mandates four distinct agents. Here is why each one is its own agent rather than a method on a larger system:

| Agent | Why it must be distinct |
|---|---|
| **Red Team Agent** | Generates adversarial input. Should be *aggressive* — its system prompt encourages exploration of the attack surface. Must not have access to the Judge's rubric (which would teach it the test, not the underlying vulnerability). Runs on a different LLM provider than the Judge to break correlation. |
| **Judge Agent** | Evaluates whether an attack succeeded. Must be *skeptical* and *consistent*. Must not see the Red Team's reasoning — only the attack and the target's response. Runs on a different LLM provider than the Red Team. Verdicts are reproducible per (target SHA, rubric SHA, model version). |
| **Orchestrator Agent** | Reads platform state, decides what to test next, allocates budget, halts on cost or canary failure. Operates on aggregate data, not on individual attacks. Its decisions are auditable — every dispatch is logged with the coverage gap that drove it. |
| **Documentation Agent** | Converts confirmed findings into structured, professional vulnerability reports. Files high-confidence reports autonomously; queues low-confidence and P0/P1 for human approval. Its job is **conservative** — it must not fabricate, exaggerate, or hallucinate severity. |

Each agent's trust level, conflict-of-interest profile, and runtime constraint is different. Combining any two of them into one agent introduces a conflict of interest that breaks the testing guarantee.

### Where humans stay in the loop, and why

Autonomy is the default, but specific decision points always require humans:

- **P0 / P1 findings before filing.** A confidently-filed P0 vulnerability against the wrong target, or based on a false-positive Judge verdict, can waste days of engineering time on a non-issue. Or worse, if filed externally, can damage a vendor relationship. Human approval is cheap insurance.
- **Low-confidence findings.** When the Judge's confidence is below a configurable threshold, the finding queues for human review rather than autonomous filing.
- **Novel attack categories.** When a Red Team generates an attack pattern that falls outside the current threat model, the Orchestrator escalates rather than executing. Humans decide whether to expand scope.
- **Approval to attack a new target.** Adding a URL to `targets.yaml` is a manual operator action. No agent can add to the allowlist.
- **Kill switch.** The platform halts on operator command. Always.

These gates are not just safety mechanisms — they are also the system's **trust-building surface**. A CISO who approves a finding once and sees it reproduced consistently will, over time, raise their trust in the platform's autonomous decisions.

---

## Comparison Table — How the Platform Improves Each Persona's Workflow

| Workflow | Status quo | With the platform |
|---|---|---|
| Pre-release AI security gate | Manual test pass, often skipped on tight schedules | Automated CI gate, blocks merges on regressions |
| Daily monitoring of AI security posture | Doesn't exist; weekly check at best | Overnight runs, daily triage queue |
| Adopting a newly-published attack technique | One-off manual test, results not retained | Add to library, platform tests it across all surfaces by morning |
| Regression validation after a fix | Often skipped; same engineer tests their own fix | Automated; previously-fixed vulnerabilities regress as test failures |
| Compliance reporting for HIPAA §164.308(a)(1) | Hand-assembled annually | Continuously generated, exportable |
| Coverage analysis | Anecdotal | Coverage-matrix dashboard with category-level budgets |
| Cost prediction for security testing | Manual estimate, often wrong | Cost-model output at 100 / 1K / 10K / 100K runs |
| Vulnerability writeup | 1–2 hours per finding | Documentation Agent drafts; human approves |

---

## What the Platform Is Not

It's important to state what the platform does not replace:

- **Not a substitute for human security expertise.** The platform finds vulnerabilities; humans interpret severity in clinical context, approve high-severity findings, and decide remediation strategy.
- **Not a classical web pentest.** Network-layer attacks, infrastructure pentesting, and OWASP Top 10 web vulnerabilities outside the AI surface are handled by existing tooling.
- **Not a model-level safety eval.** The platform tests the *application* surface — the way the LLM is deployed in AgentForge — not the underlying model's safety alignment.
- **Not a production-protection system.** It is a *testing* platform. Runtime protection (input filtering, output redaction, guardrails) is a separate concern handled by AgentForge itself. The platform tests whether those runtime defenses hold.

---

## Open Questions about Users

- **Multi-tenancy.** For a portfolio piece, the platform is single-tenant (one operator, one AgentForge target). For a production posture, multi-tenant access controls would be required. Out of scope for this assignment.
- **External attack-library contributions.** A future version could accept external contributions to the attack library through pull requests; for now, the library is operator-controlled.
- **Researcher data export.** Anonymization rules for finding exports to researchers are out of scope for this assignment but are a known follow-up.


---

## Companion documents

- [`README.md`](./README.md) — quickstart + project overview
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — system design and agent roles
- [`THREAT_MODEL.md`](./THREAT_MODEL.md) — attack surface, in-scope vs out-of-scope
- [`DEFENSE.md`](./DEFENSE.md) — architecture defense (conflict-of-interest separation)
- [`DIAGRAMS.md`](./DIAGRAMS.md) — Mermaid + ASCII system diagrams
- [`presearch.md`](./presearch.md) — initial scoping notes

*Source of truth for the operational schema: `rubrics/SCHEMA.md`.
Source of truth for the data contracts: `src/agentforge_redteam/state.py`.*
