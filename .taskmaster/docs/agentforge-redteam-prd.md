# AgentForge Adversarial AI Security Platform — Week 3 PRD

# Overview

This PRD covers the full Week 3 Gauntlet AI deliverable: an autonomous multi-agent platform that continuously red-teams the **AgentForge Clinical Co-Pilot** (built in Weeks 1–2), deployed at `https://143.244.157.90`. The platform discovers, mutates, evaluates, and files security vulnerabilities against a live healthcare AI target with minimal human-in-the-loop.

Four agents with distinct trust levels and different LLM providers — Red Team (GPT-4o), Judge (Claude Sonnet 4.6), Orchestrator (Claude Haiku 4.5), Documentation (Claude Sonnet 4.6) — coordinate through a LangGraph state machine. State persists in SQLite; traces go to Langfuse. Confirmed findings auto-promote into a regression harness and file as GitLab issues in the AgentForge project. The architecture is justified by structural conflict-of-interest separation (attack generation vs. evaluation on different providers), reproducibility (versioned YAML rubrics), and HITL on high-stakes filing decisions.

Two milestones drive scope:

- **MVP gate** — Tuesday 2026-05-12 23:59. ≥3 attack categories with results, ≥1 agent live against the deployed target, hard-gate documents (THREAT_MODEL, USERS, ARCHITECTURE) submitted, deployed URL submitted.
- **Final gate** — Friday 2026-05-15 12:00. Public web UI, ≥3 polished vulnerability reports, AI Cost Analysis at 100/1K/10K/100K runs, demo video (3–5 min), social post.

The deliverable that matters is not the most impressive jailbreak in a demo. It is a platform a hospital CISO could trust to run continuously against systems their physicians depend on. The platform's positioning hook is the new HIPAA Security Rule §164.308(a)(1) AI-tool-risk-analysis requirement finalizing May 2026 — this is the substrate that satisfies that compliance need.

# Core Features

## Red Team Agent (GPT-4o, OpenAI)

Generates adversarial inputs against the target; mutates partially-successful attacks into variants. Aggressive by design; constrained by a deterministic content filter that refuses out-of-scope content (real exploits, CBRN, child-safety) before the payload reaches the target. Reads seed payloads from `attack_library.json` (versioned), retrieves prior attempts from SQLite for mutation context. Trust level: untrusted-output-source. Falls back to OpenRouter open-source model if GPT-4o refusal rate exceeds 20% on legitimate in-scope categories.

## Judge Agent (Claude Sonnet 4.6, Anthropic)

Evaluates whether each attack succeeded against versioned, structured YAML rubrics. Independent of Red Team — different provider, no shared context, never sees Red Team's reasoning. Verdicts are reproducible per `(target_sha, rubric_sha, model_version)`. Verdict is structured JSON filling the rubric schema (not free-form prose). Trust level: trusted-evaluator. Canary cases injected every Nth verdict to detect drift; orchestrator halts on canary failure.

## Orchestrator Agent (Claude Haiku 4.5, Anthropic)

Reads platform state from SQLite, prioritizes next campaign by coverage gap and historical severity, allocates per-campaign cost budget, halts on budget exhaustion or canary failure, triggers regression runs. Operates on aggregate state, never individual attacks. Selection policy: coverage-weighted prioritization with epsilon exploration (default 0.1). Cannot expand the target allowlist or change rubrics. Trust level: decision-making within configured policy.

## Documentation Agent (Claude Sonnet 4.6, Anthropic)

Converts confirmed findings into structured, professional vulnerability reports. Assigns severity deterministically (from rubric outcomes, not LLM judgment). Sanitizes evidence (strips PHI patterns, JWTs, API keys, full document bodies). Files high-confidence P2/P3 findings autonomously as GitLab issues; routes P0/P1 and low-confidence findings to human approval queue. Reports carry framework tags: OWASP LLM Top 10 2025 IDs, MITRE ATLAS v5.4.0 technique IDs, HIPAA §164 sections.

## Audited tool wrapper + kill switch

Every tool call by every agent routes through one wrapper that writes to SQLite (audit log) and Langfuse (trace) with a shared `step_id`. Wrapper checks the kill_switch flag in SQLite before every tool execution. Single point of trust for audit completeness; operator can halt the platform instantly via CLI (`agentforge-redteam halt`) or the Final web UI's halt endpoint.

## SQLite state store

Local file (`var/platform.db`). Tables: `agent_steps`, `attacks`, `verdicts`, `findings`, `regression_runs`, `coverage_matrix`, `run_manifests`, `kill_switch`, `human_approval_queue`. Orchestrator reads coverage matrix on every dispatch decision; sub-100ms query latency; no network dependency for the decision loop. Migration-managed; schema is the source of truth for inter-agent message types.

## Versioned YAML rubrics

One per attack category (`rubrics/<category>.yaml`). Define verdict schema (verdict, confidence, evidence_refs) and per-check criteria (some deterministic, some LLM-evaluated). Rubric SHA captured in every verdict. Updates are diffable in git. Rubric schema is the contract Judge fills.

## Judge ground-truth dataset

30–50 hand-curated test cases across the 3 MVP attack categories. Known-pass, known-fail, known-partial. Built **before** Judge code runs. Judge accuracy on the ground-truth set is a CI gate; subset injected as canaries into every orchestrator session. Human-overridden Judge verdicts feed back as new ground-truth cases.

## Regression harness

Every confirmed finding auto-promotes to `evals/regressions/<finding_id>.json` (deterministic test case). On new target SHA or operator trigger, the harness replays every test against the new target using the **original** rubric (not the latest). Regressions detected by verdict comparison; P0/P1 regressions page operator.

## Langfuse observability layer

Human-facing traces with session/trace/generation/span hierarchy. Score = Judge verdict. Reuses the AgentForge Langfuse instance for cognitive overhead reduction. Cross-store consistency with SQLite via shared `step_id`.

## Target allowlist (`targets.yaml`)

Git-committed YAML allowlist of URLs the platform may attack. Platform refuses any URL not on the list. No agent can modify the file. For MVP: localhost dev-easy + droplet at `143.244.157.90`.

## Coverage matrix + selection policy

Per-category, per-sub-attack metrics: runs_last_7d, runs_lifetime, findings_by_severity, last_run_at, last_regression_at, avg_cost_per_run, coverage_score. Selection policy is hybrid: deterministic weights with LLM-driven candidate selection within the surfaced set.

## CLI (Typer)

Operator entrypoint for MVP. Commands: `start-session`, `halt`, `queue list/approve/reject`, `regress`, `eval-judge`, `ground-truth new`, `list`. Each command writes to SQLite; halt trips the kill switch.

## Public web UI (Final only)

FastAPI + minimal frontend (HTMX or small Vue page). Routes: kick off a run, view coverage matrix, browse open findings, view audit log, toggle kill switch. Basic-auth for now; OAuth is post-cohort. Backed by the same SQLite + LangGraph process as the CLI.

# User Experience

## Operator journey — Healthcare AI Security Engineer

The platform's primary user. Reads `THREAT_MODEL.md` and confirms attack categories. Configures `targets.yaml`, provides API keys in `.env`, sets the GitLab token. Contributes hand-curated cases to the Judge ground-truth set. After setup, the platform runs autonomously on a nightly cron. Daily triage: reviews vulnerability reports filed overnight, approves P0/P1 in the queue, downgrades or rejects false positives. Weekly: reviews the coverage matrix dashboard, rebalances category budgets. Monthly: exports a coverage and findings summary for HIPAA §164.308(a)(1) compliance evidence.

## CISO journey — Hospital Information Security Officer

Accountable owner. Quarterly: pulls the coverage report and findings trend chart. Sees P0/P1 findings discovered, fixed, and regressing over time. Sees coverage-budget allocation across attack categories. Audit support: provides the platform's run-manifest history as compliance evidence. Incident response: when an external vulnerability report lands, checks whether the platform's regression suite covers that pattern.

## AgentForge product team journey

Secondary consumer. Pre-merge CI gate runs a lightweight subset of the regression suite on every PR against a staging deployment. Vulnerability reports filed as GitLab issues contain reproducible attack sequences, expected vs. observed behavior, severity, framework tags, suggested remediation. Engineer can fix from the issue without context-switching to a security person. Fix validation loop: regression harness re-runs the suite when the fix branch is pushed.

## AI safety researcher journey

Quaternary user. Contributes new attack techniques to the versioned attack library. Uses the platform to evaluate published jailbreak techniques against the target. Exports anonymized findings data for research.

# Technical Architecture

## Affected components — agentforge-redteam (this repo)

- `src/agentforge_redteam/` — Python package, PSR-style layout
  - `agents/redteam.py`, `agents/judge.py`, `agents/orchestrator.py`, `agents/documentation.py`
  - `graph.py` — LangGraph state machine wiring
  - `state.py` — Pydantic `PlatformState`, `CampaignBrief`, `AttackRecord`, `VerdictRecord`, `ConfirmedFinding`
  - `tools/` — wrapped tool implementations (call_target, replay_target, mutate_payload, etc.)
  - `tools/wrapper.py` — audited tool wrapper (every call routes through here)
  - `state_store/` — SQLite migrations + repository pattern
  - `rubrics/loader.py` — YAML rubric loader + validator
  - `attack_library/loader.py` — JSON seed-payload loader
  - `severity.py` — deterministic severity mapping from rubric outcomes
  - `sanitizer.py` — deterministic PHI / secret redaction
  - `allowlist.py` — `targets.yaml` loader + URL validator
  - `kill_switch.py` — SQLite-backed flag check
  - `regression/harness.py` — finding-to-test promotion + replay engine
  - `cli.py` — Typer-based CLI entrypoint
  - `web/` — FastAPI app (Final only)
- `prompts/redteam.md`, `prompts/judge.md`, `prompts/orchestrator.md`, `prompts/doc.md` — versioned system prompts
- `rubrics/prompt-injection-indirect.yaml`, `rubrics/data-exfiltration.yaml`, `rubrics/tool-misuse.yaml` — MVP rubrics
- `attack_library.json` — versioned seed payloads
- `targets.yaml` — URL allowlist
- `orchestrator_policy.yaml`, `documentation_policy.yaml`, `models.yaml` — versioned configuration
- `evals/judge_ground_truth/` — 30–50 hand-curated cases (YAML, per-category subdirs)
- `evals/regressions/` — confirmed-finding test cases (JSON, auto-generated)
- `templates/finding.md.j2` — Jinja2 vulnerability report template
- `tests/` — pytest unit and integration tests
- `.env.example` — required env vars (ANTHROPIC_API_KEY, OPENAI_API_KEY, LANGFUSE_*, GITLAB_TOKEN)
- `.gitlab-ci.yml` — CI pipeline for unit + integration tests
- `pyproject.toml` — uv-managed Python project

## Affected components — AgentForge target (read-only, the system under test)

The target is the existing AgentForge stack on the droplet:
- FastAPI sidecar BFF (`/api/agent/turn`, `/api/agent/upload`, `/api/agent/document/{id}`, `/api/agent/promote`, FHIR proxy)
- Vue patient dashboard with AgentForge drawer
- OpenEMR PHP module (chart reads, document upload/fetch, lab/intake persistence, intake promotion)
- LangGraph agent orchestration with Langfuse traces

The platform does not modify the target. The platform reads the target SHA from the droplet's `/health` endpoint or a manual `--target-sha` flag.

## Affected components — deployment

- Second DigitalOcean droplet (separate from the AgentForge target droplet) — runs the platform
- GitLab CI cron — triggers nightly `start-session` runs
- Langfuse SaaS instance (reuses AgentForge's) — receives traces

## Data flow

1. **Operator triggers session**: CLI or CI cron invokes `agentforge-redteam start-session --cost-cap=5.00 --target=droplet`.
2. **Orchestrator reads state**: queries SQLite `coverage_matrix`, `open_findings`, `recent_regressions`, `cost_per_category`, recent canary outcomes.
3. **Orchestrator selects campaign**: applies coverage-weighted prioritization with epsilon exploration; emits `CampaignBrief` (typed Pydantic).
4. **Red Team executes campaign**: reads seed from `attack_library.json`, constructs payload (LLM mutation), passes through deterministic content filter, calls target via audited `call_target` tool.
5. **Target responds**: status, body, latency captured.
6. **Judge evaluates**: loads `rubrics/<category>.yaml`, runs deterministic pre-checks, runs LLM rubric-fill (Claude Sonnet) on remaining checks, emits `VerdictRecord` with confidence.
7. **Canary check**: if this campaign was a canary, Judge result compared to ground-truth; mismatch halts session.
8. **Documentation Agent (if verdict=pass/partial)**: dedup, deterministic severity assignment, deterministic evidence sanitization, LLM-drafted report. HITL routing: P0/P1 OR low-confidence → `human_approval_queue`; P2/P3 high-confidence → autonomous GitLab file.
9. **Orchestrator updates coverage matrix**: writes campaign_completed; checks budget, canaries, kill_switch.
10. **Loop or halt**: if cost remaining + no halt conditions, dispatch next campaign. Otherwise write session_halted with reason.
11. **All steps**: agent_steps row appended to SQLite; corresponding span in Langfuse with shared `step_id`.

## Eval architecture

- **Judge meta-eval**: ground-truth set of 30–50 cases. `agentforge-redteam eval-judge` runs Judge against all cases, computes precision/recall/accuracy by category. CI gate: must hit ≥80% precision, ≥90% recall on known-fail subset.
- **Canary subset**: 5–8 cases injected at random intervals during orchestrator sessions. Failure → halt + drift alert.
- **Regression suite**: `evals/regressions/<id>.json` auto-generated from confirmed findings. Re-runs against new target SHA using the **original** rubric. Pass = vulnerability fixed; fail = regression.
- **Per-target reproducibility**: every verdict is keyed by `(target_sha, rubric_sha, model_version, prompt_sha)`. Re-running an identical (target, config) tuple must produce the identical verdict within model-temperature tolerance.

## Configuration substrate

All operator-tunable behavior lives in versioned files captured in run manifests:
- `targets.yaml` — URL allowlist
- `rubrics/*.yaml` — per-category verdict schema and checks
- `attack_library.json` — seed payloads (categorized by sub-attack)
- `prompts/*.md` — agent system prompts
- `orchestrator_policy.yaml` — coverage targets, epsilon, weights, budget caps
- `documentation_policy.yaml` — HITL thresholds, severity thresholds
- `models.yaml` — per-agent model + temperature config

Run manifest captures SHA of each. Reproducibility per `(target_sha, prompt_set_sha, rubric_set_sha, attack_library_sha, policy_sha)`.

# Development Roadmap

## Phase 0 — Repo + CI bootstrap (lands first)

1. Initialize `pyproject.toml` with `uv` and dependencies: langgraph, langfuse, anthropic, openai, pydantic v2, pytest, sqlmodel or sqlite3 + alembic, typer, fastapi (for Final), jinja2, pyyaml, structlog, httpx.
2. Author `.gitignore` (Python defaults + `.env`, `var/`, `.taskmaster/state.json` not tracked).
3. Author `.env.example` listing required env vars: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `LANGFUSE_PUBLIC_KEY`, `LANGFUSE_SECRET_KEY`, `LANGFUSE_HOST`, `GITLAB_TOKEN`, `OPENROUTER_API_KEY` (fallback).
4. Author `LICENSE` (MIT) and `README.md` skeleton with setup instructions and architecture diagram link.
5. Configure `.gitlab-ci.yml` with stages: lint, type-check, unit-test, integration-test. Unit + integration on every push; eval-judge + live-droplet runs gated to release tags.
6. Verify the existing six planning documents are committed and cross-linked from README.

## Phase 1 — Hard-gate document verification

7. Cross-check `ARCHITECTURE.md`, `THREAT_MODEL.md`, `USERS.md` for the brief's required ~500-word executive summary at the top of each.
8. Verify Mermaid diagram present in `ARCHITECTURE.md` and `DIAGRAMS.md`; verify ASCII fallback also present for terminal viewers.
9. Verify `THREAT_MODEL.md` framework mapping is complete for 3 MVP categories (OWASP LLM ID, MITRE ATLAS ID, HIPAA section).
10. Update `presearch.md` to mark open questions resolved as they close.

## Phase 2 — Foundation: Pydantic schemas, SQLite, audit wrapper, kill switch

11. Define Pydantic `PlatformState`, `CampaignBrief`, `AttackRecord`, `VerdictRecord`, `ConfirmedFinding` in `src/agentforge_redteam/state.py` with strict types and field validators. Add tests for serialization round-trip and validation edge cases.
12. Create SQLite schema migrations for `agent_steps`, `attacks`, `verdicts`, `findings`, `regression_runs`, `coverage_matrix`, `run_manifests`, `kill_switch`, `human_approval_queue`. Apply via Alembic or sqlite3 + Python migrations. Tests verify schema applies cleanly on a fresh DB.
13. Implement `tools/wrapper.py` audited tool wrapper: takes `(agent, tool, args)`, checks kill switch, appends `agent_steps` row, calls tool, updates row with result/cost/latency, emits Langfuse span with shared `step_id`. Tests verify writes to SQLite and Langfuse (mocked) on every call.
14. Implement `kill_switch.py` SQLite-backed flag check + CLI `halt` command. Tests verify flag-check semantics and that tripping the switch raises `KillSwitchTripped`.
15. Implement `allowlist.py` `targets.yaml` loader and URL validator. Tests verify allowed URLs pass and disallowed URLs raise `TargetNotAllowed`.
16. Implement `sanitizer.py` deterministic PHI / secret redaction (regex-based for Synthea patterns, JWT tokens, common API key prefixes, full document bodies). Tests cover known patterns and known-safe inputs.
17. Implement `severity.py` deterministic mapping from rubric outcome to severity (P0–P3). Tests cover every rubric-outcome → severity edge.

## Phase 3 — Judge ground-truth dataset + rubrics

18. Design rubric YAML schema in `rubrics/SCHEMA.md`: verdict_schema, checks (with type=deterministic|llm), severity_map. Implement `rubrics/loader.py` with Pydantic validation.
19. Fill `rubrics/prompt-injection-indirect.yaml` with sub-attack-specific checks (marker_token_reproduced, citation_to_nonexistent_source, system_prompt_revealed, agent_took_unauthorized_action).
20. Fill `rubrics/data-exfiltration.yaml` with PHI-detection checks, cross-patient-id verification, minimum-necessary judgment, Langfuse trace check.
21. Fill `rubrics/tool-misuse.yaml` with unauthorized-tool-invocation check, parameter-tamper check, audit-log-evasion check, recursive-loop check.
22. Build `agentforge-redteam ground-truth new` CLI for interactive case authoring (Typer + Anthropic SDK). Prompts user for attack input, captures live target response, prompts for verdict + confidence + rubric outcomes, validates consistency, writes YAML to `evals/judge_ground_truth/<category>/<id>.yaml`.
23. Hand-author 30 ground-truth cases minimum (10 per MVP category, mixed difficulty/outcome). Distribution: ~50% known-fail, ~30% known-pass, ~15% partial, ~5% inconclusive. Timebox to 4 hours Monday. Expand to 45–50 if Final-phase time allows.

## Phase 4 — Agent skeletons: LangGraph 4-node graph

24. Build the LangGraph state machine in `src/agentforge_redteam/graph.py`: four nodes (orchestrator → red_team → judge → documentation), shared `PlatformState`, conditional edges based on verdict and halt conditions. Tests verify graph compiles and a no-op pass through the graph preserves state.
25. Implement `agents/redteam.py` skeleton: campaign brief consumption, attack-library lookup, GPT-4o call with system prompt from `prompts/redteam.md`, deterministic content filter applied to output, `call_target` tool invocation, AttackRecord hand-off. Tests with mocked OpenAI client.
26. Implement `agents/judge.py` skeleton: rubric loader, deterministic pre-checks, Claude Sonnet rubric-fill with structured output (Pydantic validation), VerdictRecord emission. Tests with mocked Anthropic client.
27. Implement `agents/orchestrator.py` skeleton: SQLite coverage-matrix read, deterministic selection policy with epsilon, Haiku invocation for reasoning trace, CampaignBrief emission. Tests with seeded SQLite + mocked Anthropic client.
28. Implement `agents/documentation.py` skeleton: dedup check, severity assignment, sanitizer invocation, Sonnet report drafting, HITL routing, GitLab API client. Tests with mocked GitLab API.
29. Wire Langfuse instrumentation into all four agent nodes via the audited tool wrapper. Verify session/trace/generation/span hierarchy.
30. Author `prompts/redteam.md`, `prompts/judge.md`, `prompts/orchestrator.md`, `prompts/doc.md` with versioned system prompts. Capture prompt SHA in run manifests.

## Phase 5 — MVP GATE (Tue 23:59)

31. Implement `attack_library.json` with 3 seed payloads per MVP sub-attack (9 seeds minimum across 3 categories). Validate against rubric structure.
32. End-to-end smoke test: `agentforge-redteam start-session --cost-cap=2.00 --target=droplet --categories=prompt-injection-indirect`. Verify Red Team generates payload, hits target, captures response, Judge evaluates, verdict written to SQLite, span in Langfuse.
33. Repeat smoke test for `data-exfiltration` and `tool-misuse` categories. Each must produce ≥1 verdict.
34. Validate at least one verdict is `pass` (real finding). If no findings, expand seed payloads with explicit known-vulnerable inputs until at least one finding lands.
35. Implement minimum Documentation Agent path: write finding to `findings/<id>.md` locally. GitLab API integration deferred to Phase 7 if time-constrained; for MVP minimum, file one finding manually as GitLab issue to demonstrate the path works.
36. **MVP submission**: deployed target URL submitted, six planning docs committed, README updated with setup + run instructions, smoke-test output captured, ≥1 GitLab issue filed.

## Phase 6 — Orchestrator coverage policy + Regression Harness

37. Implement full Orchestrator selection policy: coverage matrix denormalization from `agent_steps` + `verdicts`, weighted random selection, epsilon-greedy exploration, regression trigger detection (new target SHA, manual trigger, finding age), session-stop conditions (budget, canaries, kill, no-progress). Tests cover each branch of `select_next_campaign`.
38. Implement cost cap enforcement: per-session budget in SQLite, per-campaign allocation, per-agent step caps. Orchestrator `halt_if_cost_exceeded` precheck before every dispatch.
39. Build the Regression Harness module: finding-to-test promotion writes `evals/regressions/<id>.json`. Harness `replay(test_case, new_target_sha)` runs the payload, invokes Judge with the **original** rubric, compares verdicts. Detects: held, regressed, weakly-passing-due-to-model-change. Tests on synthetic fixtures.
40. Wire the Regression Harness into the Orchestrator: regression-due triggers (new target SHA detected, manual, aged) dispatch a regression campaign instead of a fresh attack.
41. Implement canary mechanism: Judge maintains a small set of canary cases injected every Nth verdict (configurable, default 10). Failure (Judge verdict ≠ ground-truth) writes canary_failed event; Orchestrator halts on read.

## Phase 7 — Documentation Agent polish + HITL queue

42. Build `templates/finding.md.j2` Jinja2 vulnerability report template with all required sections (severity, framework mapping, description, clinical impact, reproduction, observed vs expected, evidence, remediation, validation).
43. Implement full Documentation Agent flow: dedup → severity → sanitize → draft (Sonnet) → HITL routing → GitLab issue filing with framework-tag labels (`OWASP-LLM01`, `MITRE-AML.T0051`, `HIPAA-164.308`, severity-Px). Tests with mocked GitLab API.
44. Implement `human_approval_queue` SQLite-backed workflow. CLI: `queue list`, `queue approve <id>`, `queue reject <id>`. Rejected verdicts auto-feed back as new ground-truth cases labeled `verdict: fail`.
45. Hand-author ≥3 polished vulnerability reports for the Final submission (drawn from MVP findings; refined for clarity, completeness, remediation specificity).

## Phase 8 — Public web UI

46. Implement FastAPI app in `src/agentforge_redteam/web/`. Endpoints: `POST /sessions/start`, `GET /sessions/{id}`, `GET /coverage`, `GET /findings`, `GET /findings/{id}`, `POST /halt`, `GET /queue`, `POST /queue/{id}/approve`, `POST /queue/{id}/reject`. Basic-auth middleware.
47. Build the minimal frontend: HTMX + server-rendered HTML or a small Vue page (decide based on time). Views: kick-off form, coverage matrix table, findings list, finding detail, queue list with one-click approve/reject buttons, kill switch (big red button).
48. Deploy the platform + web UI to a second DigitalOcean droplet (separate from the target droplet). Configure: HTTPS via Let's Encrypt, basic-auth credentials, GitLab CI cron schedule for nightly runs, environment variables.

## Phase 9 — FINAL GATE (Fri 12:00)

49. Author the AI Cost Analysis deliverable: actual MVP dev spend, per-agent token usage, projected costs at 100/1K/10K/100K runs with each of the six architectural levers from `ARCHITECTURE.md` (prompt caching, deterministic pre-filters, smaller model for routine campaigns, batch API for regressions, payload-hash caching, open-source Red Team). Tables + chart.
50. Record demo video (3–5 min): walk through one campaign live against the droplet, show coverage matrix, show a filed vulnerability report, show the kill switch. Author social post (X or LinkedIn) per brief's requirement.

# Logical Dependency Chain

Tasks must land in this order — a downstream task cannot start before its upstream dependency is complete.

1. **Rubric YAML schema (Task 18) → Judge implementation (Task 26) → Judge accuracy gate (in Phase 5 smoke tests)**. Judge cannot grade without a rubric schema; cannot be promoted to live without the accuracy gate.
2. **Judge ground-truth dataset (Task 23) → Judge accuracy gate → Judge promoted to live**. Without ground truth, Judge accuracy is unmeasurable. 30-case floor must land before Phase 5.
3. **`targets.yaml` allowlist (Task 15) + audited tool wrapper (Task 13) + kill switch (Task 14) → ANY agent that calls the target**. The Red Team's first `call_target` invocation must go through the wrapper.
4. **SQLite schema migrations (Task 12) → `coverage_matrix` denormalization → Orchestrator selection policy (Task 37)**. The Orchestrator's first selection call queries SQLite; schema must exist first.
5. **LangGraph `PlatformState` Pydantic types (Task 11) → all four agent nodes (Tasks 25–28)**. Inter-agent message types must be defined and validated before agents wire to them.
6. **`attack_library.json` (Task 31) + 3 MVP rubrics (Tasks 19–21) → Red Team seed payloads → live attack runs (Tasks 32–34)**. Red Team cannot mutate from nothing.
7. **`ConfirmedFinding` schema (Task 11) → regression harness (Task 39) → `evals/regressions/<id>.json` artifacts**. Regression harness depends on the finding schema being stable.
8. **MVP gate complete (Phase 5, Tasks 31–36) → web UI work (Phase 8, Tasks 46–48)**. The UI cannot ship before the platform produces output to render. Web UI must not steal time from MVP.

# Risks and Mitigations

## Risk: GPT-4o refusal rate >20% on healthcare adversarial generation

Frontier models are trained to refuse offensive content. With proper "authorized security research" framing in the Red Team system prompt, GPT-4o generally engages — but the refusal rate is unmeasured for this specific domain. Mitigation: pre-provision an OpenRouter API key for an open-source model (DeepSeek-V3 or Qwen 2.5 72B). Architectural impact is a single config change in `models.yaml`; no rewrite. Measure refusal rate in the first 24 hours of MVP testing.

## Risk: Judge drift toward "pass" (sycophancy)

LLM judges have a documented bias toward agreeing with the input. If Judge drifts, the platform produces false positives until human review catches them. Mitigation: ground-truth canary cases (5–8 known-pass + known-fail) injected at random intervals into every orchestrator session. If a canary verdict diverges from ground-truth, Orchestrator halts and surfaces drift alert. Judge cannot drift silently for more than ~10 verdicts.

## Risk: Cost blowout from autonomous loops

Multi-agent systems can stack tokens fast. A bug in Red Team mutation or Orchestrator dispatch could burn the entire $50 MVP budget in minutes. Mitigation: hard session budget cap enforced in SQLite (`halt_if_cost_exceeded` precheck before every campaign dispatch); per-agent step caps; tool-call timeouts; recursive-loop detection in the Red Team mutation budget.

## Risk: AgentForge target instability during demo

If the droplet has issues during the Friday demo, the platform has nothing to attack. Mitigation: maintain a FastAPI mock-target stub (replicates `/api/agent/turn`, `/api/agent/upload`, `/api/agent/document/{id}`, `/api/agent/promote` with deterministic-vulnerable responses). Demo falls back to the mock if the droplet is down; mock can also be used for fast local testing.

## Risk: Web UI scope eats Wed–Thu

A minimal web UI is ~1 day of work; an "impressive" one is unbounded. Mitigation: timebox to one day. If UI work slips, ship CLI + Langfuse traces as the demo surface. Web UI is not the hard gate; the platform running against the live target is.

## Risk: Judge ground-truth authoring time blows up

30–50 hand-curated cases at ~10 minutes each is 5–8 hours. Risk of perfectionism stretches this further. Mitigation: timebox to 4 hours Monday afternoon; 30-case floor minimum for MVP; expand to 45–50 only if Final-phase time allows. Use the `ground-truth new` CLI (Task 22) to streamline authoring.

# Appendix

## Origin of this PRD

This PRD distills six existing planning documents committed in the repo: `presearch.md`, `THREAT_MODEL.md`, `USERS.md`, `ARCHITECTURE.md`, `DIAGRAMS.md`, `DEFENSE.md`. Each was authored from the Week 3 brief (`Week 3 - AgentForge - Adversarial AI Security Platform.pdf`) and verified against the current state of OWASP LLM Top 10 2025, OWASP Web Top 10 2025, MITRE ATLAS v5.4.0, NIST AI 600-1, HIPAA Security Rule 2026 NPRM, and the OWASP GenAI Red Teaming Guide.

## Out of scope this sprint (with reasons)

- **Multi-tenant authentication and per-tenant isolation**. MVP is single-tenant; multi-tenancy requires auth, isolation, separate state per tenant. Post-cohort.
- **Self-hosted Red Team (Ollama / vLLM on a GPU droplet)**. Adds ops burden during 4-day clock. The architecture supports a single config swap to an open-source provider; pre-provision OpenRouter as the fast path. Self-hosting is post-cohort.
- **Real-PHI testing under a BAA**. Requires a clinical IT environment and HIPAA-compliant platform infrastructure. Out of scope; use Synthea synthetic data only.
- **Postgres migration from SQLite**. SQLite covers single-tenant MVP. Schema is intentionally simple enough that migration is mechanical when scale demands it.
- **OAuth on the web UI**. Basic-auth for MVP and Final. OAuth integration is post-cohort.
- **Stretch attack categories 4–6** (state corruption, DoS, identity & role exploitation). Documented in `THREAT_MODEL.md`. Receive zero coverage budget until MVP categories meet target coverage. Mentioned in Phase 9 as stretch only.
- **Supervisor + worker subgraph LangGraph refactor**. Single graph for MVP. Refactor is a Final-phase consideration only if parallelism is needed; otherwise post-cohort.
- **Anthropic prompt caching, batch APIs, payload-hash caching implementations**. These are cost-reduction levers documented in `ARCHITECTURE.md`. The Phase 9 Cost Analysis *measures* their impact; implementations are post-cohort.
- **MITRE ATLAS technique ID verification** for IDs not load-bearing in MVP rubrics (`AML.T0036`, `AML.T0048`, `AML.T0070`). Tracked in `THREAT_MODEL.md` appendix as a one-off cleanup, not a Taskmaster task.

## Key architectural decisions referenced

- Multi-agent (not pipeline, not single-agent) — brief mandate.
- Provider independence between Red Team (OpenAI) and Judge (Anthropic) — breaks model-family correlation.
- Single LangGraph for MVP, supervisor pattern reserved for Final — KISS first.
- SQLite for Orchestrator decisions, Langfuse for human-facing traces — decoupled stores, decoupled purposes.
- Versioned YAML rubrics (not free-form Judge prompts) — reproducibility, drift detection.
- Audited tool wrapper for every tool call — single point of trust for audit completeness.
- HITL gates on P0/P1 filing, low-confidence findings, allowlist additions, kill switch — autonomous default with conservative bias on high-stakes decisions.
- Phased deployment: droplet + CI cron for MVP, public web UI for Final — matches the brief's two-milestone shape.
- TDD on deterministic surfaces (schemas, loaders, severity mapping, sanitizer, allowlist, audit wrapper); eval-driven on LLM loops (Red Team mutation, Judge grading, Orchestrator policy) — matches user's established TDD workflow on this fork.
