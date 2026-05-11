# Pre-Search Summary — AgentForge Adversarial AI Security Platform

**Date**: 2026-05-11
**Project**: `agentforge-redteam`
**Target system**: AgentForge Clinical Co-Pilot (built Weeks 1-2 of the Gauntlet AI Austin track), deployed at `https://143.244.157.90`
**Source repo (target)**: `https://labs.gauntletai.com/cameroncandelori/openemr`
**Deadlines**:
- Architecture Defense: ~4h after kickoff
- MVP: Tuesday 2026-05-12 23:59
- Final: Friday 2026-05-15 12:00

---

## Project context

This project builds a **multi-agent adversarial evaluation platform** that continuously stress-tests the AgentForge Clinical Co-Pilot. The platform is not a static test runner. It is an autonomous system of four agents — Red Team, Judge, Orchestrator, Documentation — that discover, mutate, evaluate, and file vulnerabilities against a live healthcare AI target, with minimal human-in-the-loop.

The platform lives in a **separate repository** from the AgentForge target. The target and the attacker must not share a tree, a host, a deploy pipeline, or an observability instance trust boundary. The brief is explicit: a pipeline or single-agent architecture does not satisfy this assignment. Each agent has its own role, context, and decision-making authority.

The deliverable that matters is not "the most impressive jailbreak in a demo." It's a platform a hospital CISO could trust to run continuously against systems their physicians depend on.

---

## Phase 1: Constraints

### Domain

- **Domain**: Healthcare AI adversarial security testing.
- **Target**: AgentForge Clinical Co-Pilot — Vue dashboard + FastAPI sidecar + LangGraph agent orchestration + OpenEMR PHP module + JWT-protected internal endpoints; document ingestion, vision extraction, RAG, persistence, observability.
- **MVP attack categories (3, hard gate)**:
  1. **Indirect prompt injection** through notes, guideline corpus chunks, and uploaded PDFs / images.
  2. **Data exfiltration** — PHI leakage, cross-patient data exposure, authorization bypass.
  3. **Tool misuse** — unintended chart-write invocation, parameter tampering against persistence paths.
- **Stretch categories (Final, if time)**: state corruption (conversation history manipulation, context poisoning), DoS / cost amplification (token exhaustion, recursive loops), identity/role exploitation (privilege escalation, persona hijacking).
- **Verification requirements**: every finding includes a reproducible attack sequence, the rubric the Judge graded against, the verdict, evidence references (sanitized), and a severity rating. No real PHI, raw JWTs, OAuth tokens, or API keys in artifacts.
- **Data sources**: live target at the droplet, Synthea synthetic patient records, existing AgentForge eval fixtures, public security frameworks (OWASP LLM Top 10, OWASP GenAI Red Teaming Guide, NIST AI RMF, MITRE ATLAS).

### Scale & Performance

- **Expected volume**: tens of attacks per MVP iteration; hundreds per Final demo run. AI Cost Analysis deliverable requires architectural reasoning at **100 / 1K / 10K / 100K** runs.
- **Latency**: not strict for offline runs. Orchestrator must halt on cost/time blowup, not run until the budget is exhausted.
- **Concurrency**: single-tenant, queued. No parallel orchestrator sessions for MVP.
- **Cost ceilings**:
  - MVP build: ~$50 (Mon–Tue)
  - Final build + demo: ~$50 (Wed–Fri)
  - Total budget for the assignment: ~$100
  - Path A (per-token API) confirmed: Anthropic + OpenAI API keys with billing available.

### Reliability

- **False negative cost**: missed vulnerability in clinical AI → potential patient safety harm. Treated as the higher-cost error.
- **False positive cost**: wasted engineering time, lost trust in the platform.
- **HITL design**:
  - High-confidence Judge verdicts → Documentation Agent files vulnerability reports **autonomously**.
  - Low-confidence verdicts → routed to a human approval queue.
  - **P0 / P1 findings always require human approval** before filing, regardless of Judge confidence.
- **Audit**: every run produces a manifest — target SHA, rubric SHA, model versions, prompt SHAs, operator, environment, start/end time, sanitized evidence references. Append-only audit log in SQLite, mirrored to Langfuse.

### Team

- **Solo builder** (Cameron).
- Strong Python / TypeScript / PHP fluency.
- Already operating LangGraph + Langfuse in the AgentForge sidecar — reuse rather than learn new stacks.
- **TDD** is the primary workflow on this fork (per CLAUDE.md). For this project:
  - **Strict TDD with pytest** on deterministic surfaces (rubric loader, attack-suite loader, schemas, cost cap, allowlist, severity rubric, GitLab issue formatter).
  - **Eval-driven** on LLM loops (Red Team mutation, Judge grading, Orchestrator policy) — same TDD spirit, different harness.

---

## Phase 2: Architecture

### Framework

- **LangGraph** for agent orchestration (reused from AgentForge — lowers cognitive overhead).
- **Topology for MVP**: single graph, four nodes (Orchestrator → Red Team → Judge → Doc), shared typed state object. KISS.
- **Topology for Final (if scaling pressure shows up)**: refactor toward supervisor + worker subgraphs (Orchestrator as supervisor; Red Team / Judge / Doc as subgraphs with their own state).
- **Language / runtime**: Python 3.12+. `uv` for dependency management.
- **CLI**: Typer for the operator entrypoint.
- **Web UI (Final only)**: FastAPI + minimal frontend (HTMX or small Vue page) for the public dashboard.

### LLM (per-agent split)

| Agent | Model | Provider | Reasoning |
|---|---|---|---|
| Red Team | **GPT-4o** | OpenAI (Provider A) | Independence from Judge. Strong tool use. Generally engages with "authorized security research" framing. |
| Judge | **Claude Sonnet 4.6** | Anthropic (Provider B) | Independent of attack engine — different provider, different training, different blind spots. Strong rubric-based grading. |
| Orchestrator | **Claude Haiku 4.5** | Anthropic | High volume, cheap, fast routing/priority decisions. Does not grade attacks. |
| Documentation | **Claude Sonnet 4.6** | Anthropic | Professional report writing, low volume. |

**Fallback plan**: if GPT-4o's refusal rate exceeds 20% on legitimate in-scope attack categories during early MVP testing, swap in an OpenRouter API key with an open-source model (DeepSeek-V3 or Qwen 2.5 72B) for the Red Team Agent. Architectural swap, not redesign.

### Tools (per agent, sketch)

- **Red Team**: `call_target(prompt, conversation_id, attachment)`, `mutate_payload(seed, strategy)`, `lookup_attack_library(category)`, `retrieve_past_results(category)`.
- **Judge**: `replay_target(test_case)`, `check_pii_leak(response)`, `check_unauthorized_action(trace)`, structured-output schema for verdict.
- **Orchestrator**: `read_observability_state()`, `select_next_campaign(coverage_gaps, severity)`, `trigger_red_team(plan)`, `trigger_regression()`, `halt_if_cost_exceeded()`.
- **Documentation**: `write_report(finding)`, `assign_severity(evidence)`, `query_human_for_approval(finding)`, `file_to_gitlab(report)` (filed as GitLab issues in the AgentForge project so they feed the fix cycle).

### Observability

- **Langfuse** for inter-agent traces (sessions, generations, scores).
- **SQLite** state store as the Orchestrator's queryable substrate: `coverage_matrix`, `open_findings`, `recent_regressions`, `cost_per_category`, `run_manifests`. The Orchestrator reads from SQLite, not Langfuse API, to keep its decision loop fast and decoupled.
- **Audit log**: every agent step appended into SQLite (`agent_steps` table) and also exported to Langfuse. All tool calls routed through a single audited wrapper to guarantee completeness.

### Evals (Judge meta-eval)

- **30–50 hand-curated ground-truth test cases** across the 3 MVP attack categories (known-pass, known-fail, known-partial). Built **before** Judge enters real runs.
- Judge accuracy on the ground-truth set is a **CI gate** — re-runs when prompts, rubrics, or models change.
- A subset of canary cases is **injected into every orchestrator session**; if Judge fails the canaries mid-run, the orchestrator halts and flags Judge drift.

### Verification (anti-drift)

- **Structured YAML rubrics per attack category**, versioned in git (`rubrics/prompt-injection-indirect.yaml`, etc.).
- Judge LLM call **fills the rubric schema**, not free-form. Verdict = structured JSON output, deterministic schema.
- Verdicts are reproducible per `(target SHA, rubric SHA, model version)` triple. Re-running against an unchanged target with an unchanged rubric must produce the same verdict (within model-temperature tolerance).
- Verdict provenance is stored: which rubric criterion fired, what evidence the Judge cited.

---

## Phase 3: Operations

### Failure modes

1. **Red Team generates genuinely harmful content** (real exploit code, child-safety violation, etc.). → In-domain scope prompt enforcing the attack taxonomy + deterministic content filter on Red Team output before it touches the target.
2. **Judge drifts toward "pass"** on everything. → Ground-truth canary cases injected each run; halt orchestrator on canary failure.
3. **Orchestrator stagnation** (same category every iteration). → Coverage-weighted prioritization with an epsilon exploration term; halt if no progress for N runs.
4. **Cost blowout**. → Hard budget cap per orchestrator session enforced in SQLite; Orchestrator must call `check_budget()` before each campaign.
5. **Cascading failure** (Red Team timeout → Judge has no input → Orchestrator loops). → Per-agent step caps + tool-call timeouts + graceful campaign abandonment with an "infra failure" record (not counted as a finding or as coverage).

### Security (trust & safety for the platform itself)

- **Target allowlist** (`targets.yaml`, committed): platform refuses to attack any URL not on the list. MVP list: local dev-easy + the AgentForge droplet at `143.244.157.90`.
- **Scoped credentials**: GitLab token has write access only to the AgentForge project. Anthropic / OpenAI API keys live in `.env` (gitignored), with per-key usage caps set in the providers' consoles.
- **P0 / P1 approval gate**: human must approve via CLI prompt or web hook before the Doc Agent files P0 or P1 vulnerabilities, regardless of Judge confidence.
- **Audit log**: append-only SQLite + Langfuse mirror, every agent step recorded (who/what/when/cost/tool call/result hash).
- **Kill switch**: CLI-callable command (`agentforge-redteam halt`) that immediately stops the orchestrator graph and prevents any in-flight tool calls from completing. Implemented via a shared `running` flag in SQLite that every agent checks before tool execution.
- **No PHI / secrets in artifacts**: every report passes a redaction sanitizer that strips known synthetic PHI patterns, JWTs, OAuth tokens, API key shapes, and full document bodies.

### Testing strategy

- **Layer 1 — Unit tests (pytest, strict TDD)**: rubric loader, attack-suite loader, finding / report schemas, cost-cap enforcement, target allowlist, severity rubric mapping, GitLab issue formatter, redaction sanitizer.
- **Layer 2 — Integration tests (mock target)**: end-to-end agent graph against a **FastAPI stub** that simulates AgentForge endpoints (deterministic responses). Fast, runs in CI on every push.
- **Layer 3 — Adversarial / eval (live droplet)**: full agents against the real target. Slow, costs money, doesn't block PRs but **does** block release tags. Manually triggered and pre-release-gated.

### Open source

- **Portfolio piece**, not a community release.
- **MIT license**.
- README + setup guide. No contribution guide, no release cadence.

### Deployment (phased)

| Milestone | Posture |
|---|---|
| **MVP (Tue 23:59)** | Platform runs on a **second DigitalOcean droplet** (separate from the AgentForge target droplet). GitLab CI cron triggers nightly runs. **No public web UI yet.** Results visible via Langfuse traces + GitLab issues filed against the AgentForge project. Hard gate satisfied: platform running, target public, live results. |
| **Final (Fri 12:00)** | Minimal **public web UI** (FastAPI backend + small frontend): kick off a run, see coverage matrix, browse vulnerability reports, see kill switch. Basic-auth for now; OAuth is post-cohort. |

- **Prompt versioning**: agent prompts live in `prompts/*.md` in the repo, referenced by relative path. Commit SHA is stamped on every run manifest.
- **CI**: GitLab CI runs unit + integration tests on every push. Eval CI (live droplet) is manual and / or release-tag-gated.
- **Rollback**: git revert, re-run. State store records prompt SHA per finding, so old findings remain reproducible.

### Iteration

- **Source 1 — regression harness**: every confirmed finding is auto-promoted to a deterministic test case in `evals/regressions/`. Every AgentForge fix triggers a regression run; previously-fixed vulnerabilities re-appearing flags a regression.
- **Source 2 — human-overridden Judge verdicts** become Judge eval cases (added to the ground-truth set). Judge improves over time, with versioned rubrics + ground-truth versions.
- **Source 3 — attack library refresh**: `attack_library.json` is a versioned file the Red Team's `lookup_attack_library` tool reads. MVP refresh is manual. Post-cohort: a weekly cron pulls new techniques from OWASP LLM Top 10 updates, MITRE ATLAS, and public jailbreak corpora.

---

## Open Questions

- [ ] **Langfuse instance** — reuse the existing AgentForge Langfuse, or stand up a separate one? Reuse is faster; separate gives a cleaner audit story (attacker observability is not co-located with target observability).
- [ ] **Second droplet** — does it need its own DigitalOcean account, or share with the AgentForge target's account? (Sharing simplifies billing; separate accounts strengthen blast-radius isolation.)
- [ ] **Public web UI auth** — basic-auth credential, or piggyback on AgentForge's OAuth? Basic-auth is faster for Friday.
- [ ] **GitLab filing identity** — file as the user, or as a dedicated bot account? Bot account is cleaner audit.
- [ ] **Judge accuracy threshold for MVP** — proposed: ≥80% precision and ≥90% recall on the known-fail ground-truth subset; tune after first eval run.
- [ ] **OpenRouter as backup** — pre-provision an OpenRouter API key now, or wait until GPT-4o refusal rate becomes a blocker? Pre-provisioning is ~$5 of buffer.
- [ ] **Run cadence for the always-on Final deployment** — once per night, every 4 hours, or on-demand only? Cron cadence has direct cost implications at scale.

---

## Identified Risks

1. **GPT-4o refusal patterns are untested** in healthcare-AI adversarial generation as of the start of this project. → Measure refusal rate in first 24h; swap to OpenRouter if needed. Single-API-call-replacement fallback, not a rewrite.
2. **Judge drift over time** is the hardest reliability problem in the assignment. Ground-truth canaries + rubric pinning + versioned verdicts mitigate, but **detection of drift is itself imperfect** — a Judge that drifts toward "pass" might also pass the canaries.
3. **Cost blowout from autonomous loops** — multi-agent systems can stack tokens fast. Mitigated by hard budget cap + step caps + tool-call timeouts, but mid-MVP a bug could still burn a chunk of the $50 budget before being noticed.
4. **Public web UI scope risk for Final** — could eat all of Wed–Thu if unbounded. Mitigated by timeboxing UI to one day; if it slips, ship CLI + Langfuse dashboard as the demo surface.
5. **AgentForge target instability** — if the droplet has issues during the demo, the platform has nothing to attack. Mitigated by keeping the mock target FastAPI stub working as a fallback demo surface.
6. **API key blast radius** — if Anthropic / OpenAI keys leak, attacker can run up cost. Keys in `.env` (gitignored), per-key usage caps in provider consoles, and secrets stripped from Langfuse traces.
7. **Audit trail completeness** — if observability misses any agent step, post-hoc attribution fails. Every tool call routes through a single audited wrapper.
8. **AgentForge target is the user's own production droplet** — running real adversarial probes against it could create persistent state (filed findings, log entries, even artifact rows from intake / chart-write attempts). Mitigation: target allowlist + read-only probes by default + explicit `--allow-write-probes` flag with a confirmation prompt.

---

## Next Steps

In dependency order, not parallel:

1. **Repo bootstrap** — `agentforge-redteam/` is initialized. Add `.gitignore`, MIT `LICENSE`, README skeleton, `.env.example`.
2. **Write the three brief-mandated documents** (this is the architecture-defense substrate):
   - `THREAT_MODEL.md` — port the surface inventory from `openemr/docs/agentforge-vulnerability-finder-presearch.md`, refine to the 3 MVP attack categories, lead with the brief-required ~500-word executive summary.
   - `USERS.md` — security engineer, CISO, Co-Pilot product team. Workflows, specific use cases, **explicit justification** for why autonomous multi-agent is the right architecture vs. a static test runner.
   - `ARCHITECTURE.md` — multi-agent design with each agent's role, inputs/outputs, trust level, inter-agent communication, orchestration policy, regression harness, observability layer. ~500-word executive summary + agent interaction diagram.
3. **Python project init** — `uv init`, `pyproject.toml` with deps: `langgraph`, `langfuse`, `anthropic`, `openai`, `pydantic`, `pytest`, `sqlmodel`, `typer`, `fastapi` (last one for Final UI).
4. **Judge ground-truth dataset** — write 30–50 cases across 3 MVP categories **before** any agent code. This is the eval substrate the rest of the platform calibrates against.
5. **Deterministic surfaces with TDD** — rubric loader, attack-suite loader, finding / report schemas, cost-cap enforcement, target allowlist, severity rubric, redaction sanitizer, audited tool wrapper.
6. **LangGraph skeleton** — four agent nodes, shared typed state, basic topology, Langfuse instrumentation, SQLite state store wired through the audited wrapper.
7. **Red Team Agent** — first 3 seed attacks per MVP category (9 total). Test against live droplet by Tuesday morning.
8. **Judge Agent** — graded against the ground-truth set. Tune until accuracy meets threshold.
9. **Orchestrator** — coverage matrix, cost cap, exploration policy.
10. **Documentation Agent** — initially writes findings to `findings/*.md` in the repo; wire GitLab API for live filing once format is stable.
11. **MVP gate (Tue 23:59)** — platform running against droplet, ≥3 attack categories with live results, ≥1 agent (Red Team or Judge) running live, all hard-gate documents present.
12. **Final-phase work (Wed–Fri)** — public web UI, AI Cost Analysis at 100/1K/10K/100K runs, ≥3 polished vulnerability reports, demo video, social post.

---

## Decisions log (referenced from above, for the architecture defense)

- Separate repo, not inside the OpenEMR fork. Reason: attacker and target must not share a tree, a host, or a deploy pipeline.
- LangGraph + Langfuse reuse. Reason: lower cognitive overhead, same primitives as AgentForge.
- Provider independence between Red Team (OpenAI) and Judge (Anthropic). Reason: brief explicitly requires Judge independent of attack engine; different providers go further than same-provider-different-model.
- Single graph for MVP, supervisor pattern as a Final-phase refactor option. Reason: KISS; defer complexity until scaling pressure justifies it.
- Hand-curated Judge ground truth before any agent code. Reason: without it, Judge accuracy is unmeasurable, and the rest of the platform calibrates against a Judge we can't trust.
- Rubrics as versioned YAML, Judge fills the schema. Reason: prevent Judge drift; reproducibility per `(target SHA, rubric SHA, model version)`.
- Phased deployment: droplet-only for MVP, public web UI for Final. Reason: the brief's hard gate is *target* publicly accessible + platform running, not platform UI; web UI is for the demo, not the gate.
