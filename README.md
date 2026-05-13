# AgentForge Adversarial AI Security Platform

> Autonomous multi-agent platform that continuously red-teams the AgentForge Clinical
> Co-Pilot against versioned rubrics with HIPAA-evidentiary audit logs.

## Overview

AgentForge is an autonomous multi-agent system that continuously discovers, evaluates, and
files security vulnerabilities in AI-assisted clinical workflows. Four agents with distinct
trust levels and independent model providers coordinate through a LangGraph state machine:
**Red Team** (GPT-4o, OpenAI) generates and mutates attacks, **Judge** (Claude Sonnet 4.6,
Anthropic) scores them against versioned YAML rubrics, **Orchestrator** (Claude Haiku 4.5,
Anthropic) prioritizes campaigns from coverage and budget state, and **Documentation**
(Claude Sonnet 4.6, Anthropic) files findings to GitLab — autonomously for high-confidence
P2/P3, through a human queue for P0/P1.

The platform is positioned against the new HIPAA Security Rule §164.308(a)(1)
AI-tool-risk-analysis substrate (NPRM finalizing May 2026), which puts AI tools explicitly
in scope of continuous, documented risk analysis. Manual pentests cannot satisfy that
cadence; this platform produces the evidentiary audit trail that can.

## Status

MVP shipped **2026-05-12**. Demo-prep underway. Final gate **2026-05-15**.

- **Deployed platform (operator UI):** [`https://104-248-232-22.sslip.io/ui/`](https://104-248-232-22.sslip.io/ui/) — TLS via Let's Encrypt, BasicAuth-protected. `/healthz` returns `200`.
- **Deployed target under test:** `https://143.244.157.90` (AgentForge Clinical Co-Pilot, built in Weeks 1–2).
- **Polished findings (committed):**
  [`findings/data_exfiltration_cross_patient_phi_disclosure_polished.md`](./findings/data_exfiltration_cross_patient_phi_disclosure_polished.md),
  [`findings/indirect_prompt_injection_citation_fabrication_polished.md`](./findings/indirect_prompt_injection_citation_fabrication_polished.md),
  [`findings/tool_misuse_unauthorized_chart_write_polished.md`](./findings/tool_misuse_unauthorized_chart_write_polished.md).
- **Documentation Agent sink:** GitLab when `GITLAB_TOKEN`+`GITLAB_PROJECT_ID` are set, else `LocalFindingsSink` writing to `findings/<title>-<n>.md`. The polished reports above are the local-sink output.

## Architecture at a glance

- Four agents (Red Team / Judge / Orchestrator / Documentation) on a LangGraph state machine.
- SQLite (`var/platform.db`) for queryable orchestration state; Langfuse for human-readable traces.
- Audited tool wrapper as the single point of trust for every tool call.
- Hard kill switch (`kill_switch` table flag) checked before every tool execution.

See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the full design and
[`DIAGRAMS.md`](./DIAGRAMS.md) for the agent-interaction diagram.

## Prerequisites

- Python 3.11 or newer
- [uv](https://github.com/astral-sh/uv) 0.11+
- API keys for Anthropic, OpenAI, Langfuse, and GitLab (see [`.env.example`](./.env.example))

## Setup

```bash
git clone <repo>
cd agentforge-redteam
uv sync                                    # installs deps + dev tools
cp .env.example .env                       # then fill in real keys
uv run alembic upgrade head                # creates var/platform.db
```

## Usage

Operator CLI (installed by `uv sync`):

- `agentforge-redteam start-session` — kick off a red-team session
- `agentforge-redteam halt` — trip the kill switch
- `agentforge-redteam queue list` / `queue approve <id>` / `queue reject <id>` — review
  the human-approval queue
- `agentforge-redteam regress` — replay every case in `evals/regressions/` against the
  target. Uses real `HTTPTargetClient` + Anthropic Judge when `ANTHROPIC_API_KEY` is set,
  else falls back to noop stubs (CI smoke path). The orchestrator runs the same replay
  automatically when a session halts on `regression_due` — `regress` is the manual
  one-shot equivalent.
- `agentforge-redteam eval-judge` — run Judge against the ground-truth set

Most live operations are also exposed through the deployed operator UI at
`https://104-248-232-22.sslip.io/ui/`. See [`docs/NEXT-SESSION.md`](./docs/NEXT-SESSION.md)
for the canonical command list (deploy, smoke, trigger, watch).

## Development

```bash
uv run pytest                              # 100+ unit tests
uv run ruff check src/ tests/              # lint
uv run ruff format --check src/ tests/     # formatting
uv run mypy src/                           # strict type-check
```

## Project layout

```
agentforge-redteam/
├── alembic/                  # database migrations (SQLite schema)
├── prompts/                  # versioned agent prompts (redteam, judge, orchestrator, doc)
├── rubrics/                  # versioned Judge rubrics, one YAML per category (planned)
├── src/agentforge_redteam/   # platform source
├── templates/                # Jinja2 finding-report templates
├── attack_library.json       # versioned seed attack payloads
├── targets.yaml              # target URL allowlist
├── alembic.ini               # Alembic config
└── pyproject.toml            # project + tooling config
```

## MVP attack categories

The three categories seeded in [`attack_library.json`](./attack_library.json):

- **prompt-injection-indirect** — marker tokens, citation fabrication, unauthorized actions
- **data-exfiltration** — cross-patient PHI, minimum-necessary violations, trace leakage
- **tool-misuse** — unauthorized tool invocation, parameter tampering, recursive loops

## Documentation

- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — system design
- [`THREAT_MODEL.md`](./THREAT_MODEL.md) — attack surface, in-scope vs out-of-scope
- [`USERS.md`](./USERS.md) — operator and CISO journeys
- [`DEFENSE.md`](./DEFENSE.md) — architecture defense (conflict-of-interest separation)
- [`DIAGRAMS.md`](./DIAGRAMS.md) — Mermaid + ASCII system diagrams
- [`presearch.md`](./presearch.md) — initial scoping notes
- [`docs/SMOKE_TEST_COVERAGE.md`](./docs/SMOKE_TEST_COVERAGE.md) — what the integration smokes cover and the deliberate gaps (e.g., no live HTTP to the deployed target)
- [`docs/COST_ANALYSIS.md`](./docs/COST_ANALYSIS.md) — per-run + at-scale cost projection (100 / 1K / 10K / 100K runs)

## MVP Status (2026-05-13)

- **Deployed platform (operator UI)**: `https://104-248-232-22.sslip.io/ui/` (TLS via Let's Encrypt, BasicAuth-protected)
- **Deployed target under test**: `https://143.244.157.90` (configured via `TARGET_DROPLET_URL`)
- **Hard-gate docs**: ARCHITECTURE.md, THREAT_MODEL.md, USERS.md, DEFENSE.md, DIAGRAMS.md, presearch.md (all committed)
- **Schema**: SQLite tables under Alembic management; migrations applied
- **Agents**: 4 LangGraph nodes (Red Team / Judge / Orchestrator / Documentation) wired with Protocol-typed clients via `graph_factory.build_production_graph`
- **Rubrics**: 3 production rubric YAMLs (prompt-injection-indirect / data-exfiltration / tool-misuse) + 1 example fixture
- **Attack library**: 16 hand-curated seed payloads (5 data-exfiltration / 5 indirect-prompt-injection / 6 tool-misuse)
- **Ground truth**: 30 hand-authored Judge cases (10 per category)
- **Findings filing path**: GitLab-or-local-file fallback — 3 polished reports already in `findings/*_polished.md`
- **Test suite**: 642 unit + integration tests, mypy strict, ruff clean

**What's next**: see [`docs/NEXT-SESSION.md`](./docs/NEXT-SESSION.md) for the live ops
runbook (deploy, smoke, trigger sessions, watch counters, tail logs) and the
prioritized debt list. Demo recording and live-evidence packaging are the
remaining open work for the final gate.

## License

MIT — see [LICENSE](./LICENSE).
