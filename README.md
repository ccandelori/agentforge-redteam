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

Active development. MVP gate **2026-05-12**, Final gate **2026-05-15**.

## MVP Status

> **Operator action required to clear the MVP gate:**
> 1. Run `agentforge-redteam queue list` to see pending high-severity findings.
> 2. Manually file ≥1 finding to the AgentForge GitLab project (project ID set via `GITLAB_PROJECT_ID`).
> 3. Replace the `<MVP_GITLAB_ISSUE_URL>` placeholder below with the issue URL.

- **Deployed target:** `https://143.244.157.90`
- **Filed finding:** `<MVP_GITLAB_ISSUE_URL>` (to be replaced after operator filing)
- **Local fallback:** when GitLab credentials are absent, the Documentation Agent writes rendered reports to `findings/<title>-<n>.md` via `LocalFindingsSink`.

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

> **Planned CLI (not yet implemented).** The commands below describe the operator surface
> wired up in a later task. Until then, the platform is exercised through the test suite
> and direct module imports.

- `agentforge-redteam start-session` — kick off a red-team session
- `agentforge-redteam halt` — trip the kill switch
- `agentforge-redteam queue list` / `queue approve <id>` / `queue reject <id>` — review
  the human-approval queue
- `agentforge-redteam regress` — run the regression harness against the current target SHA
- `agentforge-redteam eval-judge` — run Judge against the ground-truth set

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

## MVP Status (2026-05-12)

- **Deployed target**: `https://143.244.157.90` (configured via `TARGET_DROPLET_URL`)
- **Hard-gate docs**: ARCHITECTURE.md, THREAT_MODEL.md, USERS.md, DEFENSE.md, DIAGRAMS.md, presearch.md (all committed)
- **Schema**: 9 SQLite tables under Alembic management; ≥1 migration applied
- **Agents**: 4 LangGraph nodes (Red Team / Judge / Orchestrator / Documentation) wired with Protocol-typed clients
- **Rubrics**: 3 production rubric YAMLs (prompt-injection-indirect / data-exfiltration / tool-misuse) + 1 example fixture
- **Attack library**: 15 hand-curated seed payloads, 5 per category
- **Ground truth**: 30 hand-authored Judge cases
- **Findings filing path**: GitLab-or-local-file fallback — see `findings/*.md`
- **Test suite**: 500+ unit + integration tests, mypy strict, ruff clean

**Operator follow-ups for MVP submission** (manual steps):
1. Configure `GITLAB_TOKEN` and `GITLAB_PROJECT_ID` in `.env`
2. Run `uv run agentforge-redteam queue approve <queue_id>` on one finding from the local store
3. Screenshot the filed GitLab issue
4. Push to GitLab and submit the deployed URL + issue URL to the gradebook

## License

MIT — see [LICENSE](./LICENSE).
