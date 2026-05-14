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

## Verifying from a fresh checkout

A grader / reviewer can verify every load-bearing claim in this repo
with the following sequence after `git clone` + `uv sync`:

```bash
# 1. Full test suite — must finish green.
uv run pytest --no-header -q
# expected: "663 passed"

# 2. Confirm the 6-category coverage. All 6 threat-model categories
# must have a rubric YAML and ≥3 attack seeds.
ls rubrics/*.yaml
# expected: data-exfiltration / dos-cost-amplification /
#           identity-role-exploitation / prompt-injection-indirect /
#           state-corruption / tool-misuse  (6 files)
uv run python -c "import json, collections; \
  cats = collections.Counter(s['category'] for s in \
    json.load(open('attack_library.json'))['attacks']); \
  print('\n'.join(f'{c}: {n}' for c, n in sorted(cats.items())))"
# expected: 6 categories, total 27 seeds (≥6 per MVP, ≥3 per stretch)

# 3. Confirm Judge ground truth covers all 6 categories (≥10 each).
ls evals/judge_ground_truth/
for d in evals/judge_ground_truth/*/; do
  echo "$(basename "$d"): $(ls "$d" | wc -l | tr -d ' ') cases"
done
# expected: 6 categories, 10 cases each, 60 total

# 4. Regression replay — must run cleanly (no FK errors, no drift
# warnings) from a fresh DB. NOOP clients are fine for the smoke;
# set ANTHROPIC_API_KEY for a real Judge replay.
rm -f /tmp/regress_audit.db
PLATFORM_DB_PATH=/tmp/regress_audit.db uv run alembic upgrade head
PLATFORM_DB_PATH=/tmp/regress_audit.db uv run agentforge-redteam regress \
    --target-sha audit-check --root evals/regressions
# expected: total: 6, held: 6, regressed: 0  (no IntegrityError)

# 5. Live deployed platform — operator UI + healthz.
curl -sS -o /dev/null -w "%{http_code}\n" https://104-248-232-22.sslip.io/healthz
# expected: 200
# UI:  https://104-248-232-22.sslip.io/ui/    (BasicAuth — see /etc/agentforge-redteam/redteam.env on the droplet)
# All 6 categories visible in the platform's own coverage matrix:
#   curl -u $WEB_UI_USER:$WEB_UI_PASSWORD https://104-248-232-22.sslip.io/coverage | jq '[.rows[].category] | unique'
```

For the bug-and-fix history (every issue we've found and how it was
resolved), see [`docs/BUG_LEDGER.md`](./docs/BUG_LEDGER.md). For
per-session evidence packages (DB SHAs, cost summaries, multi-turn
transcripts, regression replay output), see
[`docs/EVIDENCE/`](./docs/EVIDENCE/).

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

## Attack categories

All 6 threat-model categories from [`THREAT_MODEL.md`](./THREAT_MODEL.md)
are seeded in [`attack_library.json`](./attack_library.json) and have a
rubric YAML under [`rubrics/`](./rubrics/). MVP categories (1–3) get
≥6 seeds each; stretch categories (4–6) get ≥3 each. 5 of the 27 seeds
are multi-turn (`max_turns ≥ 2`).

**MVP** (the bulk of seed coverage):
- **prompt-injection-indirect** — marker tokens, citation fabrication, unauthorized actions, system-prompt revelation
- **data-exfiltration** — cross-patient PHI, minimum-necessary violations, trace leakage
- **tool-misuse** — unauthorized tool invocation, parameter tampering, recursive loops, audit-log evasion

**Stretch** (minimum representation, room to grow):
- **state-corruption** — fake-history injection, instruction persistence, confirmation-token forgery
- **dos-cost-amplification** — recursive tool invocation, unbounded response inflation, expensive query amplification
- **identity-role-exploitation** — attending-override assertion, persona flip, break-glass invocation

## Documentation

- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — system design
- [`THREAT_MODEL.md`](./THREAT_MODEL.md) — attack surface, in-scope vs out-of-scope
- [`USERS.md`](./USERS.md) — operator and CISO journeys
- [`DEFENSE.md`](./DEFENSE.md) — architecture defense (conflict-of-interest separation)
- [`DIAGRAMS.md`](./DIAGRAMS.md) — Mermaid + ASCII system diagrams
- [`presearch.md`](./presearch.md) — initial scoping notes
- [`docs/SMOKE_TEST_COVERAGE.md`](./docs/SMOKE_TEST_COVERAGE.md) — what the integration smokes cover and the deliberate gaps (e.g., no live HTTP to the deployed target)
- [`docs/COST_ANALYSIS.md`](./docs/COST_ANALYSIS.md) — per-run + at-scale cost projection (100 / 1K / 10K / 100K runs)
- [`docs/BUG_LEDGER.md`](./docs/BUG_LEDGER.md) — rolling record of platform bugs found and fixed, with impact + fix-commit links
- [`docs/EVIDENCE/`](./docs/EVIDENCE/) — portable per-session evidence packages (DB dumps, cost summaries, findings)

## MVP Status (2026-05-13)

- **Deployed platform (operator UI)**: `https://104-248-232-22.sslip.io/ui/` (TLS via Let's Encrypt, BasicAuth-protected)
- **Deployed target under test**: `https://143.244.157.90` (configured via `TARGET_DROPLET_URL`)
- **Hard-gate docs**: ARCHITECTURE.md, THREAT_MODEL.md, USERS.md, DEFENSE.md, DIAGRAMS.md, presearch.md (all committed)
- **Schema**: SQLite tables under Alembic management; migrations applied
- **Agents**: 4 LangGraph nodes (Red Team / Judge / Orchestrator / Documentation) wired with Protocol-typed clients via `graph_factory.build_production_graph`
- **Rubrics**: **6** production rubric YAMLs covering all 6 threat-model categories + 1 example fixture
- **Attack library**: **27** hand-curated seed payloads (6 prompt-injection-indirect / 6 data-exfiltration / 6 tool-misuse / 3 state-corruption / 3 dos-cost-amplification / 3 identity-role-exploitation), of which 5 are multi-turn (`max_turns: 3`)
- **Ground truth**: 30 hand-authored Judge cases (10 per MVP category; stretch-category ground truth pending)
- **Regression corpus**: **6** promoted cases in [`evals/regressions/`](./evals/regressions/), replayable end-to-end via `agentforge-redteam regress` (no FK errors, see `docs/EVIDENCE/regression_replay/` for a captured run)
- **Findings filing path**: GitLab-or-local-file fallback — 3 polished reports in `findings/*_polished.md`
- **Test suite**: **661** unit + integration tests, mypy strict, ruff clean

**What's next**: see [`docs/NEXT-SESSION.md`](./docs/NEXT-SESSION.md) for the live ops
runbook (deploy, smoke, trigger sessions, watch counters, tail logs) and the
prioritized debt list. Demo recording and live-evidence packaging are the
remaining open work for the final gate.

## License

MIT — see [LICENSE](./LICENSE).
