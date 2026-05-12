# NEXT-SESSION.md — agentforge-redteam

**Last updated**: 2026-05-11 (Mon evening). Authored by Claude Code in the planning session before implementation begins.

This file is the first thing to read at the start of any new session on `agentforge-redteam`. It is the resume substrate — what's committed, what's next, what hurts.

---

## Where we are

Planning phase **complete**. Implementation phase **not started**.

Four commits on `main`:

```
94a86fc chore(taskmaster): initialize tasks from PRD via parse-prd --research
834400f docs(planning): add Taskmaster PRD for Week 3 build
05c78c0 docs(planning): add diagrams and defense substrate for architecture defense
a093940 docs(planning): initial presearch, threat model, users, and architecture
```

Eight documents in the repo, all committed:

- `presearch.md` (225 lines) — 16-point pre-search outcomes, open questions, identified risks, next-steps backlog
- `THREAT_MODEL.md` (445 lines) — attack surface mapped to OWASP LLM 2025 / OWASP Web 2025 / MITRE ATLAS v5.4.0 / NIST AI 600-1 / HIPAA §164
- `USERS.md` (258 lines) — four operator personas + the "why multi-agent" architecture justification
- `ARCHITECTURE.md` (837 lines) — four-agent design with tradeoffs and cost analysis
- `DIAGRAMS.md` (741 lines) — 12 Mermaid diagrams + ASCII fallbacks
- `DEFENSE.md` (295 lines) — anticipated Q&A, counter-arguments, honest limitations
- `.taskmaster/docs/agentforge-redteam-prd.md` (324 lines) — Taskmaster-shaped PRD distilling the above
- `.taskmaster/tasks/tasks.json` — 50 parent tasks + 231 subtasks (281 actionable units) with all 339 dependencies validated

## Read these first (in this order)

1. **This file** — you're already here.
2. `presearch.md` — fastest way to load context (open questions + decisions).
3. `ARCHITECTURE.md` § Executive Summary — 500-word framing of the four-agent design.
4. `task-master next` — Taskmaster tells you what to work on.
5. `task-master show <id>` — full task detail when you pick one up.

Skip on first read: DIAGRAMS.md (consult when needed), DEFENSE.md (consult before the architecture defense), the PRD (consult before adding tasks).

## Immediate next action

Open the repo. Run:

```bash
cd ~/Desktop/Gauntlet/agentforge-redteam
task-master next
```

Expected output: **Task #1 — Initialize Python project with uv and pyproject.toml** (complexity 3, no dependencies, 11 downstream blockers).

Then create the branch and start TDD:

```bash
git checkout -b task-1-init-python-project
```

Per CLAUDE.md and memory: branch-per-task. Per-task commits use `Assisted-by: Claude Code` trailer if Claude wrote them. TDD with pytest is the default for deterministic surfaces; eval-driven for LLM loops.

## Critical-path chain (don't break this order)

Per `THREAT_MODEL.md` and the PRD's Logical Dependency Chain section. Taskmaster's dependency graph enforces this, but as a sanity check:

1. **Task 1 (Init project)** → unlocks 11 children
2. **Tasks 11 + 12 (Pydantic schemas + SQLite migrations)** → unlock the audit wrapper
3. **Task 13 (Audited tool wrapper)** → required before any agent calls the target
4. **Tasks 14, 15 (Kill switch + targets.yaml allowlist)** → required before any live target call
5. **Task 18 (Rubric YAML schema) + Tasks 19/20/21 (3 MVP rubrics)** → required before Judge can grade
6. **Task 23 (30 ground-truth cases)** → required before Judge is promoted to live (timebox to 4h Monday afternoon if not done; PRD risk #6)
7. **Tasks 24–28 (LangGraph skeleton + 4 agent skeletons)** → unlock Phase 5 MVP gate
8. **MVP gate Phase 5 (Tasks 31–36)** → submission Tuesday 23:59
9. **Phases 6–9** → Final gate Friday noon

## Deadlines

- **MVP gate**: Tuesday 2026-05-12 23:59 — deployed target URL, ≥3 attack categories with results, ≥1 agent live, hard-gate docs submitted
- **Final gate**: Friday 2026-05-15 12:00 — public web UI, ≥3 polished vulnerability reports, AI Cost Analysis at 100/1K/10K/100K runs, demo video (3–5 min), social post

## What NOT to redo

Don't re-write any of the eight documents listed above. They're sized, scoped, and committed. If you find a gap, add to the relevant doc with a clear delta — don't rewrite.

Don't re-run `task-master parse-prd`. The 50 tasks are generated. If you need new tasks, use `task-master add-task` or amend the PRD and use `task-master update`.

Don't change the `.taskmaster/config.json` provider. It's copied from openemr to use `claude-code` provider (opus main, sonnet research, haiku fallback). This routes Taskmaster's LLM calls through the Claude Code subscription — $0 against the project API budget.

## Workflow expectations (per CLAUDE.md + memory)

- **TDD primary**. Deterministic surfaces (schemas, loaders, severity, sanitizer, allowlist, audit wrapper) → strict TDD with pytest. LLM loops (Red Team mutation, Judge grading, Orchestrator policy) → eval-driven.
- **Branch per task**. Each Taskmaster task gets its own feature branch off main. One commit per subtask for non-trivial tasks.
- **Commit trailer**: `Assisted-by: Claude Code` when Claude wrote the commit.
- **Run task-master CLI, not raw tasks.json**. Edit JSON directly only when CLI can't express the op.
- **Maintain `docs/DEVIATIONS.md`** when implementation diverges from `ARCHITECTURE.md` or the PRD. Log what changed, why, what we learned. Distinguish *deviation* from *unfinished work*.

## Gotchas not in the planning docs

1. **`.taskmaster/config.json` was overwritten** after `task-master init` to match the user's openemr config (claude-code provider). This is intentional. If you re-init Taskmaster for any reason, re-copy from `~/Desktop/Gauntlet/openemr/.taskmaster/config.json` before running parse-prd or expand. The init default uses direct Anthropic + Perplexity providers and would charge against API budget.

2. **`Week 3 - AgentForge - Adversarial AI Security Platform.pdf`** is in the repo root, untracked. It's the original brief. Decide whether to: (a) gitignore it, (b) move to `docs/brief/` and commit, (c) leave untracked as local reference. Default = leave untracked.

3. **`.gitignore` created by `task-master init` is JavaScript-oriented** (node_modules, etc.). Task 2 in the Taskmaster plan ("Create .gitignore for Python") will expand it for Python (`__pycache__/`, `*.pyc`, `.pytest_cache/`, `var/`, `dist/`, `build/`, `*.egg-info/`, `.coverage`, `htmlcov/`, `.venv/`, `.python-version`).

4. **MITRE ATLAS technique IDs flagged for verification** are listed in `THREAT_MODEL.md` Appendix. AML.T0036, AML.T0048, AML.T0070 are cited from training-era memory; the load-bearing ones (AML.T0051, AML.T0024, AML.T0053) were web-verified. Verify the rest against `atlas.mitre.org` before locking the rubrics in Phase 3.

5. **The HIPAA Security Rule 2026 NPRM is finalizing this month** (May 2026). Section numbers cited in THREAT_MODEL.md and ARCHITECTURE.md are from the proposed rule. After finalization, re-map any §164 references to the final rule. The compliance positioning is in `DEFENSE.md` § Compliance.

6. **GPT-4o refusal rate is unmeasured.** Plan to measure it in the first 24 hours of MVP build. If > 20% on legitimate in-scope categories, swap to OpenRouter (DeepSeek-V3 or Qwen 2.5 72B). Pre-provisioning an OpenRouter key is on the open-questions list in `presearch.md`.

7. **Judge ground-truth dataset is the architectural bottleneck.** PRD risk #6 + DEFENSE.md identifies this as the hardest scheduled chunk. Timebox the first 30 cases to 4 hours Monday afternoon. Use the case-authoring CLI built in Task 22 to streamline.

8. **Mock target stub** is the demo-day insurance policy. If the AgentForge droplet has issues Friday, the demo falls back to a FastAPI stub that simulates `/api/agent/turn`, `/api/agent/upload`, etc. with deterministic-vulnerable responses. Not in the Taskmaster task list explicitly — consider adding as Phase 9 Task 50.5 if not already covered.

## Open questions (still unresolved)

From `presearch.md` and various decisions made during planning:

- Should `Week 3 - ... .pdf` be committed or gitignored?
- Langfuse instance: reuse the existing AgentForge instance, or stand up a separate one? Separate is cleaner audit story; reuse is faster.
- Second droplet: own DigitalOcean account, or share with AgentForge target's account? Sharing simplifies billing; separate strengthens blast-radius isolation.
- Final web UI auth: basic-auth credential, or piggyback on AgentForge's OAuth? Basic-auth is faster.
- GitLab filing identity: file as the user, or as a dedicated bot account? Bot is cleaner audit.
- Judge accuracy threshold for MVP: proposed ≥80% precision, ≥90% recall on known-fail; tune after first eval run.
- OpenRouter pre-provisioning: now, or wait for refusal rate to be an actual blocker?
- Web UI run cadence in Final deployment: once per night, every 4 hours, or on-demand only?

## Relevant memories (already saved)

- `feedback_tdd_primary.md` — TDD default, pytest for Python
- `feedback_git_workflow.md` — branch per task, `Assisted-by: Claude Code` trailer
- `feedback_use_taskmaster_cli.md` — CLI over raw JSON edits
- `feedback_lean_on_prior_art.md` — map to OWASP/MITRE/NIST/HIPAA framework IDs, don't just name-drop (saved this session)
- `project_resume_doc.md` — this NEXT-SESSION.md pattern
- `feedback_no_rm_rf.md` — don't run rm -rf
- `feedback_max_parallel_agents.md` — fan out subagents when work is file-disjoint

## Cost so far

- **Planning session (this one)**: $0 against API budget. All Taskmaster LLM calls routed through Claude Code subscription via `claude-code` provider (~6.2M tokens consumed).
- **Implementation budget remaining**: ~$50 MVP + ~$50 Final per `presearch.md`. Anthropic + OpenAI API keys confirmed available.

## One more thing

The architecture defense gate is **~4h after kickoff**. If kickoff has already passed and the defense is imminent, prioritize: open `DEFENSE.md`, walk the demo plan section, have `DIAGRAMS.md` open in a second window. The 60-second and 2-minute elevator pitches are at the top of `DEFENSE.md`.

If the defense is asynchronous (written submission), the four planning docs (`THREAT_MODEL`, `USERS`, `ARCHITECTURE`, `DEFENSE`) plus the agent interaction diagram in `DIAGRAMS.md` collectively form the submission. They are committed and link to each other.
