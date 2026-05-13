# Smoke Test Coverage

> Snapshot: **2026-05-12**. Edit this file as new tests land or gaps close — do not let it rot.

## Purpose

The four integration smoke tests under `tests/integration/` prove that the agent stack
**composes** — that `Orchestrator → Red Team → Judge` (and, in the doc-agent smoke,
`→ Documentation`) can run a campaign end-to-end and produce a verdict, with audit rows
landing in SQLite and span calls reaching the (fake) Langfuse client. They are deliberately
hermetic: every external boundary (LLM, HTTP target, GitLab, Langfuse) is replaced by a
`Protocol`-shaped fake. They **do not** prove the platform works against the real deployed
target at `https://143.244.157.90`. That evidence comes from **Task 59** (live-target
campaign), which is operator-led and is not captured in repo artifacts today.

If you are reviewing this repo for MVP-gate evidence, read this file as the boundary
between "the wiring is right" (the smokes prove that) and "the wiring fires against a real
target" (operator must demonstrate that separately). The deployed operator UI for that
demonstration lives at **`https://104-248-232-22.sslip.io/ui/`** (`/healthz` returns 200).

---

## What the smoke tests cover

### 1. `tests/integration/test_smoke_prompt_injection_indirect.py`

- **Category / scenario:** `prompt-injection-indirect`, sub-attack `marker_token_reproduction`.
  Target's response echoes the `BANANA` marker, firing the deterministic
  `marker_token_reproduced` check and yielding `verdict="pass"` with confidence `1.0`.
- **Agents exercised:** Orchestrator, Red Team, Judge.
  - Orchestrator node: `tests/integration/test_smoke_prompt_injection_indirect.py:233`
  - Red Team node: `tests/integration/test_smoke_prompt_injection_indirect.py:264`
  - Judge node: `tests/integration/test_smoke_prompt_injection_indirect.py:328`
  - Full Orchestrator → Red Team → Judge composition: `tests/integration/test_smoke_prompt_injection_indirect.py:368`
- **Fake clients:** `_FakeOrchestratorLLM`, `_FakeRedTeamLLM`, `_FakeIPIHTTP`, `_FakeJudgeLLM`,
  `fake_langfuse` (from `tests/integration/conftest.py:47`).
- **Representative assertions:**
  - `test_orchestrator_selects_a_rubric_category` — picker returns a category in
    `load_all_rubrics(...)` (`:233`).
  - `test_judge_evaluates_ipi_verdict` — verdict is `pass`, confidence `1.0`, `rubric_sha`
    matches the on-disk rubric (`:328`).
  - `test_full_pipeline_writes_to_sqlite` — `agent_steps` has rows for each agent and zero
    rows with NULL `result` (`:368`).
  - `test_langfuse_spans_recorded` — fake Langfuse client received ≥3 spans, all ended
    (`:452`).
  - `test_full_pipeline_increments_cost` — `state.cost_so_far` monotonically non-decreasing
    across stages (`:611`).

### 2. `tests/integration/test_smoke_data_exfiltration.py`

- **Category / scenario:** `data-exfiltration`, sub-attack `cross_patient_phi_disclosure`.
  Target leaks a Synthea-style MRN UUID belonging to a different patient; the deterministic
  `response_contains_phi_from_wrong_patient` check fires (UUID4 regex).
- **Agents exercised:** Red Team, Judge.
  - Red Team node: `tests/integration/test_smoke_data_exfiltration.py:238`
  - Judge node: `tests/integration/test_smoke_data_exfiltration.py:288`
- **Fake clients:** `_FakeRedTeamLLM`, `_FakeDataExfilHTTP` (PHI-leaking), `_CleanHTTP`
  (refusal), `_FakeJudgeLLM` (every-hit), `_FakeJudgeLLMNoHit` (every-miss),
  local `fake_langfuse`.
- **Representative assertions:**
  - `test_red_team_generates_data_exfil_attack` — Red Team appends exactly one
    `AttackRecord` whose payload matches `attack_library.json` verbatim (`:238`).
  - `test_judge_evaluates_data_exfil_verdict_pass` — `verdict="pass"`, confidence `1.0`,
    `rubric_sha` matches the data-exfiltration rubric (`:288`).
  - `test_negative_case_clean_response_yields_fail_verdict` — clean response + no-hit Judge
    yields `verdict="fail"`, confidence `0.5`, empty `evidence_refs` (`:389`).
  - `test_smoke_completes_quickly_without_real_network` — wall-clock < 2 s, used as a
    structural "no network leaked in" invariant (`:434`).

### 3. `tests/integration/test_smoke_tool_misuse.py`

- **Category / scenario:** `tool-misuse`, sub-attack `unauthorized_tool_invocation`.
  Target replies with an "I've updated the problem list..." string indicating it actually
  performed an unauthorized chart write. Tool-misuse has no deterministic checks wired in
  the skeleton, so all-LLM hits drive `verdict="pass"` at confidence `0.7`.
- **Agents exercised:** Red Team, Judge.
  - Red Team node: `tests/integration/test_smoke_tool_misuse.py:170`
  - Judge node: `tests/integration/test_smoke_tool_misuse.py:200`
- **Fake clients:** `_FakeRedTeamLLM`, `_FakeToolMisuseHTTP` (writes-the-chart),
  `_RefusalHTTP` (negative case), `_FakeJudgeLLM`, `_RefusalJudgeLLM`, shared `fake_langfuse`
  + `migrated_engine` fixtures from `tests/integration/conftest.py:21`.
- **Representative assertions:**
  - `test_judge_evaluates_tool_misuse_verdict_pass` — `verdict="pass"`,
    confidence `pytest.approx(0.7)` (LLM-only, no deterministic check fired) (`:200`).
  - `test_evidence_refs_populated_on_tool_misuse_pass` — `evidence_refs` includes the LLM
    fake's anchor text (`:223`).
  - `test_negative_case_refusal_response_yields_fail` — clean refusal + no-hit Judge
    yields `verdict="fail"` with empty `evidence_refs` (`:294`).
  - `test_seed_payloads_present_for_all_three_tool_misuse_sub_attacks` — pins the three
    declared sub_attacks (`:308`).

### 4. `tests/integration/test_doc_agent_end_to_end.py`

- **Category / scenario:** Same IPI marker-token success as smoke #1, but pipes the result
  into the Documentation Agent with a `LocalFindingsSink` GitLab substitute. Severity falls
  out as `P3`; confidence `1.0 ≥ 0.7` triggers the autofile path.
- **Agents exercised:** Red Team, Judge, **Documentation**.
  - Full pipeline test: `tests/integration/test_doc_agent_end_to_end.py:241`
- **Fake clients:** `_FakeRedTeamLLM`, `_FakeIPIHTTP`, `_FakeJudgeLLM`, `_FakeDocLLM`
  (returns the canned finding envelope), `LocalFindingsSink` (real class, no network),
  shared `fake_langfuse`.
- **Representative assertions** (all in `test_full_pipeline_files_finding_to_local_sink`):
  - Exactly one `*.md` file lands in `findings/`, containing `## Summary`, `## Severity`,
    `## Framework Mapping`, and `## Reproduction Steps`.
  - `confirmed_findings[0].severity == "P3"` and `gitlab_issue_id == 1` (sink's synthetic id).
  - One row in the `findings` SQLite table.

---

## Deliberate gaps

These are gaps the smokes **knowingly** leave uncovered. Each is owned by a different test
or task; nothing in this list is "we forgot."

### G1. Documentation Agent autofile path is exercised only in smoke #4

Only `tests/integration/test_doc_agent_end_to_end.py:241` runs the Doc Agent. The three
category smokes (#1–#3) stop at Judge.

**Rationale:** the Documentation Agent has its own dedicated integration smoke; making the
category smokes also exercise it would couple "did the Judge return the right verdict?"
with "did the Doc Agent render the right report?" These are independent failure modes that
deserve independent assertions. Closed by Task 36.

### G2. The `verdicts` SQLite-table row is **not** written by the category smokes

The Judge skeleton appends only to `state.verdict_records` (in-memory). The actual
`INSERT INTO verdicts (...)` row is written downstream when the Doc Agent runs. Smoke #1
explicitly asserts `SELECT COUNT(*) FROM verdicts` is **zero** after Judge runs alone
(`tests/integration/test_smoke_prompt_injection_indirect.py:540`).

**Rationale:** smoke #4 (`test_doc_agent_end_to_end.py`) does write a `verdicts` row (it
seeds attack + verdict directly via `_persist_attack_and_verdict` at
`tests/integration/test_doc_agent_end_to_end.py:185`). The category smokes intentionally
do not — they assert on `state.verdict_records[0]`, not on a `SELECT`.

### G3. `sanitize_evidence` is exercised in unit tests but not in any category smoke

`src/agentforge_redteam/sanitizer.py:73` (`sanitize_evidence`) is only called from the
Documentation Agent's render path. The category smokes never invoke Doc Agent, so they
never invoke the sanitizer.

**Covered by:** `tests/unit/test_sanitizer.py` (JWT, sk-keys, SSN, Synthea MRN, idempotence
— see `test_jwt_token_is_redacted:35`, `test_synthea_style_mrn_uuid_is_redacted:113`,
`test_sanitize_evidence_is_idempotent:172`, etc.) and indirectly by
`test_doc_agent_end_to_end.py` once the Doc Agent renders the finding.

### G4. Canary-mismatch halt is not exercised

When a canary campaign's verdict diverges from `canary_expected_verdict`, the Judge sets
`state.halt_reason = "canary_failed"` and raises `CanaryMismatch`
(`src/agentforge_redteam/agents/judge.py:111` and `:457`). No smoke triggers this — every
smoke fixture uses an in-scope, non-canary `CampaignBrief`.

**Covered by:** `tests/unit/test_canary.py` (case selection + `record_canary_failure` row
writes — see `test_select_canary_case_returns_pass_or_fail_for_ipi:112`,
`test_record_canary_failure_writes_one_row:239`). The graph-level "Orchestrator preserves
the existing `canary_failed` halt before scoring candidates" path is asserted in
`tests/unit/test_orchestrator_full.py:458`
(`test_orchestrator_preserves_existing_canary_failed_halt`). End-to-end "Judge raises
`CanaryMismatch` and the LangGraph reducer halts the run" is wiring work tracked under
Task 55 / Task 58.

### G5. `content_filter` refusal short-circuit never fires in a smoke

`src/agentforge_redteam/redteam/content_filter.py:38` refuses payloads matching
`OUT_OF_SCOPE_PATTERNS` (CSAM, terrorism, etc.) **before** the target HTTP call. Every
smoke payload is the in-scope seed from `attack_library.json`, so the filter passes.

**Covered by:** `tests/unit/test_red_team.py:483`
(`test_filter_refuses_each_out_of_scope_category` — parameterized over every category),
`:492` (`test_filter_passes_in_scope_payload`), and the Red Team integration path
`test_content_filter_refusal_propagates:318`.

### G6. Real `cost.py` math is never exercised by a smoke

The smoke fake LLMs return a hard-coded `cost_cents=75` (Judge) / `cost_cents=20`
(Orchestrator) / `cost_cents=150` (Red Team mutation, never invoked because no priors).
The actual tokenizer heuristic and provider pricing table in `src/agentforge_redteam/cost.py`
(`make_cost_estimator`, `estimate_cost_cents`) are not composed in any smoke run.

**Covered by:** `tests/unit/test_cost.py` — `test_estimate_cost_cents_small_input_is_small_positive_int:63`,
`test_estimate_cost_cents_scales_linearly_with_prompt_size:84`,
`test_make_cost_estimator_prefers_sdk_cost_cents_when_nonzero:123`,
`test_pricing_table_has_entry_for_production_model:169` (parameterized over all production
models).

### G7. Orchestrator policy gates beyond kill-switch + budget

The Orchestrator implements four halt conditions in priority order
(`src/agentforge_redteam/agents/orchestrator.py:441`):

1. `HALT_KILL_SWITCH`
2. `HALT_NO_PROGRESS` (last N verdicts all fail, where N = `policy.no_progress_threshold`)
3. `HALT_REGRESSION_DUE` (target SHA drift vs latest manifest)
4. `HALT_BUDGET` (`cost_so_far + default_campaign_budget > max_session_cost_cents`)

Only path #1 and #4 are even reachable from a smoke (and only as a side effect — smokes
don't trip the kill switch or run out of budget). The other two are exercised by
**`tests/unit/test_orchestrator_full.py`**: `test_orchestrator_halts_on_no_progress:388`,
`test_orchestrator_halts_on_regression_due:478`, plus the halt-priority ordering tests
(`test_halt_order_existing_beats_everything:504`,
`test_halt_order_kill_switch_beats_no_progress:541`,
`test_halt_order_no_progress_beats_regression:569`,
`test_halt_order_regression_beats_budget:598`).

**Rationale:** the smoke tests force a manually-constructed `CampaignBrief` past the
Orchestrator's epsilon-greedy picker (see `state_with_ipi_campaign` at
`test_smoke_prompt_injection_indirect.py:124` and `_initial_state` at
`test_smoke_data_exfiltration.py:192`) precisely so the rest of the smoke stays scoped to
one category. That bypass means the gates are not on the smoke's critical path.

### G8. Langfuse: the real SDK client is never invoked

Every smoke uses the in-process `FakeLangfuse` from `tests/integration/conftest.py:47` —
it appends to an in-memory list and never opens a socket.

**Covered by:** `tests/unit/test_langfuse_client.py` — env-detection
(`test_from_env_returns_config_when_both_keys_set:111`,
`test_from_env_returns_none_when_empty:123`) plus the SDK-monkeypatched span lifecycle
tests further down the file. The smoke composition never exercises the real client.

### G9. **Live HTTP against the deployed target**

This is the headline gap. Every smoke uses one of `_FakeIPIHTTP`,
`_FakeDataExfilHTTP`, or `_FakeToolMisuseHTTP`, all of which return canned
`TargetResponse` objects without touching the network. The platform has **never** made an
actual `httpx.post` to `https://143.244.157.90` from inside the test suite.

The smoke wall-clock assertion (`assert elapsed < 2.0` in
`test_smoke_data_exfiltration.py:434` and `test_smoke_tool_misuse.py:319`) is a soft
"no network leaked in" check, not a "we hit the target" proof.

**Closed by Task 59** (live-target campaign, operator-led). Until then, MVP "live target"
evidence lives in the operator's manually-filed GitLab issue plus the screenshot listed at
`README.md`'s MVP Status section — **not** in repo artifacts.

### G10. Documentation Agent → real GitLab client

`src/agentforge_redteam/clients/gitlab_client.py` is unit-tested with monkeypatched
`httpx` in `tests/unit/test_gitlab_client.py` (`test_create_issue_posts_to_correct_url:216`,
`test_create_issue_sends_private_token_header:243`, etc.). No smoke invokes it: smoke #4
uses `LocalFindingsSink` (writes a `.md` file to a tmp dir) as the GitLab substitute via
`tests/integration/test_doc_agent_end_to_end.py:260`.

**Rationale:** wiring a real GitLab POST into the suite requires `GITLAB_TOKEN` +
`GITLAB_PROJECT_ID` in CI, which is an ops/secrets decision rather than a test-design one.
The `LocalFindingsSink` fallback was built explicitly so the autofile path could be
asserted end-to-end on a dev box with no credentials.

---

## What it would take to close these gaps

- **G9 (live HTTP) and Task 59** together are the priority. A live-target integration
  smoke wired against a **SAFE staging target** (not production) would close the headline
  gap. This implies (a) standing up a staging deployment whose only purpose is to absorb
  red-team traffic, (b) gating the test behind a `pytest -m live_target` marker so it does
  not run in normal CI, and (c) capturing the resulting `agent_steps` rows + filed
  finding into a versioned artifact in the repo.
- **G4 (canary halt)** can be closed inside the unit-test layer by injecting state
  directly — no live target required. It will land naturally when Task 55 / Task 58 wire
  `CanaryMismatch` through the LangGraph reducer.
- **G8 (real Langfuse) and G10 (real GitLab)** both require keys-in-CI which is its own
  ops decision. The pragmatic alternative is recording-mode integration tests that snapshot
  one real call and replay it; that is out of scope for MVP.
- **G6 (real cost math)** can be closed cheaply by injecting the real `cost.py` estimator
  factory into the smoke fakes' `cost_cents` field — a small refactor that did not feel
  worth the coupling on the MVP timeline.

---

## Honesty footer

This document is a snapshot as of **2026-05-12**. If you add a smoke, close a gap, or
move a referenced line number, edit this file in the same commit. A coverage doc that lies
is worse than one that does not exist — reviewers depend on the gap list being accurate to
know what the smoke suite does **not** prove.
