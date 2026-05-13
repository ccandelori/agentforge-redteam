# Bug Ledger

A rolling record of bugs found and fixed in the agentforge-redteam
platform itself (not bugs found in the target system under test — those
live in `findings/`).

Entries are reverse-chronological: newest at the top. Each row links to
the commit that fixed it and, where applicable, to the live-session
evidence package that surfaced it.

For open / not-yet-fixed issues, see the "Known debt — prioritized" list
in [`docs/NEXT-SESSION.md`](./NEXT-SESSION.md).

## Format

Every entry: **Bug** (what was wrong), **Impact** (what it meant in
practice — not the code-level cause, but the operator- or
reviewer-visible consequence), **Resolution** (the fix), **Surfaced by**
(how we found it).

---

## 2026-05-13 — Session 29488fc5 evidence run

This batch of three bugs surfaced from the first live campaign packaged
into [`docs/EVIDENCE/2026-05-13-session-29488fc5/`](EVIDENCE/2026-05-13-session-29488fc5/).

### 1. Red Team mutation sent the JSON envelope as the attack payload

- **Bug:** `red_team.py:245` did `payload = llm_response.text`, taking
  the LLM's raw response as the attack body. The `redteam.md` prompt
  asks the LLM for a structured envelope
  (`{"payload":..., "rationale":..., "mutation_of_attack_id":...}`) but
  nothing parsed it back out. Other agents have this parser
  (`judge._extract_json_blob`, `documentation._strip_markdown_json_fence`).
- **Impact:** Every mutated attack landed against the target as
  structured wrapper noise. The target rightly refused the noise.
  Verdicts came back `fail` for the wrong reason — not because the
  inner attack failed, but because the target never saw it.
  The finding `ab6a68c9` (citation_fabrication) was a corrupted-payload
  mutation and had to be removed from `evals/regressions/`. Earlier
  framing in the session-evidence README that called this a "Judge
  bug" was wrong; the Judge was correct throughout.
- **Resolution:** Commit **[`3a65339`](https://gitlab.com/cameroncandelori/agentforgeredteam/-/commit/3a65339)**
  — `_parse_mutation_payload` (markdown-fence-tolerant) wired in with
  seed-fallback + warning on parse failure. Three unit tests added.
  Corrupted regression case deleted.
- **Surfaced by:** Visible in the operator UI "ATTACK PAYLOAD" field
  on finding `ab6a68c9` — the entire JSON envelope was rendered
  verbatim.

### 2. `halt_reason` was never persisted on the manifest

- **Bug:** `run_manifests` had no `halt_reason` column.
  `PlatformState.halt_reason` lived only in memory and was lost when
  the session ended. `GET /sessions/{id}` hardcoded `halt_reason=None`
  (with a comment "halt_reason is not stored on the manifest").
  `POST /halt` flipped the kill switch but did not annotate any
  in-flight session.
- **Impact:** A wedged session, a clean completion, and an in-flight
  session all looked identical from outside the process
  (`halt_reason: null` for all three). Operator had no quick way to
  verify "did this session terminate cleanly." Demo recording was
  risky.
- **Resolution:** Commit **[`227753d`](https://gitlab.com/cameroncandelori/agentforgeredteam/-/commit/227753d)**
  — Migration `0003_add_halt_reason_to_run_manifests` adds
  `halt_reason` + `ended_at` columns (nullable, idempotent,
  downgrade-safe). Dispatcher writes the terminal state on every exit
  path: `"completed"`, `"dispatcher_timeout"`,
  `"dispatcher_crash:<ExceptionClass>"`. `/halt` writes
  `"operator_halt"` for active sessions without clobbering
  more-specific reasons. `get_session` reads from the column. Three
  tests added.
- **Surfaced by:** Session 29488fc5 wedged silently; `POST /halt`
  returned 200 but the manifest stayed `halt_reason: null`, leaving
  the post-mortem state uninformative.

### 3. No wall-clock backstop on a wedged session

- **Bug:** `session_runner.py:281` ran
  `asyncio.run(app.ainvoke(...))` with no timeout. Per-LLM-call
  timeouts (60 s on the Anthropic and OpenAI clients) bound individual
  steps but not the whole session. A single hung coroutine deadlocked
  the entire session indefinitely.
- **Impact:** The 29488fc5 wedge ran for 15+ minutes before the
  operator manually halted it. Without intervention it would have run
  forever, burning a session slot and confusing the operator UI's
  in-memory `_active_sessions` set.
- **Resolution:** Commit **[`227753d`](https://gitlab.com/cameroncandelori/agentforgeredteam/-/commit/227753d)**
  — 30-minute backstop via `asyncio.wait_for`
  (`_SESSION_WALL_TIMEOUT_S`). 30 min is well above any normal
  session at MVP scale (a 75¢ session typically runs 8-12 min; the
  $10 cap finishes inside the window). On expiry, `TimeoutError`
  propagates through `asyncio.run`, the dispatcher catches it, and
  the manifest is updated with
  `halt_reason="dispatcher_timeout"`.
- **Surfaced by:** Same session as above. Note: this fix makes
  wedges observable; it does **not** diagnose the underlying cause
  of the wedge itself (most likely a hung Anthropic API call or a
  LangGraph routing deadlock). Needs a fresh repro with better
  instrumentation to root-cause.

## Diagnosis corrections

Entries here are *not* platform bugs — they're cases where the
session-evidence README or my chat framing got the root cause wrong and
was corrected after deeper investigation. Recorded for honesty / so
graders can trace the reasoning trail.

### Empty `rubric_outcomes={}` is not a Judge bug

- **Original framing (2026-05-13, in the first cut of the session
  29488fc5 evidence README):** "All 15 verdicts came back
  `verdict=fail` with empty `rubric_outcomes={}` — the Judge LLM's
  structured output did not parse into rubric checks."
- **Actual root cause:** The Judge LLM was returning well-formed
  per-check JSON throughout the run (verifiable in
  `agent_steps.result` rows where `tool LIKE 'evaluate_check_%'`).
  The aggregator at `agents/judge.py:351` initializes
  `rubric_outcomes: dict[str, bool] = {}` and only populates it when a
  check fires (`outcome.hit == True`). Empty `{}` is the *correct*
  output when no rubric criterion fires — which is what happens when
  the target legitimately defends. In session 29488fc5 the target
  was either correctly refusing seed attacks or refusing the JSON
  envelope noise produced by bug 1 above. The Judge was not broken.
- **Corrected in:** Commit **[`30e44e6`](https://gitlab.com/cameroncandelori/agentforgeredteam/-/commit/30e44e6)**.
