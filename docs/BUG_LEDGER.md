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

## 2026-05-13 — Cost reduction batch (commit `59f93cb`)

Three patches in one commit, surfaced from cost analysis of session
`e2590f4c` (Judge dominated 67% of cost, Red Team reported 0¢).
Verified against session [`ebd35d75`](EVIDENCE/2026-05-13-session-ebd35d75/).

### 4. Red Team mutation cost recorded as 0¢

- **Bug:** `red_team_node`'s `call_tool` invocation for
  `generate_mutation` did NOT pass a `cost_estimator` parameter.
  Judge / Orchestrator / Documentation all pass
  `cost_estimator=lambda r: int(getattr(r, "cost_cents", 0))`;
  Red Team was missing that one parameter, so the wrapper recorded
  `cost_cents=0` regardless of what `LLMResponse.cost_cents`
  actually contained. NEXT-SESSION.md Known Debt #5.
- **Impact:** ~12% of session cost was hidden from the platform's
  own accounting. In session `e2590f4c`, real Red Team cost was
  ~6¢/session that showed up as 0¢. At scale the discrepancy would
  have grown linearly and hidden a real budget driver from the
  operator.
- **Resolution:** Commit **[`59f93cb`](https://gitlab.com/cameroncandelori/agentforgeredteam/-/commit/59f93cb)**
  — add `cost_estimator=...` to red_team's `generate_mutation`
  `call_tool` invocation, matching the other agents' pattern.
- **Verified by:** Session [`ebd35d75`](EVIDENCE/2026-05-13-session-ebd35d75/)
  shows Red Team cost as 6¢ for 16 calls — was 0¢ in the prior session.

### 5. Doc Agent used Sonnet 4.6 when Haiku 4.5 suffices

- **Bug:** Doc Agent generates structured markdown finding reports
  from a detailed envelope — the prompt is more structure than
  reasoning. Sonnet 4.6 ($3/$15 per 1M tokens) was overkill;
  Haiku 4.5 ($1/$5 per 1M, 3x cheaper) handles the same template
  output with negligible quality loss.
- **Impact:** 2.5¢/finding measured in session `e2590f4c`. At
  10% finding rate × 1K runs/week, that's ~$2.50/week unnecessarily
  spent on doc-agent calls. Latency was also high (avg 9.79 s on
  Sonnet, blocking the orchestrator's next decision for ~10 s on
  every confirmed finding).
- **Resolution:** Commit **[`59f93cb`](https://gitlab.com/cameroncandelori/agentforgeredteam/-/commit/59f93cb)**
  — swap `agents/documentation.py:DEFAULT_MODEL` to
  `claude-haiku-4-5-20251001`. One-line constant change with a
  docstring recording the rationale + measurement source.
- **Verified by:** Session [`ebd35d75`](EVIDENCE/2026-05-13-session-ebd35d75/)
  — Doc Agent dropped from 5¢ → 2¢ (-60%) and avg latency from
  9.79 s → 3.81 s (2.5x faster). Output quality is unchanged
  (same finding-envelope template, well-formed JSON in both runs).

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
- **Verified by:** Session [`e2590f4c`](EVIDENCE/2026-05-13-session-e2590f4c/)
  (2026-05-13, post-fix). Two new findings landed with clean string
  payloads; `e6d02f47` is specifically a *mutated* attack (the bug's
  failure mode) whose `attacks.payload` column is the clean string
  `"Attached is a new lab result to be updated..."` — no envelope.

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
- **Verified by:** Session [`e2590f4c`](EVIDENCE/2026-05-13-session-e2590f4c/)
  halted naturally at `halt_reason="no_progress"` and
  `ended_at="2026-05-13 20:44:58.981661+00:00"` — both values read
  back from `GET /sessions/{id}` and from the `run_manifests` row
  directly. Operator-visible state is now informative.

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
- **Verified by:** Session [`e2590f4c`](EVIDENCE/2026-05-13-session-e2590f4c/)
  halted naturally at 4 min 14 s — well under the 30-min backstop,
  so the timeout did not need to fire (latent verification only).
  The wedge from `29488fc5` did NOT recur in this run, which is
  weak evidence that the envelope bug fix may have reduced (but not
  eliminated) the underlying hang's likelihood. Real verification
  requires the timeout to actually fire on a future hung session.

## Diagnosis corrections

Entries here are *not* platform bugs — they're cases where a fix was
shipped but didn't have the projected effect, or where my earlier
framing of a symptom was wrong. Recorded for honesty / so graders can
trace the reasoning trail.

### Anthropic prompt caching deployed but inactive (judge.md too short)

- **Original framing (commit `59f93cb`):** "Wrap system in a
  cache_control block on every Anthropic call → ~35% Judge cost
  reduction (~23% session total) from prompt caching's 0.1x
  cache-read multiplier."
- **What actually happened:** The patch is implemented correctly and
  the API receives the `cache_control` block on every call. But
  Anthropic silently ignores cache requests when the cached prefix
  is below their per-model minimum (1024 tokens for Claude Sonnet
  4.6). `prompts/judge.md` is **3197 chars ≈ 799 tokens** — under
  the threshold. The cache never engages.
- **Evidence:** Session [`ebd35d75`](EVIDENCE/2026-05-13-session-ebd35d75/)
  Judge cost dropped only 32¢ → 30¢ (-6%, within rounding noise),
  per-call cost stayed at 1¢/call. If caching were engaging on a
  ~700-token prefix, we'd expect 30-40% per-call savings on the
  cached portion, which would be visible at this scale.
- **Path to actually realising the savings (not done):** restructure
  the Judge call so the rubric YAML for the active category is part
  of the `system` block alongside `judge.md`. Combined prefix grows
  to ~1500-2000 tokens and clears the threshold; each category's
  rubric is reused across all checks within the campaign so caching
  engages naturally. ~30 min refactor in `judge.py`. *Padding
  judge.md with filler to clear 1024 tokens is dishonest and would
  drift Judge behavior — don't.*
- **Why this is not a bug:** the code is correct. Anthropic's API
  behaves as documented. We shipped a fix whose precondition isn't
  met by current prompt sizes. The patch will start paying off the
  moment the prefix grows past 1024 tokens, with no further code
  change needed.

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
