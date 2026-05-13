"""Orchestrator agent skeleton — pick the next campaign or halt.

This is the Task 27 *skeleton*: one invocation produces ONE
:class:`CampaignBrief`, or sets ``state.halt_reason`` and returns the
state untouched otherwise. The full Orchestrator (Task 37) will manage
drift-aware policy and rebalance after canary failures; this skeleton
exercises the full operational stack:

1. **Kill switch.** Consulted BEFORE any other side effect. A tripped
   switch halts the orchestrator immediately with ``halt_reason =
   "kill_switch_tripped"``; no LLM call, no audit row, no campaign.
2. **Budget gate.** ``cost_so_far + default_campaign_budget`` must fit
   under ``max_session_cost_cents``. Over-budget halts with
   ``"budget_exhausted"``.
3. **Candidates.** Enumerated from :func:`load_all_rubrics` —
   ``(category, sub_attack)`` tuples. If the rubric set is empty, halt
   with ``"no_candidates"``.
4. **Coverage join.** Read every matching row from ``coverage_matrix``
   in one SELECT. Missing rows are treated as a default zero row.
5. **Score.** ``raw_score = max(1.0, severity_score) * (1 +
   coverage_gap)``, where ``coverage_gap = max(0, target_runs -
   runs_last_7d)`` and ``severity_score`` is the dot product of the
   policy's ``severity_weights`` with ``findings_by_severity``.
6. **Select.** With probability ``epsilon`` (drawn from the injected
   :class:`random.Random`) pick uniformly at random; otherwise pick the
   argmax. Tie-break by (lower ``coverage_score``, then alphabetical
   ``sub_attack``) for determinism.
7. **Canary.** If ``campaigns_run > 0`` and ``campaigns_run %
   canary_every_n_campaigns == 0``, mark this campaign as a canary with
   ``canary_expected_verdict = "fail"``.
8. **Rationale.** A short prose rationale is requested from the
   injected LLM via :func:`call_tool` so the ``agent_steps`` table grows
   one row per non-halted invocation. The user prompt is a JSON
   *summary*, NOT raw SQL: we surface the selected candidate and a
   single-row coverage snapshot, nothing else.
9. **Return.** A fresh :class:`PlatformState` with ``current_campaign``
   set, ``campaigns_run += 1``, ``cost_so_far += llm_cost_dollars``.

Design constraints (load-bearing — keep stable):

* **No top-level Anthropic / openai import.** The LLM client is
  injected as a :class:`Protocol`-typed parameter so tests can substitute
  a fake without monkeypatching.
* **All randomness from the injected ``rng``.** This module never
  calls :func:`random.random` or :func:`random.choice` directly; every
  draw flows through the ``rng`` argument so tests are deterministic
  under ``random.Random(42)``.
* **All side effects through :func:`call_tool`.** The rationale LLM
  hop produces exactly one ``agent_steps`` row, keyed by
  ``agent="orchestrator"``. Halts produce zero rows by contract — a
  halted invocation must look "didn't happen" to the audit log so the
  kill switch is unambiguously the most recent operator action.
"""

from __future__ import annotations

import json
import random
from collections.abc import Iterable
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, Final, Protocol

from sqlalchemy import text
from sqlalchemy.engine import Engine

from agentforge_redteam.kill_switch import is_kill_switch_enabled
from agentforge_redteam.orchestrator_policy import OrchestratorPolicy
from agentforge_redteam.prompts import PROMPTS_DIR, load_prompt
from agentforge_redteam.rubrics.loader import DEFAULT_RUBRICS_DIR, load_all_rubrics
from agentforge_redteam.state import CampaignBrief, PlatformState
from agentforge_redteam.tools.wrapper import call_tool

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MODEL: Final[str] = "claude-haiku-4-5-20251001"
_AGENT_NAME: Final[str] = "orchestrator"

# Halt reason vocabulary — kept narrow so downstream dashboards can switch
# on the exact strings rather than parsing free text.
HALT_KILL_SWITCH: Final[str] = "kill_switch_tripped"
HALT_BUDGET: Final[str] = "budget_exhausted"

# Per-finding doc-agent cost reserve held back from the budget gate so
# a finding landing in the last campaign before halt doesn't push total
# spend over the cap. Calibrated from session e2590f4c measured
# 2.5¢/finding (Sonnet) and ebd35d75 measured 0.5¢/finding (Haiku);
# 5¢ is the conservative side and is still under 7% of a typical
# 75¢ session cap.
_DOC_AGENT_RESERVE_CENTS: Final[int] = 5
HALT_NO_CANDIDATES: Final[str] = "no_candidates"
# Task 37 additions. ``HALT_CANARY_FAILED`` is the value the Judge agent
# stamps on ``state.halt_reason`` when a canary's verdict diverges from
# its declared expectation — the orchestrator must honor it without
# overwriting (defense-in-depth even if the graph routes around us).
HALT_NO_PROGRESS: Final[str] = "no_progress"
HALT_CANARY_FAILED: Final[str] = "canary_failed"
HALT_REGRESSION_DUE: Final[str] = "regression_due"

# Canary expected verdict for the skeleton. Real canaries (Task 41) will
# carry their own ground-truth verdicts; until then, every canary we
# inject is a "should-fail" probe.
_CANARY_EXPECTED_VERDICT: Final[str] = "fail"


# ---------------------------------------------------------------------------
# Injected-client protocol
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LLMResponse:
    """Minimum surface area the Orchestrator needs from an LLM client.

    ``text`` is a free-prose rationale — we do NOT validate its content.
    The selection decision was already made by the time we asked; the
    rationale is for the audit log, not for the routing.
    """

    text: str
    cost_cents: int


class LLMClientLike(Protocol):
    """Subset of an Anthropic-shaped client. Tests inject a fake."""

    async def complete(self, *, system: str, user: str, model: str) -> LLMResponse: ...


# ---------------------------------------------------------------------------
# Scoring value object
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CandidateScore:
    """One sub_attack's score in the selection pool.

    ``coverage_gap`` is the (target - runs_last_7d) clamped to >= 0.
    ``severity_score`` is the dot product of the policy's severity
    weights with the historical ``findings_by_severity`` counts.
    ``raw_score`` is the value the epsilon-greedy picker maximises.
    ``coverage_score`` is the raw coverage_matrix column, surfaced here
    only for deterministic tie-breaking.
    """

    category: str
    sub_attack: str
    coverage_gap: int
    severity_score: float
    raw_score: float
    coverage_score: float = 0.0


# ---------------------------------------------------------------------------
# Pure scoring + selection (no DB, no LLM — easily unit tested)
# ---------------------------------------------------------------------------


def _severity_score(
    findings_by_severity: dict[str, Any] | None,
    severity_weights: dict[str, float],
) -> float:
    """Dot product of severity weights with the historical findings vector.

    Missing severities (e.g. the sub_attack has never produced a P0)
    contribute 0. Unknown keys in ``findings_by_severity`` (a future
    severity tier we haven't taught the policy yet) are silently
    skipped — the policy is the canonical list, not the column.
    """
    if not findings_by_severity:
        return 0.0
    total = 0.0
    for severity, weight in severity_weights.items():
        count = findings_by_severity.get(severity, 0)
        # JSON decodes integer counts as ``int``; defensive cast keeps us
        # honest if a future column stored them as strings.
        try:
            n = int(count)
        except (TypeError, ValueError):
            n = 0
        total += weight * n
    return total


def score_candidates(
    candidates: Iterable[tuple[str, str]],
    coverage_rows: dict[tuple[str, str], dict[str, Any]],
    severity_weights: dict[str, float],
    target_runs: int,
    target_runs_per_category: dict[str, int] | None = None,
) -> list[CandidateScore]:
    """Score every candidate; the output order follows the input iteration.

    Missing coverage rows are treated as a default zero row. The
    function is pure: no DB, no LLM, no rng. Callers feed it the inputs
    they already have so it can be exercised under tight unit tests.

    ``target_runs_per_category`` is the optional per-category override
    introduced in Task 37: when the candidate's ``category`` appears in the
    map, that value is used as the target instead of the flat ``target_runs``
    default. Categories not in the map fall back to ``target_runs``.
    """
    overrides = target_runs_per_category or {}
    out: list[CandidateScore] = []
    for category, sub_attack in candidates:
        row = coverage_rows.get((category, sub_attack), {})
        runs_last_7d = int(row.get("runs_last_7d", 0))
        effective_target = overrides.get(category, target_runs)
        coverage_gap = max(0, effective_target - runs_last_7d)
        sev = _severity_score(row.get("findings_by_severity"), severity_weights)
        # max(1.0, sev) is the "floor": even a never-found sub_attack
        # still gets one unit of severity weight so the coverage-gap
        # factor alone can drive it up the queue. (1 + coverage_gap) is
        # the "+1 floor" on the multiplier so a zero gap doesn't zero
        # the score for high-severity history.
        raw = max(1.0, sev) * (1 + coverage_gap)
        out.append(
            CandidateScore(
                category=category,
                sub_attack=sub_attack,
                coverage_gap=coverage_gap,
                severity_score=sev,
                raw_score=raw,
                coverage_score=float(row.get("coverage_score", 0.0)),
            )
        )
    return out


def select_candidate(
    scored: list[CandidateScore], *, epsilon: float, rng: random.Random
) -> CandidateScore:
    """Epsilon-greedy pick from ``scored``.

    With probability ``epsilon`` we pick uniformly at random from the
    full list — this is the explorer that keeps coverage from collapsing
    onto the same handful of sub_attacks. Otherwise we pick the
    argmax. Ties on ``raw_score`` are broken deterministically by
    (lower ``coverage_score``, then alphabetical ``sub_attack``) so
    repeated runs with the same seeded rng land on the same sub_attack.

    Raises :class:`ValueError` on an empty list — callers must guard
    against this (the orchestrator node treats it as the
    ``no_candidates`` halt).
    """
    if not scored:
        raise ValueError("select_candidate called with empty scored list")

    # ``rng.random()`` is the only stochastic draw in this module. We
    # use a single threshold compare so the same seed deterministically
    # picks the same branch.
    if rng.random() < epsilon:
        return rng.choice(scored)

    # Argmax with deterministic tie-break. We sort the whole list
    # because the list is small (sub_attack count in the low tens) and
    # the explicit sort key makes the tie-break rule readable.
    def _sort_key(c: CandidateScore) -> tuple[float, float, str]:
        # Negate raw_score so a descending sort places the max first.
        # Then ascend on coverage_score (lower coverage first), then
        # alphabetical sub_attack.
        return (-c.raw_score, c.coverage_score, c.sub_attack)

    return sorted(scored, key=_sort_key)[0]


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------


def _read_coverage_rows(
    engine: Engine,
    candidates: Iterable[tuple[str, str]],
) -> dict[tuple[str, str], dict[str, Any]]:
    """Read every matching ``coverage_matrix`` row in ONE round trip.

    SQLite has no ``IN ((a, b), (c, d))`` tuple support, so we use a
    composite ``IN``-of-strings via ``category || '::' || sub_attack``.
    The candidate set is small (low tens), so the materialisation cost
    is negligible compared to the round-trip we save.

    The ``findings_by_severity`` column is JSON; SQLAlchemy's
    ``sa.JSON`` type handles the decode for us, so the value comes back
    as a Python dict (or ``None`` if the row was inserted with the
    ``'{}'`` default and the dialect coerced it that way — we normalise
    both cases here).
    """
    candidates_list = list(candidates)
    if not candidates_list:
        return {}

    keys = [f"{cat}::{sub}" for cat, sub in candidates_list]
    placeholders = ", ".join(f":k{i}" for i in range(len(keys)))
    params = {f"k{i}": key for i, key in enumerate(keys)}

    sql = (
        "SELECT category, sub_attack, runs_last_7d, runs_lifetime, "
        "findings_by_severity, last_run_at, avg_cost_cents, coverage_score "
        "FROM coverage_matrix "
        f"WHERE (category || '::' || sub_attack) IN ({placeholders})"
    )

    out: dict[tuple[str, str], dict[str, Any]] = {}
    with engine.connect() as conn:
        rows = conn.execute(text(sql), params).mappings().all()
    for row in rows:
        fbs = row["findings_by_severity"]
        # Defensive: SQLAlchemy sa.JSON returns a dict already; a
        # raw-text fallback would return a JSON string we need to parse.
        if isinstance(fbs, str):
            try:
                fbs = json.loads(fbs)
            except json.JSONDecodeError:
                fbs = {}
        out[(row["category"], row["sub_attack"])] = {
            "runs_last_7d": row["runs_last_7d"],
            "runs_lifetime": row["runs_lifetime"],
            "findings_by_severity": fbs or {},
            "last_run_at": row["last_run_at"],
            "avg_cost_cents": row["avg_cost_cents"],
            "coverage_score": row["coverage_score"],
        }
    return out


# ---------------------------------------------------------------------------
# Halt-condition helpers
# ---------------------------------------------------------------------------


def _recent_verdicts_all_fail(state: PlatformState, *, n: int) -> bool:
    """Return True if the most recent ``n`` verdicts on the state are all 'fail'.

    Looks at ``state.verdict_records`` in reverse chronological order. If
    the state has fewer than ``n`` records, returns False — we don't trip
    no-progress until we have enough evidence to call it.
    """
    if n <= 0:
        return False
    records = state.verdict_records
    if len(records) < n:
        return False
    window = records[-n:]
    return all(r.verdict == "fail" for r in window)


def detect_regression_due(engine: Engine, *, current_target_sha: str | None) -> bool:
    """Return True if ``run_manifests`` has a session with a different ``target_sha``.

    The orchestrator uses this to short-circuit into a regression flow when
    the target build has changed since the last recorded session. The
    semantics are deliberately one-sided:

    * If ``current_target_sha`` is ``None``, we have no anchor to compare
      against, so we cannot conclude a regression is due — returns False.
    * If ``run_manifests`` is empty, there is no prior session to compare
      against — returns False.
    * Otherwise, return True iff *any* manifest row carries a ``target_sha``
      that differs from ``current_target_sha``.

    The check is read-only — it never mutates ``run_manifests``.
    """
    if not current_target_sha:
        return False
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT target_sha FROM run_manifests")).fetchall()
    if not rows:
        return False
    return any(row[0] != current_target_sha for row in rows)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def _halt(state: PlatformState, reason: str) -> PlatformState:
    """Return a fresh state with ``halt_reason`` set; ``current_campaign``
    left untouched per the contract (a halt is not a campaign)."""
    return state.model_copy(update={"halt_reason": reason})


def _build_rationale_user_prompt(
    pick: CandidateScore,
    coverage_row: dict[str, Any],
    *,
    is_canary: bool,
    budget_cents: int,
) -> str:
    """Assemble the user prompt for the rationale LLM call.

    By contract this prompt carries ONLY aggregated JSON about the
    selected candidate. It never embeds raw SQL, never names other
    sub_attacks, and never quotes attack payloads. The Orchestrator's
    decision is already made — the LLM is a pure narrator here. Keeping
    information exposure minimal limits the blast radius if the
    rationale endpoint were ever logged in a less-protected sink.
    """
    payload = {
        "selected": {
            "category": pick.category,
            "sub_attack": pick.sub_attack,
            "coverage_gap": pick.coverage_gap,
            "severity_score": pick.severity_score,
            "raw_score": pick.raw_score,
        },
        "coverage_snapshot": {
            "runs_last_7d": coverage_row.get("runs_last_7d", 0),
            "runs_lifetime": coverage_row.get("runs_lifetime", 0),
            "findings_by_severity": coverage_row.get("findings_by_severity", {}),
            "coverage_score": coverage_row.get("coverage_score", 0.0),
        },
        "is_canary": is_canary,
        "budget_cents": budget_cents,
    }
    return json.dumps(payload, default=str, sort_keys=True)


async def orchestrator_node(
    state: PlatformState,
    *,
    engine: Engine,
    llm: LLMClientLike,
    policy: OrchestratorPolicy,
    rng: random.Random,
    model: str = DEFAULT_MODEL,
    langfuse: Any | None = None,
    rubrics_dir: Path | str = DEFAULT_RUBRICS_DIR,
    prompts_dir: Path = PROMPTS_DIR,
    current_target_sha: str | None = None,
) -> PlatformState:
    """Pick the next campaign, or halt.

    Contract (full detail in the module docstring):

    The halt rulebook (Task 37). Evaluated top-to-bottom; the first match
    wins. A halt sets ``halt_reason`` and returns WITHOUT setting
    ``current_campaign``; no LLM call, no audit row.

    0. ``state.halt_reason`` already set on entry -> PRESERVE and return
       unchanged. Defense-in-depth: if the Judge stamped
       ``canary_failed`` (or any other halt) on the state, the orchestrator
       does not overwrite it.
    1. Kill switch enabled -> ``HALT_KILL_SWITCH``.
    2. The last ``policy.no_progress_threshold`` verdicts are all 'fail'
       -> ``HALT_NO_PROGRESS``. Catches saturated categories before we
       burn more budget grinding on them.
    3. ``current_target_sha`` is provided AND ``run_manifests`` carries a
       different ``target_sha`` -> ``HALT_REGRESSION_DUE``. The graph layer
       routes to a regression run, then resumes; the orchestrator just
       detects and halts.
    4. ``cost_so_far_cents + default_campaign_budget_cents >
       max_session_cost_cents`` -> ``HALT_BUDGET``.
    5. No candidates surface (empty rubric set) -> ``HALT_NO_CANDIDATES``.

    Otherwise:

    1. Enumerate candidates from :func:`load_all_rubrics`.
    2. Read ``coverage_matrix`` rows for the candidate set.
    3. Score (per-category targets honored when present); epsilon-greedy pick.
    4. Canary check (every Nth campaign).
    5. Build :class:`CampaignBrief` with
       ``budget_cents = policy.default_campaign_budget_cents``.
    6. Audit-wrapped LLM rationale call.
    7. Update state: ``current_campaign``, ``campaigns_run += 1``,
       ``cost_so_far += llm_cost_dollars``.
    """
    # ---- 0. Existing halt_reason wins (canary_failed et al.) -------------
    # If a prior node already halted, the orchestrator MUST NOT overwrite
    # the reason. The graph normally routes around us in this state, but
    # this guard is defense-in-depth.
    if state.halt_reason is not None:
        return state

    # ---- 1. Kill switch (fail closed) ------------------------------------
    if is_kill_switch_enabled(engine):
        return _halt(state, HALT_KILL_SWITCH)

    # ---- 2. No-progress halt --------------------------------------------
    # Walk back through the verdict history; if the most recent N are all
    # 'fail', halt. Cheap in-memory check on a small list.
    if _recent_verdicts_all_fail(state, n=policy.no_progress_threshold):
        return _halt(state, HALT_NO_PROGRESS)

    # ---- 3. Regression-due halt -----------------------------------------
    # A new target_sha (relative to any manifest on file) means a build has
    # shipped under us. Halt so the graph can route into a regression run.
    if detect_regression_due(engine, current_target_sha=current_target_sha):
        return _halt(state, HALT_REGRESSION_DUE)

    # ---- 4. Budget gate --------------------------------------------------
    # ``cost_so_far`` is stored in dollars (Decimal). We compare in cents
    # against the policy's integer cap so the per-cent rounding stays
    # honest.
    #
    # Reserve includes:
    #   default_campaign_budget_cents: full budget for the next campaign
    #     (red_team mutation + target POST + 3-5 judge checks).
    #   _DOC_AGENT_RESERVE_CENTS: a follow-on doc-agent call that fires
    #     AFTER the orchestrator returns if the next campaign produces a
    #     pass verdict. Without this, sessions can land 5-10¢ over the
    #     cap when a finding lands in the last campaign before halt.
    #     See BUG_LEDGER.md ("Cost cap leakage") and live overshoot
    #     observed in session f044fd18 ($0.75 cap → $1.16 actual).
    cost_so_far_cents = int(state.cost_so_far * Decimal(100))
    projected = cost_so_far_cents + policy.default_campaign_budget_cents + _DOC_AGENT_RESERVE_CENTS
    if projected > policy.max_session_cost_cents:
        return _halt(state, HALT_BUDGET)

    # ---- 5. Enumerate candidates ----------------------------------------
    try:
        rubrics = load_all_rubrics(rubrics_dir)
    except FileNotFoundError:
        rubrics = {}

    candidates: list[tuple[str, str]] = []
    for category in sorted(rubrics.keys()):
        for sub_attack in rubrics[category].sub_attacks:
            candidates.append((category, sub_attack))

    if not candidates:
        return _halt(state, HALT_NO_CANDIDATES)

    # ---- 6. Coverage join + score ---------------------------------------
    coverage_rows = _read_coverage_rows(engine, candidates)
    scored = score_candidates(
        candidates,
        coverage_rows,
        policy.severity_weights,
        policy.target_runs_per_sub_attack_per_week,
        target_runs_per_category=policy.target_runs_per_category,
    )

    # ---- 5. Epsilon-greedy pick -----------------------------------------
    pick = select_candidate(scored, epsilon=policy.epsilon, rng=rng)

    # ---- 6. Canary check ------------------------------------------------
    is_canary = (
        state.campaigns_run > 0 and state.campaigns_run % policy.canary_every_n_campaigns == 0
    )
    canary_expected: str | None = _CANARY_EXPECTED_VERDICT if is_canary else None

    # ---- 7. Build the brief ---------------------------------------------
    # CampaignBrief enforces the canary invariant in its validator, so a
    # bug in our canary logic here would raise at construction time.
    brief = CampaignBrief(
        category=pick.category,
        sub_attack=pick.sub_attack,
        budget_cents=policy.default_campaign_budget_cents,
        is_canary=is_canary,
        canary_expected_verdict=canary_expected,
    )

    # ---- 8. Audit-wrapped rationale LLM call ----------------------------
    loaded = load_prompt("orchestrator", prompts_dir)
    coverage_row = coverage_rows.get((pick.category, pick.sub_attack), {})
    user_prompt = _build_rationale_user_prompt(
        pick,
        coverage_row,
        is_canary=is_canary,
        budget_cents=brief.budget_cents,
    )

    llm_call = await call_tool(
        agent=_AGENT_NAME,
        tool_name="campaign_rationale",
        tool=llm.complete,
        args={"system": loaded.text, "user": user_prompt, "model": model},
        session_id=state.session_id,
        engine=engine,
        langfuse=langfuse,
        cost_estimator=lambda response: int(getattr(response, "cost_cents", 0)),
    )

    # ---- 9. Sum costs in dollars (Decimal) ------------------------------
    delta_dollars = Decimal(llm_call.cost_cents) / Decimal(100)

    return state.model_copy(
        update={
            "current_campaign": brief,
            "campaigns_run": state.campaigns_run + 1,
            "cost_so_far": state.cost_so_far + delta_dollars,
        }
    )
