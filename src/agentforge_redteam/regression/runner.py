"""Regression session runner — replay every promoted case against a new build.

When the orchestrator halts with ``HALT_REGRESSION_DUE`` (a new ``target_sha``
has appeared on the in-scope target), the platform needs to re-run every
previously-promoted regression test against THAT build before opening any new
campaign work. This module is the entry point for that replay loop.

Why a separate module
---------------------
The orchestrator's main loop is already large; tacking a regression-dispatch
branch onto it would tangle two distinct concerns (single-campaign
scheduling vs. corpus-wide replay). A dedicated runner keeps the audit story
clean: every promoted case maps to exactly ONE :class:`RegressionResult` and
exactly ONE ``regression_runs`` row, regardless of how many campaigns are
running in the parent orchestrator process.

Why per-case exception catch
----------------------------
``replay_regression_test`` propagates hard errors (HTTP timeout, missing
rubric file, malformed verdict). A single bad case must NOT abort the
entire regression session — the operator needs to know which OTHER cases
also regressed so they can triage the whole front at once. So the runner
catches per-case exceptions, records them as ``status='regressed'`` with a
``notes='exception: <type>: <message>'`` marker, and continues.

Why escalation is left to the caller
------------------------------------
A regression on a P0/P1 case ultimately needs to land in the
``human_approval_queue`` so a human reviewer can decide whether to halt
deploys. That wiring belongs in the orchestrator (which already owns the
queue), not in this runner. The runner's job is to PRODUCE the regression
verdicts; the orchestrator's job is to ROUTE them. Keeping the boundary
explicit means this module stays pure (no DB writes beyond the per-case
``regression_runs`` rows already done by ``replay_regression_test``) and
testable without spinning up the orchestrator's escalation surface.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog
from pydantic import ValidationError
from sqlalchemy.engine import Engine

from agentforge_redteam.agents.judge import judge_node
from agentforge_redteam.agents.red_team import HTTPTargetClientLike
from agentforge_redteam.regression.case import (
    REGRESSIONS_DIR,
    RegressionTestCase,
    read_case,
)
from agentforge_redteam.regression.harness import (
    RegressionResult,
    replay_regression_test,
)

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Result aggregate
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RegressionSessionSummary:
    """Aggregate outcome of one :func:`run_regression_session` invocation.

    The counts let a CI gate decide in one glance whether to fail the build:
    any ``regressed > 0`` is a hard fail; ``weakly_passing > 0`` is a
    warning; ``inconclusive > 0`` means at least one Judge call couldn't
    classify the replay and a human needs to look. See
    ``regression.harness._classify_status`` for the full decision table.

    ``results`` preserves the per-case detail so the CLI / orchestrator can
    print a structured summary without re-reading the DB.
    """

    new_target_sha: str
    total: int
    held: int
    regressed: int
    weakly_passing: int
    inconclusive: int = 0
    results: list[RegressionResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Case discovery
# ---------------------------------------------------------------------------


def _iter_case_files(root: Path) -> Iterator[Path]:
    """Yield every ``*.json`` file directly under ``root``.

    Non-existent root is treated as empty — the very first regression
    session in a fresh checkout should succeed (with zero cases) rather
    than raise. Sub-directories are ignored: the on-disk layout is flat
    (``<root>/<finding_id>.json``) by design.
    """
    if not root.exists():
        return
    for path in sorted(root.glob("*.json")):
        if path.is_file():
            yield path


def list_promoted_cases(root: Path | str = REGRESSIONS_DIR) -> list[RegressionTestCase]:
    """Return every :class:`RegressionTestCase` under ``root``.

    Ordering: stable, lexicographic by the case's ``finding_id`` (which is
    a UUID string). The lexicographic sort gives a deterministic replay
    order across machines so the per-case ``regression_runs`` rows land
    in a reproducible sequence — useful when correlating against a CI
    log.

    Malformed JSON files (Pydantic validation errors, file read errors)
    are SKIPPED with a structured warning. The regression corpus is a Git-
    tracked human-curated tree and one corrupt entry should not block the
    rest of the session.
    """
    root_path = Path(root)
    cases: list[RegressionTestCase] = []
    for path in _iter_case_files(root_path):
        try:
            cases.append(read_case(path))
        except (ValidationError, ValueError, OSError) as exc:
            logger.warning(
                "regression.case_unreadable",
                path=str(path),
                error_type=type(exc).__name__,
                error=str(exc),
            )
            continue
    cases.sort(key=lambda c: str(c.finding_id))
    return cases


# ---------------------------------------------------------------------------
# Status tally
# ---------------------------------------------------------------------------


def _tally(results: list[RegressionResult]) -> dict[str, int]:
    """Bucket ``results`` by ``status``. Missing buckets default to 0."""
    counts = {"held": 0, "regressed": 0, "weakly_passing": 0, "inconclusive": 0}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    return counts


def _exception_to_result(
    *,
    case: RegressionTestCase,
    new_target_sha: str,
    exc: Exception,
    root: Path,
) -> RegressionResult:
    """Build a synthetic :class:`RegressionResult` for a per-case hard error.

    The runner classifies an uncaught replay exception as ``regressed`` so
    a CI gate fails loud — the alternative (silently dropping the case)
    would let a broken target hide behind an unhandled exception. The
    ``run_id`` is a freshly-minted UUID so the result still slots into the
    summary's results list cleanly; there is intentionally NO matching
    ``regression_runs`` row for this synthetic result because no replay
    actually completed. The ``notes`` field carries the exception class
    name so reviewers can grep for "exception:" in CI output.
    """
    notes = f"exception: {type(exc).__name__}: {exc}"
    return RegressionResult(
        run_id=uuid.uuid4(),
        test_case_path=str(root / f"{case.finding_id}.json"),
        new_target_sha=new_target_sha,
        status="regressed",
        old_verdict=case.expected_verdict,
        new_verdict=case.expected_verdict,
        old_confidence=case.expected_confidence,
        new_confidence=case.expected_confidence,
        confidence_delta=0.0,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def run_regression_session(
    *,
    new_target_sha: str,
    engine: Engine,
    http: HTTPTargetClientLike,
    llm_for_judge: Any,
    langfuse: Any | None = None,
    root: Path | str = REGRESSIONS_DIR,
) -> RegressionSessionSummary:
    """Replay every promoted regression case against ``new_target_sha``.

    Steps:

    1. Discover every case via :func:`list_promoted_cases`. Empty corpus
       returns an empty summary — the caller is responsible for deciding
       whether "no regression tests" is itself a configuration error.
    2. For each case, invoke :func:`replay_regression_test` with the real
       :func:`judge_node` (injected here, not imported by the harness, so
       the harness's unit tests stay LLM-free). Per-case exceptions are
       caught and recorded as ``regressed`` so one bad case does NOT
       abort the whole session.
    3. Aggregate via :func:`_tally`, build a :class:`RegressionSessionSummary`
       and return it.

    Escalation (filing a P0/P1 regression onto the ``human_approval_queue``)
    is deliberately NOT done here — see the module docstring. The runner's
    contract is "produce the verdicts"; routing is the orchestrator's.
    """
    root_path = Path(root)
    cases = list_promoted_cases(root_path)

    logger.info(
        "regression.session_start",
        new_target_sha=new_target_sha,
        case_count=len(cases),
        root=str(root_path),
    )

    results: list[RegressionResult] = []
    for case in cases:
        try:
            result = await replay_regression_test(
                test_case=case,
                new_target_sha=new_target_sha,
                engine=engine,
                http=http,
                judge_node=judge_node,
                llm_for_judge=llm_for_judge,
                langfuse=langfuse,
                root=root_path,
            )
        except Exception as exc:
            logger.error(
                "regression.case_failed",
                finding_id=str(case.finding_id),
                error_type=type(exc).__name__,
                error=str(exc),
            )
            result = _exception_to_result(
                case=case,
                new_target_sha=new_target_sha,
                exc=exc,
                root=root_path,
            )
        results.append(result)

    counts = _tally(results)
    summary = RegressionSessionSummary(
        new_target_sha=new_target_sha,
        total=len(results),
        held=counts["held"],
        regressed=counts["regressed"],
        weakly_passing=counts["weakly_passing"],
        inconclusive=counts["inconclusive"],
        results=results,
    )

    logger.info(
        "regression.session_complete",
        new_target_sha=new_target_sha,
        total=summary.total,
        held=summary.held,
        regressed=summary.regressed,
        weakly_passing=summary.weakly_passing,
        inconclusive=summary.inconclusive,
    )

    return summary
