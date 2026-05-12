"""Tests for the canary selection + metric layer (Task 41).

The canary layer is split across two modules:

* :mod:`agentforge_redteam.judge.canary` — pick a ground-truth case and wrap
  it in a :class:`CampaignBrief` honoring the canary invariant.
* :mod:`agentforge_redteam.judge.canary_metric` — record a canary-failure
  event into ``agent_steps`` under the ``tool='canary_failed'`` marker.

Tests against the *real* ``evals/judge_ground_truth/`` corpus are clearly
labelled and depend on the Task-23 seeded distribution (5 fail / 3 pass / 2
partial / 0 inconclusive per category, 30 total). If that distribution
shifts, expect the counts here to need updating.

Tests that need a database build a tiny ``migrated_engine`` inline so the
file remains self-contained — the integration fixture is in a separate
conftest and we don't want to spread that import.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text as sql_text
from sqlalchemy.engine import Engine

from agentforge_redteam.db import create_platform_engine
from agentforge_redteam.ground_truth import GroundTruthCase, write_case
from agentforge_redteam.judge.canary import (
    NoCanaryAvailable,
    campaign_for_canary,
    list_canary_cases,
    select_canary_case,
)
from agentforge_redteam.judge.canary_metric import (
    CANARY_FAILED_AGENT,
    CANARY_FAILED_TOOL_NAME,
    record_canary_failure,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
REAL_GROUND_TRUTH_ROOT = REPO_ROOT / "evals" / "judge_ground_truth"


# ---------------------------------------------------------------------------
# list_canary_cases
# ---------------------------------------------------------------------------


def test_list_canary_cases_empty_root_returns_empty(tmp_path: Path) -> None:
    """A missing-or-empty root must yield ``[]`` without crashing.

    Useful so callers can safely list before any cases have been authored
    (e.g. in a stripped-down test environment)."""
    assert list_canary_cases(root=tmp_path / "does-not-exist") == []
    empty = tmp_path / "empty"
    empty.mkdir()
    assert list_canary_cases(root=empty) == []


def test_list_canary_cases_against_real_corpus_returns_pass_plus_fail() -> None:
    """Against the Task-23 corpus the default filter yields 8 cases / category.

    Distribution per category: 5 fail + 3 pass = 8 high-confidence cases.
    Three categories on disk -> 24 cases total."""
    cases = list_canary_cases(root=REAL_GROUND_TRUTH_ROOT)
    assert len(cases) >= 24
    assert all(c.expected_verdict in ("pass", "fail") for c in cases)


def test_list_canary_cases_filters_by_category() -> None:
    cases = list_canary_cases(
        category="prompt-injection-indirect",
        root=REAL_GROUND_TRUTH_ROOT,
    )
    assert cases  # IPI has 8 high-confidence cases.
    assert all(c.category == "prompt-injection-indirect" for c in cases)


def test_list_canary_cases_filters_to_only_pass() -> None:
    cases = list_canary_cases(
        expected_verdicts=("pass",),
        root=REAL_GROUND_TRUTH_ROOT,
    )
    assert cases
    assert all(c.expected_verdict == "pass" for c in cases)


def test_list_canary_cases_respects_partial_filter() -> None:
    """The filter is whatever the caller asked for — 'partial' is a valid
    opt-in, not a hard-coded exclusion. Use case: a Judge accuracy gate that
    walks the full distribution."""
    cases = list_canary_cases(
        expected_verdicts=("partial",),
        root=REAL_GROUND_TRUTH_ROOT,
    )
    # Each category seeds 2 partials, 3 categories on disk -> 6 expected.
    assert len(cases) >= 6
    assert all(c.expected_verdict == "partial" for c in cases)


# ---------------------------------------------------------------------------
# select_canary_case
# ---------------------------------------------------------------------------


def test_select_canary_case_returns_pass_or_fail_for_ipi() -> None:
    case = select_canary_case(
        "prompt-injection-indirect",
        rng=random.Random(0),
        root=REAL_GROUND_TRUTH_ROOT,
    )
    assert case.category == "prompt-injection-indirect"
    assert case.expected_verdict in ("pass", "fail")


def test_select_canary_case_unknown_category_raises() -> None:
    with pytest.raises(NoCanaryAvailable):
        select_canary_case(
            "not-a-real-category",
            rng=random.Random(0),
            root=REAL_GROUND_TRUTH_ROOT,
        )


def test_select_canary_case_no_inconclusive_in_corpus_raises() -> None:
    """Task-23 explicitly did not seed any ``inconclusive`` cases; asking for
    that verdict on the real corpus must surface the empty-pool error."""
    with pytest.raises(NoCanaryAvailable):
        select_canary_case(
            "prompt-injection-indirect",
            rng=random.Random(0),
            expected_verdicts=("inconclusive",),
            root=REAL_GROUND_TRUTH_ROOT,
        )


def test_select_canary_case_is_deterministic_under_same_seed() -> None:
    """Same seed -> same case id across calls. The cadence layer relies on
    this to make canary picks reproducible from session metadata alone."""
    first = select_canary_case(
        "prompt-injection-indirect",
        rng=random.Random(42),
        root=REAL_GROUND_TRUTH_ROOT,
    )
    second = select_canary_case(
        "prompt-injection-indirect",
        rng=random.Random(42),
        root=REAL_GROUND_TRUTH_ROOT,
    )
    assert first.case_id == second.case_id


# ---------------------------------------------------------------------------
# campaign_for_canary
# ---------------------------------------------------------------------------


def _make_case(
    category: str = "prompt-injection-indirect",
    expected_verdict: str = "fail",
    rubric_outcomes: dict[str, bool] | None = None,
) -> GroundTruthCase:
    """Pydantic-only :class:`GroundTruthCase` factory for tests."""
    return GroundTruthCase(
        category=category,
        attack_input="probe",
        target_response="resp",
        expected_verdict=expected_verdict,  # type: ignore[arg-type]
        confidence=0.9,
        rubric_outcomes=rubric_outcomes or {},
    )


def test_campaign_for_canary_with_override_carries_explicit_sub_attack() -> None:
    case = _make_case(expected_verdict="fail")
    brief = campaign_for_canary(
        case,
        budget_cents=50,
        sub_attack_override="marker_token_reproduction",
    )
    assert brief.category == "prompt-injection-indirect"
    assert brief.sub_attack == "marker_token_reproduction"
    assert brief.budget_cents == 50
    assert brief.is_canary is True
    assert brief.canary_expected_verdict == "fail"


def test_campaign_for_canary_falls_back_to_unknown_when_no_signal() -> None:
    """No override, no True rubric_outcomes -> the inference must produce
    the literal ``"unknown"`` so the brief still validates. Callers are
    expected to treat that as a hint to provide an override."""
    case = _make_case(rubric_outcomes={"a": False, "b": False})
    brief = campaign_for_canary(case, budget_cents=10)
    assert brief.sub_attack == "unknown"
    assert brief.is_canary is True


def test_campaign_for_canary_infers_sub_attack_from_rubric_outcomes() -> None:
    """First ``True`` rubric_outcomes key wins (sorted for determinism)."""
    case = _make_case(
        rubric_outcomes={
            "marker_token_reproduced": True,
            "system_prompt_revealed": False,
            "agent_took_unauthorized_action": False,
        }
    )
    brief = campaign_for_canary(case, budget_cents=10)
    assert brief.sub_attack == "marker_token_reproduced"


# ---------------------------------------------------------------------------
# record_canary_failure (needs DB)
# ---------------------------------------------------------------------------


@pytest.fixture
def migrated_engine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Engine:
    """A tmp SQLite DB with ``alembic upgrade head`` applied. Self-contained
    so this unit test file does not depend on the integration conftest."""
    db_path = tmp_path / "platform.db"
    monkeypatch.setenv("PLATFORM_DB_PATH", str(db_path))
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    command.upgrade(cfg, "head")
    engine = create_platform_engine(db_path)
    try:
        yield engine
    finally:
        engine.dispose()


def test_record_canary_failure_writes_one_row(migrated_engine: Engine) -> None:
    case = _make_case()
    record_canary_failure(
        migrated_engine,
        session_id="session-A",
        case_id=case.case_id,
        expected_verdict="fail",
        actual_verdict="pass",
        confidence_delta=-0.4,
    )
    with migrated_engine.begin() as conn:
        rows = conn.execute(
            sql_text("SELECT agent, tool, session_id FROM agent_steps WHERE tool = :tool"),
            {"tool": CANARY_FAILED_TOOL_NAME},
        ).all()
    assert len(rows) == 1
    agent, tool, session_id = rows[0]
    assert agent == CANARY_FAILED_AGENT
    assert tool == CANARY_FAILED_TOOL_NAME
    assert session_id == "session-A"


def test_record_canary_failure_does_not_dedup(migrated_engine: Engine) -> None:
    """Two calls -> two rows. See module docstring rationale."""
    case = _make_case()
    for _ in range(2):
        record_canary_failure(
            migrated_engine,
            session_id="session-B",
            case_id=case.case_id,
            expected_verdict="fail",
            actual_verdict="pass",
            confidence_delta=-0.4,
        )
    with migrated_engine.begin() as conn:
        count = conn.execute(
            sql_text("SELECT COUNT(*) FROM agent_steps WHERE tool = :tool"),
            {"tool": CANARY_FAILED_TOOL_NAME},
        ).scalar_one()
    assert count == 2


def test_record_canary_failure_args_json_is_well_formed(
    migrated_engine: Engine,
) -> None:
    case = _make_case()
    record_canary_failure(
        migrated_engine,
        session_id="session-C",
        case_id=case.case_id,
        expected_verdict="fail",
        actual_verdict="pass",
        confidence_delta=-0.25,
    )
    with migrated_engine.begin() as conn:
        args_str = conn.execute(
            sql_text("SELECT args FROM agent_steps WHERE tool = :tool"),
            {"tool": CANARY_FAILED_TOOL_NAME},
        ).scalar_one()
    payload = json.loads(args_str)
    assert payload["case_id"] == str(case.case_id)
    assert payload["expected_verdict"] == "fail"
    assert payload["actual_verdict"] == "pass"
    assert payload["confidence_delta"] == pytest.approx(-0.25)


def test_record_canary_failure_row_timestamp_is_auto_populated(
    migrated_engine: Engine,
) -> None:
    """The ``timestamp`` column has ``server_default=CURRENT_TIMESTAMP`` —
    we don't pass a value, so SQLite must fill it in."""
    case = _make_case()
    record_canary_failure(
        migrated_engine,
        session_id="session-D",
        case_id=case.case_id,
        expected_verdict="fail",
        actual_verdict="pass",
        confidence_delta=0.0,
    )
    with migrated_engine.begin() as conn:
        ts = conn.execute(
            sql_text("SELECT timestamp FROM agent_steps WHERE tool = :tool"),
            {"tool": CANARY_FAILED_TOOL_NAME},
        ).scalar_one()
    # SQLite returns this as a string under SQLAlchemy's default conversion;
    # we just need to confirm it's non-empty and shaped like an ISO ts.
    assert ts is not None
    assert str(ts)  # non-empty
    # Quick shape check — CURRENT_TIMESTAMP in SQLite emits 'YYYY-MM-DD HH:MM:SS'.
    assert len(str(ts)) >= len("YYYY-MM-DD HH:MM:SS")


# ---------------------------------------------------------------------------
# End-to-end canary flow against a faux corpus
# ---------------------------------------------------------------------------


def test_end_to_end_canary_pick_and_brief(tmp_path: Path) -> None:
    """Author a tiny corpus on disk, pick a case, build a brief — exercises
    the full selection path that the orchestrator will eventually call."""
    root = tmp_path / "ground_truth"
    fail_case = GroundTruthCase(
        category="prompt-injection-indirect",
        attack_input="payload",
        target_response="resp",
        expected_verdict="fail",
        confidence=0.95,
        rubric_outcomes={"marker_token_reproduced": True},
    )
    pass_case = GroundTruthCase(
        category="prompt-injection-indirect",
        attack_input="benign",
        target_response="clean",
        expected_verdict="pass",
        confidence=0.9,
    )
    write_case(fail_case, root=root)
    write_case(pass_case, root=root)

    picked = select_canary_case(
        "prompt-injection-indirect",
        rng=random.Random(7),
        root=root,
    )
    assert picked.case_id in {fail_case.case_id, pass_case.case_id}

    brief = campaign_for_canary(picked, budget_cents=25)
    assert brief.is_canary is True
    assert brief.canary_expected_verdict == picked.expected_verdict
    assert brief.category == "prompt-injection-indirect"
