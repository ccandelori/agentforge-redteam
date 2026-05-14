"""Tests for the Task 37 orchestrator extensions.

These tests cover the three discrete extensions added on top of the Task 27
skeleton, without touching the existing ``test_orchestrator.py`` contract:

* Per-category targets in :class:`OrchestratorPolicy`.
* Coverage-matrix denormalization in
  :mod:`agentforge_redteam.observability.coverage`.
* The full halt-condition rulebook in :func:`orchestrator_node`
  (no_progress, canary_failed, regression_due) and the
  ``detect_regression_due`` helper.

Fixtures mirror ``test_orchestrator.py``: a tmp SQLite database migrated
to ``head`` via Alembic, a seeded :class:`random.Random`, and a fake LLM
client.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from random import Random
from typing import Any
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
import yaml
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import Engine

from agentforge_redteam.agents import orchestrator as orchestrator_mod
from agentforge_redteam.agents.orchestrator import (
    HALT_BUDGET,
    HALT_CANARY_FAILED,
    HALT_KILL_SWITCH,
    HALT_NO_PROGRESS,
    HALT_REGRESSION_DUE,
    LLMResponse,
    detect_regression_due,
    orchestrator_node,
    score_candidates,
)
from agentforge_redteam.db import create_platform_engine
from agentforge_redteam.kill_switch import set_kill_switch
from agentforge_redteam.observability.coverage import (
    CoverageRow,
    coverage_row_for,
    recompute_coverage_matrix,
)
from agentforge_redteam.orchestrator_policy import OrchestratorPolicy, load_policy
from agentforge_redteam.state import PlatformState, VerdictRecord

REPO_ROOT = Path(__file__).resolve().parents[2]
ALEMBIC_INI = REPO_ROOT / "alembic.ini"
ALEMBIC_DIR = REPO_ROOT / "alembic"
RUBRICS_DIR = REPO_ROOT / "rubrics"
POLICY_PATH = REPO_ROOT / "orchestrator_policy.yaml"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Engine]:
    """Yield a platform engine pointed at a freshly-migrated tmp database."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("PLATFORM_DB_PATH", str(db_path))

    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("script_location", str(ALEMBIC_DIR))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    command.upgrade(cfg, "head")

    eng = create_platform_engine(db_path)
    try:
        yield eng
    finally:
        eng.dispose()


@pytest.fixture
def policy() -> OrchestratorPolicy:
    """Load the real repo policy (now carrying the Task 37 fields)."""
    return load_policy(POLICY_PATH)


@pytest.fixture
def base_state() -> PlatformState:
    return PlatformState(session_id="test-session")


def _write_policy(tmp_path: Path, **overrides: Any) -> Path:
    """Write a custom policy YAML; defaults track the production policy."""
    body: dict[str, Any] = {
        "version": 1,
        "target_runs_per_sub_attack_per_week": 50,
        "epsilon": 0.1,
        "severity_weights": {"P0": 4.0, "P1": 2.0, "P2": 1.0, "P3": 0.5},
        "max_session_cost_cents": 1000,
        "default_campaign_budget_cents": 50,
        "canary_every_n_campaigns": 10,
    }
    body.update(overrides)
    out = tmp_path / "policy.yaml"
    out.write_text(yaml.safe_dump(body), encoding="utf-8")
    return out


class _FakeLLM:
    """Fake :class:`LLMClientLike`; records calls so halt tests can assert
    that no rationale was requested."""

    def __init__(self, *, text: str = "rationale", cost_cents: int = 20) -> None:
        self.text = text
        self.cost_cents = cost_cents
        self.calls: list[dict[str, Any]] = []

    async def complete(self, *, system: str, user: str, model: str) -> LLMResponse:
        self.calls.append({"system": system, "user": user, "model": model})
        return LLMResponse(text=self.text, cost_cents=self.cost_cents)


def _insert_attack(
    engine: Engine,
    *,
    attack_id: UUID,
    campaign_id: UUID,
    target_sha: str = "sha-abc",
    created_at: datetime | None = None,
) -> None:
    """Direct INSERT into ``attacks`` so coverage tests can seed history."""
    with engine.begin() as conn:
        params: dict[str, Any] = {
            "attack_id": str(attack_id),
            "campaign_id": str(campaign_id),
            "payload": "p",
            "target_sha": target_sha,
            "status_code": 200,
        }
        if created_at is not None:
            params["created_at"] = created_at
            conn.execute(
                sa.text(
                    "INSERT INTO attacks "
                    "(attack_id, campaign_id, payload, target_sha, status_code, created_at) "
                    "VALUES (:attack_id, :campaign_id, :payload, :target_sha, "
                    ":status_code, :created_at)"
                ),
                params,
            )
        else:
            conn.execute(
                sa.text(
                    "INSERT INTO attacks "
                    "(attack_id, campaign_id, payload, target_sha, status_code) "
                    "VALUES (:attack_id, :campaign_id, :payload, :target_sha, :status_code)"
                ),
                params,
            )


def _insert_verdict(engine: Engine, *, verdict_id: UUID, attack_id: UUID) -> None:
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO verdicts "
                "(verdict_id, attack_id, verdict, confidence, rubric_sha, model_version, prompt_sha) "
                "VALUES (:vid, :aid, 'fail', 0.9, 'rsha', 'mv', 'psha')"
            ),
            {"vid": str(verdict_id), "aid": str(attack_id)},
        )


def _insert_finding(
    engine: Engine,
    *,
    finding_id: UUID,
    attack_id: UUID,
    verdict_id: UUID,
    severity: str,
) -> None:
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO findings "
                "(finding_id, severity, attack_id, verdict_id) "
                "VALUES (:fid, :sev, :aid, :vid)"
            ),
            {
                "fid": str(finding_id),
                "sev": severity,
                "aid": str(attack_id),
                "vid": str(verdict_id),
            },
        )


def _insert_run_manifest(engine: Engine, *, session_id: str, target_sha: str) -> None:
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO run_manifests "
                "(session_id, target_sha, prompt_set_sha, rubric_set_sha, "
                " attack_library_sha, policy_sha, cost_cap_cents) "
                "VALUES (:sid, :tsha, 'p', 'r', 'a', 'pol', 1000)"
            ),
            {"sid": session_id, "tsha": target_sha},
        )


# ---------------------------------------------------------------------------
# 1-2. Policy parsing: new field optional, accepted when present
# ---------------------------------------------------------------------------


def test_policy_accepts_target_runs_per_category(tmp_path: Path) -> None:
    """A YAML with the per-category override map parses cleanly."""
    p = _write_policy(
        tmp_path,
        target_runs_per_category={
            "prompt-injection-indirect": 50,
            "data-exfiltration": 40,
            "tool-misuse": 30,
        },
    )
    loaded = load_policy(p)
    assert loaded.target_runs_per_category == {
        "prompt-injection-indirect": 50,
        "data-exfiltration": 40,
        "tool-misuse": 30,
    }


def test_policy_without_per_category_still_parses(tmp_path: Path) -> None:
    """Backward compat: no ``target_runs_per_category`` key -> defaults to None."""
    p = _write_policy(tmp_path)  # no override
    loaded = load_policy(p)
    assert loaded.target_runs_per_category is None
    # No-progress threshold defaults to 5.
    assert loaded.no_progress_threshold == 5


# ---------------------------------------------------------------------------
# 3-4. score_candidates honors per-category target
# ---------------------------------------------------------------------------


def test_score_candidates_uses_per_category_target() -> None:
    """A category present in ``target_runs_per_category`` gets that target."""
    coverage = {
        ("cat-a", "sub"): {"runs_last_7d": 10, "findings_by_severity": {}},
        ("cat-b", "sub"): {"runs_last_7d": 10, "findings_by_severity": {}},
    }
    scored = score_candidates(
        [("cat-a", "sub"), ("cat-b", "sub")],
        coverage_rows=coverage,
        severity_weights={"P0": 4.0},
        target_runs=50,
        target_runs_per_category={"cat-a": 100, "cat-b": 20},
    )
    by_cat = {s.category: s for s in scored}
    # cat-a: target=100, gap = 100 - 10 = 90
    assert by_cat["cat-a"].coverage_gap == 90
    # cat-b: target=20, gap = 20 - 10 = 10
    assert by_cat["cat-b"].coverage_gap == 10


def test_score_candidates_falls_back_to_flat_target() -> None:
    """Categories absent from the per-category map use the flat default."""
    coverage = {
        ("cat-overridden", "sub"): {"runs_last_7d": 0, "findings_by_severity": {}},
        ("cat-default", "sub"): {"runs_last_7d": 0, "findings_by_severity": {}},
    }
    scored = score_candidates(
        [("cat-overridden", "sub"), ("cat-default", "sub")],
        coverage_rows=coverage,
        severity_weights={"P0": 4.0},
        target_runs=50,
        target_runs_per_category={"cat-overridden": 10},
    )
    by_cat = {s.category: s for s in scored}
    assert by_cat["cat-overridden"].coverage_gap == 10
    assert by_cat["cat-default"].coverage_gap == 50


# ---------------------------------------------------------------------------
# 5-8. Coverage matrix denormalization
# ---------------------------------------------------------------------------


def test_recompute_coverage_empty_lookup_is_no_op(engine: Engine) -> None:
    """An empty ``campaign_brief_lookup`` writes nothing and returns []."""
    out = recompute_coverage_matrix(engine, campaign_brief_lookup={})
    assert out == []
    with engine.connect() as conn:
        n = conn.execute(sa.text("SELECT COUNT(*) FROM coverage_matrix")).scalar_one()
    assert n == 0


def test_recompute_coverage_aggregates_correctly(engine: Engine) -> None:
    """Seed attacks/verdicts/findings; assert the resulting CoverageRows."""
    campaign_a = uuid4()
    campaign_b = uuid4()
    a1, a2, a3 = uuid4(), uuid4(), uuid4()
    v1, v2 = uuid4(), uuid4()
    f1, f2 = uuid4(), uuid4()

    # Two attacks under campaign_a (cat-a, sub-x), one under campaign_b
    # (cat-b, sub-y). One finding per campaign.
    now = datetime.now(tz=UTC)
    _insert_attack(engine, attack_id=a1, campaign_id=campaign_a, created_at=now)
    _insert_attack(engine, attack_id=a2, campaign_id=campaign_a, created_at=now)
    _insert_attack(engine, attack_id=a3, campaign_id=campaign_b, created_at=now)
    _insert_verdict(engine, verdict_id=v1, attack_id=a1)
    _insert_verdict(engine, verdict_id=v2, attack_id=a3)
    _insert_finding(engine, finding_id=f1, attack_id=a1, verdict_id=v1, severity="P0")
    _insert_finding(engine, finding_id=f2, attack_id=a3, verdict_id=v2, severity="P2")

    lookup = {
        campaign_a: ("cat-a", "sub-x"),
        campaign_b: ("cat-b", "sub-y"),
    }
    rows = recompute_coverage_matrix(engine, campaign_brief_lookup=lookup, now=now)

    by_pair = {(r.category, r.sub_attack): r for r in rows}
    assert by_pair[("cat-a", "sub-x")].runs_lifetime == 2
    assert by_pair[("cat-a", "sub-x")].runs_last_7d == 2
    assert by_pair[("cat-a", "sub-x")].findings_by_severity == {"P0": 1}
    assert by_pair[("cat-b", "sub-y")].runs_lifetime == 1
    assert by_pair[("cat-b", "sub-y")].findings_by_severity == {"P2": 1}


def test_coverage_row_for_returns_none_when_missing(engine: Engine) -> None:
    """Composite PK miss -> None."""
    assert coverage_row_for(engine, category="nope", sub_attack="nope") is None


def test_coverage_row_for_returns_row_after_recompute(engine: Engine) -> None:
    """After recompute_coverage_matrix, the row is queryable by PK."""
    campaign = uuid4()
    attack = uuid4()
    _insert_attack(engine, attack_id=attack, campaign_id=campaign)
    rows = recompute_coverage_matrix(engine, campaign_brief_lookup={campaign: ("cat", "sub")})
    assert len(rows) == 1
    row = coverage_row_for(engine, category="cat", sub_attack="sub")
    assert isinstance(row, CoverageRow)
    assert row.runs_lifetime == 1


# ---------------------------------------------------------------------------
# 9-12. detect_regression_due
# ---------------------------------------------------------------------------


def test_detect_regression_due_returns_false_without_current_sha(engine: Engine) -> None:
    """No anchor SHA -> we cannot conclude regression."""
    assert detect_regression_due(engine, current_target_sha=None) is False


def test_detect_regression_due_returns_false_on_empty_manifests(engine: Engine) -> None:
    """No prior sessions -> nothing to compare against."""
    assert detect_regression_due(engine, current_target_sha="sha-new") is False


def test_detect_regression_due_returns_false_when_shas_match(engine: Engine) -> None:
    """Only manifest in DB matches the current SHA -> no regression."""
    _insert_run_manifest(engine, session_id="s1", target_sha="sha-same")
    assert detect_regression_due(engine, current_target_sha="sha-same") is False


def test_detect_regression_due_returns_true_on_mismatch(engine: Engine) -> None:
    """A prior manifest with a different SHA triggers regression."""
    _insert_run_manifest(engine, session_id="s1", target_sha="sha-old")
    assert detect_regression_due(engine, current_target_sha="sha-new") is True


# ---------------------------------------------------------------------------
# 13-16. orchestrator_node — new halts
# ---------------------------------------------------------------------------


async def test_orchestrator_halts_on_no_progress(
    engine: Engine, policy: OrchestratorPolicy, base_state: PlatformState
) -> None:
    """N consecutive fail verdicts in state -> HALT_NO_PROGRESS, no LLM call.

    Uses ``policy.no_progress_threshold`` directly rather than a hardcoded
    constant — the production threshold has been bumped (5 → 15) to give
    the Red Team's mutation loop more room to find variants against the
    deployed Co-Pilot's defenses.
    """
    fails = [
        VerdictRecord(
            attack_id=uuid4(),
            verdict="fail",
            confidence=0.9,
            rubric_sha="r",
            model_version="m",
        )
        for _ in range(policy.no_progress_threshold)
    ]
    state = base_state.model_copy(update={"verdict_records": fails})

    llm = _FakeLLM()
    new_state = await orchestrator_node(
        state,
        engine=engine,
        llm=llm,
        policy=policy,
        rng=Random(42),
        rubrics_dir=RUBRICS_DIR,
    )
    assert new_state.halt_reason == HALT_NO_PROGRESS
    assert new_state.current_campaign is None
    assert llm.calls == []


async def test_orchestrator_no_progress_not_triggered_with_one_pass(
    engine: Engine, policy: OrchestratorPolicy, base_state: PlatformState
) -> None:
    """Four fails + one pass in the recent window does NOT trip no_progress."""
    records: list[VerdictRecord] = []
    for _ in range(4):
        records.append(
            VerdictRecord(
                attack_id=uuid4(),
                verdict="fail",
                confidence=0.9,
                rubric_sha="r",
                model_version="m",
            )
        )
    # Trailing pass — most-recent-N window must include this and short-circuit.
    records.append(
        VerdictRecord(
            attack_id=uuid4(),
            verdict="pass",
            confidence=0.9,
            rubric_sha="r",
            model_version="m",
        )
    )
    state = base_state.model_copy(update={"verdict_records": records})

    llm = _FakeLLM()
    new_state = await orchestrator_node(
        state,
        engine=engine,
        llm=llm,
        policy=policy,
        rng=Random(42),
        rubrics_dir=RUBRICS_DIR,
    )
    assert new_state.halt_reason is None
    assert new_state.current_campaign is not None


async def test_orchestrator_preserves_existing_canary_failed_halt(
    engine: Engine, policy: OrchestratorPolicy, base_state: PlatformState
) -> None:
    """If state.halt_reason='canary_failed' on entry, orchestrator MUST NOT overwrite it."""
    state = base_state.model_copy(update={"halt_reason": HALT_CANARY_FAILED})
    llm = _FakeLLM()
    new_state = await orchestrator_node(
        state,
        engine=engine,
        llm=llm,
        policy=policy,
        rng=Random(42),
        rubrics_dir=RUBRICS_DIR,
    )
    # Reason preserved verbatim.
    assert new_state.halt_reason == HALT_CANARY_FAILED
    assert new_state.current_campaign is None
    assert llm.calls == []


async def test_orchestrator_halts_on_regression_due(
    engine: Engine, policy: OrchestratorPolicy, base_state: PlatformState
) -> None:
    """current_target_sha differs from a prior manifest -> HALT_REGRESSION_DUE."""
    _insert_run_manifest(engine, session_id="s-prior", target_sha="sha-old")

    llm = _FakeLLM()
    new_state = await orchestrator_node(
        base_state,
        engine=engine,
        llm=llm,
        policy=policy,
        rng=Random(42),
        rubrics_dir=RUBRICS_DIR,
        current_target_sha="sha-new",
    )
    assert new_state.halt_reason == HALT_REGRESSION_DUE
    assert new_state.current_campaign is None
    assert llm.calls == []


# ---------------------------------------------------------------------------
# 17. Halt-condition ORDER
# ---------------------------------------------------------------------------


async def test_halt_order_existing_beats_everything(
    engine: Engine, base_state: PlatformState, tmp_path: Path
) -> None:
    """An entry-time halt_reason beats kill_switch, no_progress, regression,
    budget, and no_candidates — checked in one combined scenario."""
    # Tight budget + kill switch on + prior regression + 5 fails + entry halt.
    set_kill_switch(engine, enabled=True)
    _insert_run_manifest(engine, session_id="s-old", target_sha="sha-old")
    p = _write_policy(tmp_path, max_session_cost_cents=1, default_campaign_budget_cents=1)
    policy = load_policy(p)

    fails = [
        VerdictRecord(
            attack_id=uuid4(),
            verdict="fail",
            confidence=0.9,
            rubric_sha="r",
            model_version="m",
        )
        for _ in range(5)
    ]
    state = base_state.model_copy(
        update={"halt_reason": HALT_CANARY_FAILED, "verdict_records": fails}
    )

    new_state = await orchestrator_node(
        state,
        engine=engine,
        llm=_FakeLLM(),
        policy=policy,
        rng=Random(42),
        rubrics_dir=RUBRICS_DIR,
        current_target_sha="sha-new",
    )
    assert new_state.halt_reason == HALT_CANARY_FAILED


async def test_halt_order_kill_switch_beats_no_progress(
    engine: Engine, policy: OrchestratorPolicy, base_state: PlatformState
) -> None:
    """Kill switch + 5 fails: kill_switch wins (it sits above no_progress)."""
    set_kill_switch(engine, enabled=True)
    fails = [
        VerdictRecord(
            attack_id=uuid4(),
            verdict="fail",
            confidence=0.9,
            rubric_sha="r",
            model_version="m",
        )
        for _ in range(5)
    ]
    state = base_state.model_copy(update={"verdict_records": fails})

    new_state = await orchestrator_node(
        state,
        engine=engine,
        llm=_FakeLLM(),
        policy=policy,
        rng=Random(42),
        rubrics_dir=RUBRICS_DIR,
    )
    assert new_state.halt_reason == HALT_KILL_SWITCH


async def test_halt_order_no_progress_beats_regression(
    engine: Engine, policy: OrchestratorPolicy, base_state: PlatformState
) -> None:
    """N fails + prior manifest mismatch: no_progress beats regression_due."""
    _insert_run_manifest(engine, session_id="s-old", target_sha="sha-old")
    fails = [
        VerdictRecord(
            attack_id=uuid4(),
            verdict="fail",
            confidence=0.9,
            rubric_sha="r",
            model_version="m",
        )
        for _ in range(policy.no_progress_threshold)
    ]
    state = base_state.model_copy(update={"verdict_records": fails})

    new_state = await orchestrator_node(
        state,
        engine=engine,
        llm=_FakeLLM(),
        policy=policy,
        rng=Random(42),
        rubrics_dir=RUBRICS_DIR,
        current_target_sha="sha-new",
    )
    assert new_state.halt_reason == HALT_NO_PROGRESS


async def test_halt_order_regression_beats_budget(
    engine: Engine, tmp_path: Path, base_state: PlatformState
) -> None:
    """Regression-due + budget exhausted: regression wins (sits above budget)."""
    _insert_run_manifest(engine, session_id="s-old", target_sha="sha-old")
    # Tight budget so the budget halt would normally trigger.
    p = _write_policy(tmp_path, max_session_cost_cents=10, default_campaign_budget_cents=100)
    policy = load_policy(p)

    new_state = await orchestrator_node(
        base_state,
        engine=engine,
        llm=_FakeLLM(),
        policy=policy,
        rng=Random(42),
        rubrics_dir=RUBRICS_DIR,
        current_target_sha="sha-new",
    )
    assert new_state.halt_reason == HALT_REGRESSION_DUE


async def test_halt_order_budget_beats_no_candidates(
    engine: Engine, tmp_path: Path, base_state: PlatformState
) -> None:
    """Budget exhausted + empty rubric dir: budget wins (sits above no_candidates)."""
    p = _write_policy(tmp_path, max_session_cost_cents=10, default_campaign_budget_cents=100)
    policy = load_policy(p)
    empty_rubrics = tmp_path / "empty"
    empty_rubrics.mkdir()

    new_state = await orchestrator_node(
        base_state,
        engine=engine,
        llm=_FakeLLM(),
        policy=policy,
        rng=Random(42),
        rubrics_dir=empty_rubrics,
    )
    assert new_state.halt_reason == HALT_BUDGET


# ---------------------------------------------------------------------------
# 18-19. Public exports + policy threshold
# ---------------------------------------------------------------------------


def test_new_halt_constants_exported() -> None:
    """HALT_NO_PROGRESS, HALT_CANARY_FAILED, HALT_REGRESSION_DUE are reachable."""
    assert orchestrator_mod.HALT_NO_PROGRESS == "no_progress"
    assert orchestrator_mod.HALT_CANARY_FAILED == "canary_failed"
    assert orchestrator_mod.HALT_REGRESSION_DUE == "regression_due"


def test_no_progress_threshold_default_and_override() -> None:
    """OrchestratorPolicy.no_progress_threshold defaults to 5 and is overridable."""
    p = OrchestratorPolicy(
        version=1,
        target_runs_per_sub_attack_per_week=50,
        epsilon=0.1,
        severity_weights={"P0": 4.0},
        max_session_cost_cents=1000,
        default_campaign_budget_cents=50,
        canary_every_n_campaigns=10,
        sha="0" * 64,
    )
    assert p.no_progress_threshold == 5

    p2 = OrchestratorPolicy(
        version=1,
        target_runs_per_sub_attack_per_week=50,
        epsilon=0.1,
        severity_weights={"P0": 4.0},
        max_session_cost_cents=1000,
        default_campaign_budget_cents=50,
        canary_every_n_campaigns=10,
        no_progress_threshold=3,
        sha="0" * 64,
    )
    assert p2.no_progress_threshold == 3


# ---------------------------------------------------------------------------
# 20. Idempotency of recompute
# ---------------------------------------------------------------------------


def test_recompute_coverage_is_idempotent(engine: Engine) -> None:
    """Re-running ``recompute_coverage_matrix`` twice yields the same row state.

    No double-counting: ``INSERT OR REPLACE`` on the composite PK
    overwrites the prior row rather than appending.
    """
    campaign = uuid4()
    a1, a2 = uuid4(), uuid4()
    v1 = uuid4()
    f1 = uuid4()
    now = datetime.now(tz=UTC)
    _insert_attack(engine, attack_id=a1, campaign_id=campaign, created_at=now)
    _insert_attack(engine, attack_id=a2, campaign_id=campaign, created_at=now)
    _insert_verdict(engine, verdict_id=v1, attack_id=a1)
    _insert_finding(engine, finding_id=f1, attack_id=a1, verdict_id=v1, severity="P1")

    lookup = {campaign: ("cat", "sub")}

    rows1 = recompute_coverage_matrix(engine, campaign_brief_lookup=lookup, now=now)
    rows2 = recompute_coverage_matrix(engine, campaign_brief_lookup=lookup, now=now)

    assert len(rows1) == 1
    assert len(rows2) == 1

    # The matrix has exactly one row (no duplicates).
    with engine.connect() as conn:
        n = conn.execute(sa.text("SELECT COUNT(*) FROM coverage_matrix")).scalar_one()
    assert n == 1

    row = coverage_row_for(engine, category="cat", sub_attack="sub")
    assert row is not None
    # Counts reflect the single underlying dataset, not 2x.
    assert row.runs_lifetime == 2
    assert row.findings_by_severity == {"P1": 1}


# ---------------------------------------------------------------------------
# Bonus: the production policy parses with its new fields populated.
# ---------------------------------------------------------------------------


def test_production_policy_loads_with_new_fields() -> None:
    """The shipped ``orchestrator_policy.yaml`` parses and carries the
    Task 37 fields. ``no_progress_threshold`` lives in the YAML — this
    asserts the production tunable is being picked up, but uses ≥
    rather than == so calibration changes (the default was bumped from
    5 to 15) don't require a test edit."""
    p = load_policy(POLICY_PATH)
    assert p.target_runs_per_category is not None
    # The YAML carries all three production categories.
    assert "prompt-injection-indirect" in p.target_runs_per_category
    assert p.no_progress_threshold >= 5


def test_recompute_returns_sorted_rows(engine: Engine) -> None:
    """Output is sorted by (category, sub_attack) for determinism."""
    cb = uuid4()
    ca = uuid4()
    aa, ab = uuid4(), uuid4()
    _insert_attack(engine, attack_id=aa, campaign_id=ca)
    _insert_attack(engine, attack_id=ab, campaign_id=cb)
    rows = recompute_coverage_matrix(
        engine,
        campaign_brief_lookup={
            cb: ("z-cat", "z-sub"),
            ca: ("a-cat", "a-sub"),
        },
    )
    assert [(r.category, r.sub_attack) for r in rows] == [
        ("a-cat", "a-sub"),
        ("z-cat", "z-sub"),
    ]


def test_recompute_includes_runs_last_7d_window(engine: Engine) -> None:
    """Attacks older than 7d count toward lifetime but not last_7d."""
    campaign = uuid4()
    now = datetime.now(tz=UTC)
    old = now - timedelta(days=14)
    recent = now - timedelta(hours=1)

    _insert_attack(engine, attack_id=uuid4(), campaign_id=campaign, created_at=old)
    _insert_attack(engine, attack_id=uuid4(), campaign_id=campaign, created_at=recent)

    rows = recompute_coverage_matrix(
        engine,
        campaign_brief_lookup={campaign: ("cat", "sub")},
        now=now,
    )
    assert len(rows) == 1
    assert rows[0].runs_lifetime == 2
    assert rows[0].runs_last_7d == 1


def test_recompute_writes_json_findings_column(engine: Engine) -> None:
    """The stored ``findings_by_severity`` column survives the round-trip
    as JSON (whether returned as dict or str)."""
    campaign = uuid4()
    a1 = uuid4()
    v1 = uuid4()
    _insert_attack(engine, attack_id=a1, campaign_id=campaign)
    _insert_verdict(engine, verdict_id=v1, attack_id=a1)
    _insert_finding(engine, finding_id=uuid4(), attack_id=a1, verdict_id=v1, severity="P3")

    recompute_coverage_matrix(engine, campaign_brief_lookup={campaign: ("cat", "sub")})
    with engine.connect() as conn:
        raw = conn.execute(sa.text("SELECT findings_by_severity FROM coverage_matrix")).scalar_one()
    if isinstance(raw, str):
        raw = json.loads(raw)
    assert raw == {"P3": 1}
