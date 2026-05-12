"""Tests for the Orchestrator agent skeleton (Task 27).

These tests run against:

* a real SQLite database migrated via Alembic into ``tmp_path`` (so the
  ``coverage_matrix`` and ``agent_steps`` rows under test live in the same
  schema production uses),
* the real rubric set checked into ``rubrics/`` — three production
  categories with multiple sub_attacks each,
* the real ``orchestrator_policy.yaml`` shipped in the repo, plus targeted
  override files for the budget / canary / epsilon-edge tests,
* a seeded :class:`random.Random` so every selection is deterministic,
* a fake LLM client that satisfies the injected :class:`Protocol` and
  records every call.

The orchestrator never imports an LLM SDK at module top level, so this
isolation is structural — not a test-suite trick.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from decimal import Decimal
from pathlib import Path
from random import Random
from typing import Any

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from pydantic import ValidationError
from sqlalchemy.engine import Engine

from agentforge_redteam.agents.orchestrator import (
    DEFAULT_MODEL,
    HALT_BUDGET,
    HALT_KILL_SWITCH,
    HALT_NO_CANDIDATES,
    CandidateScore,
    LLMClientLike,
    LLMResponse,
    orchestrator_node,
    score_candidates,
    select_candidate,
)
from agentforge_redteam.db import create_platform_engine
from agentforge_redteam.kill_switch import set_kill_switch
from agentforge_redteam.orchestrator_policy import OrchestratorPolicy, load_policy

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
    """Load the real repo policy under test."""
    return load_policy(POLICY_PATH)


@pytest.fixture
def base_state() -> Any:
    """A clean :class:`PlatformState` with no campaign or cost yet."""
    from agentforge_redteam.state import PlatformState

    return PlatformState(session_id="test-session")


def _write_policy(tmp_path: Path, **overrides: Any) -> Path:
    """Write a custom policy YAML and return its path.

    The defaults match the production ``orchestrator_policy.yaml`` so
    individual tests only need to override the fields they care about.
    """
    import yaml

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


def _insert_coverage(
    engine: Engine,
    *,
    category: str,
    sub_attack: str,
    runs_last_7d: int = 0,
    runs_lifetime: int = 0,
    findings_by_severity: dict[str, int] | None = None,
    coverage_score: float = 0.0,
    avg_cost_cents: int = 0,
) -> None:
    """Direct INSERT into ``coverage_matrix`` for tests that need specific values."""
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO coverage_matrix "
                "(category, sub_attack, runs_last_7d, runs_lifetime, "
                "findings_by_severity, avg_cost_cents, coverage_score) "
                "VALUES (:c, :s, :r7, :rl, :fbs, :acc, :cs)"
            ),
            {
                "c": category,
                "s": sub_attack,
                "r7": runs_last_7d,
                "rl": runs_lifetime,
                "fbs": json.dumps(findings_by_severity or {}),
                "acc": avg_cost_cents,
                "cs": coverage_score,
            },
        )


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeLLM:
    """Fake :class:`LLMClientLike` — returns canned text and records calls."""

    def __init__(
        self,
        *,
        text: str = "The orchestrator selected this campaign because...",
        cost_cents: int = 20,
    ) -> None:
        self.text = text
        self.cost_cents = cost_cents
        self.calls: list[dict[str, Any]] = []

    async def complete(self, *, system: str, user: str, model: str) -> LLMResponse:
        self.calls.append(
            {
                "system_len": len(system),
                "user_len": len(user),
                "user": user,
                "model": model,
            }
        )
        return LLMResponse(text=self.text, cost_cents=self.cost_cents)


# Module-level binding to assert the protocol is satisfiable at type-check time.
_proto_llm: LLMClientLike = _FakeLLM()


# ---------------------------------------------------------------------------
# Policy loader
# ---------------------------------------------------------------------------


def test_load_policy_round_trips_valid_file(tmp_path: Path) -> None:
    """Round trip: write a known-valid policy, load it, fields match."""
    p = _write_policy(tmp_path, epsilon=0.25)
    loaded = load_policy(p)
    assert loaded.version == 1
    assert loaded.epsilon == 0.25
    assert loaded.target_runs_per_sub_attack_per_week == 50
    # SHA is 64 hex chars (SHA-256 of the file bytes).
    assert len(loaded.sha) == 64
    assert all(c in "0123456789abcdef" for c in loaded.sha)


def test_policy_rejects_epsilon_above_one() -> None:
    """Pydantic must refuse ``epsilon > 1.0`` — it's a probability."""
    with pytest.raises(ValidationError):
        OrchestratorPolicy(
            version=1,
            target_runs_per_sub_attack_per_week=50,
            epsilon=1.5,
            severity_weights={"P0": 4.0},
            max_session_cost_cents=1000,
            default_campaign_budget_cents=50,
            canary_every_n_campaigns=10,
            sha="a" * 64,
        )


# ---------------------------------------------------------------------------
# Pure scoring
# ---------------------------------------------------------------------------


def test_score_candidates_non_empty_for_production_rubrics() -> None:
    """The three production rubric categories produce a non-empty score list."""
    from agentforge_redteam.rubrics.loader import load_all_rubrics

    rubrics = load_all_rubrics(RUBRICS_DIR)
    candidates = [(cat, sa) for cat in sorted(rubrics.keys()) for sa in rubrics[cat].sub_attacks]
    scored = score_candidates(
        candidates,
        coverage_rows={},
        severity_weights={"P0": 4.0, "P1": 2.0, "P2": 1.0, "P3": 0.5},
        target_runs=50,
    )
    assert len(scored) == len(candidates)
    assert all(isinstance(s, CandidateScore) for s in scored)
    # Empty coverage: gap == target_runs for every candidate.
    assert all(s.coverage_gap == 50 for s in scored)


def test_score_candidates_higher_coverage_gap_scores_higher() -> None:
    """A sub_attack with more remaining runs should score higher than one
    that's already saturated, all else equal."""
    weights = {"P0": 4.0, "P1": 2.0, "P2": 1.0, "P3": 0.5}
    coverage = {
        ("cat", "fresh"): {"runs_last_7d": 0, "findings_by_severity": {}},
        ("cat", "saturated"): {"runs_last_7d": 50, "findings_by_severity": {}},
    }
    scored = score_candidates(
        [("cat", "fresh"), ("cat", "saturated")],
        coverage_rows=coverage,
        severity_weights=weights,
        target_runs=50,
    )
    by_name = {s.sub_attack: s for s in scored}
    assert by_name["fresh"].raw_score > by_name["saturated"].raw_score
    assert by_name["fresh"].coverage_gap == 50
    assert by_name["saturated"].coverage_gap == 0


def test_score_candidates_severity_weight_applied() -> None:
    """Two candidates with identical coverage but different severity history:
    the one with prior P0s must score higher."""
    weights = {"P0": 4.0, "P1": 2.0, "P2": 1.0, "P3": 0.5}
    coverage = {
        ("cat", "boring"): {"runs_last_7d": 10, "findings_by_severity": {}},
        ("cat", "dangerous"): {
            "runs_last_7d": 10,
            "findings_by_severity": {"P0": 2, "P3": 1},
        },
    }
    scored = score_candidates(
        [("cat", "boring"), ("cat", "dangerous")],
        coverage_rows=coverage,
        severity_weights=weights,
        target_runs=50,
    )
    by_name = {s.sub_attack: s for s in scored}
    assert by_name["dangerous"].raw_score > by_name["boring"].raw_score
    # 4.0 * 2 + 0.5 * 1 = 8.5
    assert by_name["dangerous"].severity_score == pytest.approx(8.5)


def test_score_candidates_missing_coverage_rows_treated_as_zero() -> None:
    """A category with NO rows in coverage_rows still scores; treated as
    a default-zero row."""
    weights = {"P0": 4.0}
    # Pass an empty coverage map; every candidate should still score.
    scored = score_candidates(
        [("absent", "one"), ("absent", "two")],
        coverage_rows={},
        severity_weights=weights,
        target_runs=10,
    )
    assert len(scored) == 2
    assert all(s.coverage_gap == 10 for s in scored)
    assert all(s.severity_score == 0.0 for s in scored)
    # raw_score = max(1.0, 0.0) * (1 + 10) = 11
    assert all(s.raw_score == 11.0 for s in scored)


# ---------------------------------------------------------------------------
# Pure selection
# ---------------------------------------------------------------------------


def _candidate(name: str, raw_score: float, coverage_score: float = 0.0) -> CandidateScore:
    return CandidateScore(
        category="cat",
        sub_attack=name,
        coverage_gap=0,
        severity_score=0.0,
        raw_score=raw_score,
        coverage_score=coverage_score,
    )


def test_select_candidate_epsilon_zero_picks_argmax() -> None:
    """At epsilon=0 we always pick the highest raw_score."""
    scored = [_candidate("a", 1.0), _candidate("b", 5.0), _candidate("c", 3.0)]
    pick = select_candidate(scored, epsilon=0.0, rng=Random(42))
    assert pick.sub_attack == "b"


def test_select_candidate_epsilon_one_picks_uniformly_seeded() -> None:
    """At epsilon=1.0 every pick is uniform-random. With Random(42), we
    can assert the deterministic outcome."""
    scored = [
        _candidate("alpha", 1.0),
        _candidate("beta", 1.0),
        _candidate("gamma", 1.0),
    ]
    rng = Random(42)
    pick = select_candidate(scored, epsilon=1.0, rng=rng)
    # The pick must be one of the candidates and is deterministic under seed 42.
    assert pick.sub_attack in {"alpha", "beta", "gamma"}
    # Re-running with a fresh Random(42) gives the same answer.
    pick2 = select_candidate(scored, epsilon=1.0, rng=Random(42))
    assert pick.sub_attack == pick2.sub_attack


def test_select_candidate_raises_on_empty_input() -> None:
    """Empty list is a programmer error; we raise ValueError."""
    with pytest.raises(ValueError, match="empty"):
        select_candidate([], epsilon=0.0, rng=Random(42))


def test_select_candidate_tie_break_is_deterministic() -> None:
    """Two candidates with the same raw_score: tie-broken by (coverage_score,
    sub_attack alphabetical)."""
    # Same raw_score; "alpha" comes first alphabetically.
    scored = [
        _candidate("zeta", 5.0, coverage_score=1.0),
        _candidate("alpha", 5.0, coverage_score=1.0),
    ]
    pick = select_candidate(scored, epsilon=0.0, rng=Random(42))
    assert pick.sub_attack == "alpha"


# ---------------------------------------------------------------------------
# orchestrator_node — happy path
# ---------------------------------------------------------------------------


async def test_orchestrator_node_writes_campaign_and_increments_state(
    engine: Engine, policy: OrchestratorPolicy, base_state: Any
) -> None:
    """Fresh state: orchestrator picks a campaign, sets it on state,
    increments ``campaigns_run`` and ``cost_so_far``."""
    llm = _FakeLLM(cost_cents=20)
    new_state = await orchestrator_node(
        base_state,
        engine=engine,
        llm=llm,
        policy=policy,
        rng=Random(42),
        rubrics_dir=RUBRICS_DIR,
    )
    assert new_state.current_campaign is not None
    assert new_state.campaigns_run == 1
    # 20 cents = $0.20
    assert new_state.cost_so_far == Decimal("0.20")
    assert new_state.halt_reason is None
    # The base state must remain pristine (no in-place mutation).
    assert base_state.current_campaign is None
    assert base_state.campaigns_run == 0


async def test_orchestrator_node_brief_uses_policy_budget(
    engine: Engine, policy: OrchestratorPolicy, base_state: Any
) -> None:
    """CampaignBrief.budget_cents must equal policy.default_campaign_budget_cents."""
    llm = _FakeLLM()
    new_state = await orchestrator_node(
        base_state,
        engine=engine,
        llm=llm,
        policy=policy,
        rng=Random(42),
        rubrics_dir=RUBRICS_DIR,
    )
    assert new_state.current_campaign is not None
    assert new_state.current_campaign.budget_cents == policy.default_campaign_budget_cents


async def test_orchestrator_node_cost_so_far_is_decimal(
    engine: Engine, policy: OrchestratorPolicy, base_state: Any
) -> None:
    """``cost_so_far`` stays Decimal and increments by exactly the LLM cost."""
    llm = _FakeLLM(cost_cents=37)
    new_state = await orchestrator_node(
        base_state,
        engine=engine,
        llm=llm,
        policy=policy,
        rng=Random(42),
        rubrics_dir=RUBRICS_DIR,
    )
    assert isinstance(new_state.cost_so_far, Decimal)
    assert new_state.cost_so_far == Decimal("0.37")


# ---------------------------------------------------------------------------
# orchestrator_node — halts
# ---------------------------------------------------------------------------


async def test_orchestrator_node_kill_switch_halts(
    engine: Engine, policy: OrchestratorPolicy, base_state: Any
) -> None:
    """Kill switch on -> halt with ``HALT_KILL_SWITCH`` and NO LLM call."""
    set_kill_switch(engine, enabled=True)
    llm = _FakeLLM()
    new_state = await orchestrator_node(
        base_state,
        engine=engine,
        llm=llm,
        policy=policy,
        rng=Random(42),
        rubrics_dir=RUBRICS_DIR,
    )
    assert new_state.halt_reason == HALT_KILL_SWITCH
    assert new_state.current_campaign is None
    assert new_state.campaigns_run == 0
    # No audit row and no LLM call.
    assert llm.calls == []
    with engine.connect() as conn:
        n = conn.execute(sa.text("SELECT COUNT(*) FROM agent_steps")).scalar_one()
    assert n == 0


async def test_orchestrator_node_budget_halts(
    engine: Engine, tmp_path: Path, base_state: Any
) -> None:
    """Project cost above the session cap -> halt with ``HALT_BUDGET``."""
    # Tight cap: 100 cents max, 60 cents per campaign. Seeding 50 cents
    # in cost_so_far makes the projected next campaign (50 + 60 = 110)
    # exceed the 100 cap.
    p = _write_policy(
        tmp_path,
        max_session_cost_cents=100,
        default_campaign_budget_cents=60,
    )
    policy = load_policy(p)
    state = base_state.model_copy(update={"cost_so_far": Decimal("0.50")})

    llm = _FakeLLM()
    new_state = await orchestrator_node(
        state,
        engine=engine,
        llm=llm,
        policy=policy,
        rng=Random(42),
        rubrics_dir=RUBRICS_DIR,
    )
    assert new_state.halt_reason == HALT_BUDGET
    assert new_state.current_campaign is None
    assert llm.calls == []


async def test_orchestrator_node_no_candidates_halts(
    engine: Engine, policy: OrchestratorPolicy, base_state: Any, tmp_path: Path
) -> None:
    """Empty rubric directory -> halt with ``HALT_NO_CANDIDATES``."""
    empty_dir = tmp_path / "empty_rubrics"
    empty_dir.mkdir()
    llm = _FakeLLM()
    new_state = await orchestrator_node(
        base_state,
        engine=engine,
        llm=llm,
        policy=policy,
        rng=Random(42),
        rubrics_dir=empty_dir,
    )
    assert new_state.halt_reason == HALT_NO_CANDIDATES
    assert new_state.current_campaign is None
    assert llm.calls == []


# ---------------------------------------------------------------------------
# Audit + canary
# ---------------------------------------------------------------------------


async def test_orchestrator_node_writes_agent_steps_row(
    engine: Engine, policy: OrchestratorPolicy, base_state: Any
) -> None:
    """One audit row, agent='orchestrator', tool='campaign_rationale'."""
    llm = _FakeLLM()
    await orchestrator_node(
        base_state,
        engine=engine,
        llm=llm,
        policy=policy,
        rng=Random(42),
        rubrics_dir=RUBRICS_DIR,
    )
    with engine.connect() as conn:
        rows = conn.execute(sa.text("SELECT agent, tool FROM agent_steps")).fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "orchestrator"
    assert rows[0][1] == "campaign_rationale"


async def test_orchestrator_node_canary_every_n(
    engine: Engine, tmp_path: Path, base_state: Any
) -> None:
    """With campaigns_run == 10 and canary_every_n == 10, next is a canary."""
    p = _write_policy(tmp_path, canary_every_n_campaigns=10)
    policy = load_policy(p)
    state = base_state.model_copy(update={"campaigns_run": 10})
    llm = _FakeLLM()
    new_state = await orchestrator_node(
        state,
        engine=engine,
        llm=llm,
        policy=policy,
        rng=Random(42),
        rubrics_dir=RUBRICS_DIR,
    )
    assert new_state.current_campaign is not None
    assert new_state.current_campaign.is_canary is True
    assert new_state.current_campaign.canary_expected_verdict == "fail"


async def test_orchestrator_node_tie_break_is_deterministic_across_calls(
    engine: Engine, base_state: Any
) -> None:
    """Two orchestrator_node calls with the same seeded rng must produce
    the same first selection.

    Use epsilon=0 so the argmax + tie-break path determines the pick.
    Empty coverage matrix means every sub_attack has the same raw_score,
    which is exactly the tie-breaker we want to test.
    """
    policy_zero = OrchestratorPolicy(
        version=1,
        target_runs_per_sub_attack_per_week=50,
        epsilon=0.0,
        severity_weights={"P0": 4.0, "P1": 2.0, "P2": 1.0, "P3": 0.5},
        max_session_cost_cents=1000,
        default_campaign_budget_cents=50,
        canary_every_n_campaigns=10,
        sha="0" * 64,
    )

    s1 = await orchestrator_node(
        base_state,
        engine=engine,
        llm=_FakeLLM(),
        policy=policy_zero,
        rng=Random(42),
        rubrics_dir=RUBRICS_DIR,
    )
    s2 = await orchestrator_node(
        base_state,
        engine=engine,
        llm=_FakeLLM(),
        policy=policy_zero,
        rng=Random(42),
        rubrics_dir=RUBRICS_DIR,
    )
    assert s1.current_campaign is not None
    assert s2.current_campaign is not None
    assert s1.current_campaign.category == s2.current_campaign.category
    assert s1.current_campaign.sub_attack == s2.current_campaign.sub_attack


async def test_orchestrator_node_llm_user_prompt_carries_no_sql(
    engine: Engine, policy: OrchestratorPolicy, base_state: Any
) -> None:
    """The rationale user prompt must be a JSON payload, not raw SQL.

    Information-exposure boundary: the rationale endpoint sees the
    selected candidate and a one-row coverage snapshot — nothing else.
    We assert no SQL keywords appear (defensive sanity) and that the
    body parses as JSON.
    """
    llm = _FakeLLM()
    # Seed a coverage row so the snapshot has interesting values.
    _insert_coverage(
        engine,
        category="prompt-injection-indirect",
        sub_attack="marker_token_reproduction",
        runs_last_7d=3,
        findings_by_severity={"P2": 1},
    )

    await orchestrator_node(
        base_state,
        engine=engine,
        llm=llm,
        policy=policy,
        rng=Random(42),
        rubrics_dir=RUBRICS_DIR,
    )
    assert len(llm.calls) == 1
    user = llm.calls[0]["user"]
    # Parses as JSON.
    payload = json.loads(user)
    assert "selected" in payload
    assert "coverage_snapshot" in payload
    # No SQL keywords leaked into the prompt.
    upper = user.upper()
    for kw in ("SELECT ", "INSERT ", "UPDATE ", "DELETE ", "FROM ", "WHERE "):
        assert kw not in upper, f"unexpected SQL keyword {kw!r} in rationale prompt"


async def test_orchestrator_node_passes_default_model(
    engine: Engine, policy: OrchestratorPolicy, base_state: Any
) -> None:
    """The default model wired into ``orchestrator_node`` is Haiku."""
    llm = _FakeLLM()
    await orchestrator_node(
        base_state,
        engine=engine,
        llm=llm,
        policy=policy,
        rng=Random(42),
        rubrics_dir=RUBRICS_DIR,
    )
    assert llm.calls[0]["model"] == DEFAULT_MODEL


# ---------------------------------------------------------------------------
# Protocol sanity
# ---------------------------------------------------------------------------


def test_protocol_fake_typechecks() -> None:
    """Module-level :data:`_proto_llm` exists, proving the fake satisfies
    :class:`LLMClientLike` at type-check time."""
    assert isinstance(_proto_llm, _FakeLLM)
