"""Unit tests for the LangGraph state-machine wiring in ``agentforge_redteam.graph``.

These tests validate *routing*, not agent behavior — the node bodies are
deterministic stubs from :mod:`agentforge_redteam.agents.stubs`. We exercise
the real LangGraph runtime (no mocking) because the graph is small and the
stubs are pure.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from langgraph.graph import StateGraph

from agentforge_redteam.graph import (
    _should_halt,
    _verdict_routes,
    build_graph,
    compile_graph,
)
from agentforge_redteam.state import (
    AttackRecord,
    PlatformState,
    VerdictRecord,
)


def _as_platform_state(result: Any) -> PlatformState:
    """LangGraph ``.invoke`` may return either a ``PlatformState`` or a dict.

    Normalize so tests can read attributes uniformly.
    """
    if isinstance(result, PlatformState):
        return result
    return PlatformState(**result)


def _run_to_termination() -> PlatformState:
    """Invoke the compiled graph from a fresh state and return the final state."""
    app = compile_graph()
    initial = PlatformState(session_id="test-session")
    final = app.invoke(initial, config={"recursion_limit": 50})
    return _as_platform_state(final)


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_build_graph_returns_state_graph() -> None:
    g = build_graph()
    assert isinstance(g, StateGraph)


def test_compile_graph_returns_runnable() -> None:
    app = compile_graph()
    assert hasattr(app, "invoke")
    assert callable(app.invoke)


# ---------------------------------------------------------------------------
# End-to-end routing via the real runtime
# ---------------------------------------------------------------------------


def test_graph_invocation_runs_to_termination() -> None:
    """Stub orchestrator halts after 2 campaigns; the graph must terminate cleanly."""
    final_state = _run_to_termination()
    assert final_state.halt_reason is not None
    assert final_state.campaigns_run >= 2


def test_final_campaigns_run_is_two() -> None:
    assert _run_to_termination().campaigns_run == 2


def test_final_halt_reason_is_set() -> None:
    assert _run_to_termination().halt_reason is not None


def test_final_attack_records_length_is_two() -> None:
    assert len(_run_to_termination().attack_records) == 2


def test_final_verdict_records_length_is_two() -> None:
    assert len(_run_to_termination().verdict_records) == 2


def test_final_confirmed_findings_length_is_two() -> None:
    """Judge stub returns ``pass`` so documentation fires on every loop."""
    assert len(_run_to_termination().confirmed_findings) == 2


# ---------------------------------------------------------------------------
# Unit tests for the conditional-edge functions
# ---------------------------------------------------------------------------


def _verdict_state(verdict_value: str) -> PlatformState:
    """Build a minimal :class:`PlatformState` whose last verdict has the given value."""
    attack_id = uuid4()
    return PlatformState(
        session_id="t",
        attack_records=[
            AttackRecord(
                campaign_id=uuid4(),
                payload="p",
                target_response="r",
                target_sha="sha",
                status_code=200,
                latency_ms=0,
                attack_id=attack_id,
            )
        ],
        verdict_records=[
            VerdictRecord(
                attack_id=attack_id,
                verdict=verdict_value,  # type: ignore[arg-type]
                confidence=0.5,
                rubric_sha="rubric",
                model_version="m",
            )
        ],
    )


def test_verdict_routes_to_doc_on_pass() -> None:
    assert _verdict_routes(_verdict_state("pass")) == "to_doc"


def test_verdict_routes_skip_doc_on_fail() -> None:
    assert _verdict_routes(_verdict_state("fail")) == "skip_doc"


def test_should_halt_returns_halt_when_reason_set() -> None:
    state = PlatformState(session_id="t", halt_reason="budget_exhausted")
    assert _should_halt(state) == "halt"


def test_should_halt_returns_continue_when_reason_none() -> None:
    state = PlatformState(session_id="t")
    assert _should_halt(state) == "continue"


# ---------------------------------------------------------------------------
# Isolation — repeated runs must not share state
# ---------------------------------------------------------------------------


def test_repeated_invocation_does_not_bleed_state() -> None:
    """Two independent invocations must each produce exactly 2 of each record."""
    app = compile_graph()
    first = _as_platform_state(
        app.invoke(PlatformState(session_id="run-1"), config={"recursion_limit": 50})
    )
    second = _as_platform_state(
        app.invoke(PlatformState(session_id="run-2"), config={"recursion_limit": 50})
    )
    assert first.campaigns_run == 2
    assert second.campaigns_run == 2
    assert len(first.attack_records) == 2
    assert len(second.attack_records) == 2
    assert first.session_id == "run-1"
    assert second.session_id == "run-2"
