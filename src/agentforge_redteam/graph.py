"""LangGraph ``StateGraph`` wiring for the four-agent red-team loop.

This module defines the *structure* of the agent graph: nodes for the four
agents and the conditional edges that route between them. The node bodies are
the stub functions from :mod:`agentforge_redteam.agents.stubs`; real agents
land in tasks 25-28 and are slotted in by name.

The graph operates over :class:`agentforge_redteam.state.PlatformState`, which
is a Pydantic ``BaseModel``. LangGraph 1.x accepts Pydantic models as state
schemas directly — see :class:`langgraph.graph.StateGraph` — so no TypedDict
adapter is required.

Edges
-----
``START -> orchestrator``
    The graph always begins by asking the Orchestrator what to do.

``orchestrator -> (END | red_team)``
    Conditional on :func:`_should_halt`: a non-``None`` ``halt_reason``
    terminates the run; otherwise the Red Team agent is dispatched.

``red_team -> judge``
    Every attack must be judged.

``judge -> (documentation | orchestrator)``
    Conditional on :func:`_verdict_routes`: only ``pass`` and ``partial``
    verdicts are worth documenting; ``fail`` / ``inconclusive`` loop straight
    back to the Orchestrator for the next campaign.

``documentation -> orchestrator``
    After a finding is filed the Orchestrator decides whether to continue.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

from langgraph.graph import END, START, StateGraph

from agentforge_redteam.agents.stubs import (
    documentation_stub,
    judge_stub,
    orchestrator_stub,
    red_team_stub,
)
from agentforge_redteam.state import PlatformState

if TYPE_CHECKING:
    # LangGraph's generic state classes carry four type params; we don't need
    # the precision in callers and the langgraph stubs are ignored by mypy
    # anyway (see [[tool.mypy.overrides]] in pyproject.toml).
    StateGraphT = Any
    CompiledStateGraphT = Any


NODE_ORCHESTRATOR: Final = "orchestrator"
NODE_RED_TEAM: Final = "red_team"
NODE_JUDGE: Final = "judge"
NODE_DOCUMENTATION: Final = "documentation"


def _should_halt(state: PlatformState) -> str:
    """Conditional edge from orchestrator: ``halt`` -> END, ``continue`` -> red_team."""
    return "halt" if state.halt_reason is not None else "continue"


def _verdict_routes(state: PlatformState) -> str:
    """Conditional edge from judge: route to documentation only on pass/partial."""
    last = state.verdict_records[-1] if state.verdict_records else None
    if last is None:
        # Malformed — should never happen, but defend the edge so a missing
        # judge write becomes a "loop back to orchestrator" rather than a crash.
        return "skip_doc"
    return "to_doc" if last.verdict in ("pass", "partial") else "skip_doc"


def build_graph() -> StateGraphT:
    """Construct the un-compiled :class:`StateGraph` over :class:`PlatformState`."""
    g = StateGraph(PlatformState)
    g.add_node(NODE_ORCHESTRATOR, orchestrator_stub)
    g.add_node(NODE_RED_TEAM, red_team_stub)
    g.add_node(NODE_JUDGE, judge_stub)
    g.add_node(NODE_DOCUMENTATION, documentation_stub)

    g.add_edge(START, NODE_ORCHESTRATOR)
    g.add_conditional_edges(
        NODE_ORCHESTRATOR,
        _should_halt,
        {"halt": END, "continue": NODE_RED_TEAM},
    )
    g.add_edge(NODE_RED_TEAM, NODE_JUDGE)
    g.add_conditional_edges(
        NODE_JUDGE,
        _verdict_routes,
        {"to_doc": NODE_DOCUMENTATION, "skip_doc": NODE_ORCHESTRATOR},
    )
    g.add_edge(NODE_DOCUMENTATION, NODE_ORCHESTRATOR)
    return g


def compile_graph() -> CompiledStateGraphT:
    """Build and compile the graph. Returns the LangGraph runnable."""
    return build_graph().compile()
