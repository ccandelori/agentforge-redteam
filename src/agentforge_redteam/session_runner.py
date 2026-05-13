"""Production session runner — invoke the real LangGraph state machine end-to-end.

The ``agentforge-redteam start-session`` CLI command is a thin Typer wrapper
around this module. The wrapper handles operator-facing exit-code mapping and
output formatting; this module owns the *lifecycle* of one red-team session:

1. Build (or accept) the SQLAlchemy engine.
2. Insert a ``run_manifests`` row up front. Audit-trail-first: if a kill switch
   trips mid-session, an operator can still see that a session was *attempted*
   against the configured target. The placeholder SHAs in the row are filled
   in by individual agents as they resolve their artefacts.
3. Build the production graph via :func:`build_production_graph` and seed an
   initial :class:`PlatformState`.
4. Drive the compiled graph through ``ainvoke`` with a recursion-limit
   backstop derived from ``max_campaigns``. One full orchestrator cycle is
   four hops (orchestrator -> red_team -> judge -> documentation), so the
   limit is ``4 * max_campaigns + 4`` to comfortably bracket the boundary.
5. Coerce the final state into a :class:`SessionSummary` for the caller.

Errors are deliberately *not* swallowed here:

* ``ValueError`` (unknown ``target_alias``) propagates from
  :func:`build_production_graph`.
* ``RuntimeError`` from stub LLMs (missing API keys) propagates — the CLI
  maps it to exit code 3.
* :class:`langgraph.errors.GraphRecursionError` propagates — the CLI maps it
  to exit code 2.

The module deliberately does NOT import Typer or print anything. Keeping the
runner UI-free means future entry points (web worker, scheduled job) can call
it directly without inheriting the CLI's exit-code semantics.
"""

from __future__ import annotations

import asyncio
import logging
import random
import uuid
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, Final

from sqlalchemy import text
from sqlalchemy.engine import Engine

from agentforge_redteam.db import create_platform_engine
from agentforge_redteam.graph_factory import build_production_graph
from agentforge_redteam.state import PlatformState

__all__ = [
    "DEFAULT_CATEGORIES",
    "DEFAULT_COST_CAP_CENTS",
    "DEFAULT_MAX_CAMPAIGNS",
    "DEFAULT_TARGET_ALIAS",
    "SessionSummary",
    "run_session",
]

_LOGGER: Final[logging.Logger] = logging.getLogger(__name__)

DEFAULT_TARGET_ALIAS: Final[str] = "droplet_prod"
DEFAULT_COST_CAP_CENTS: Final[int] = 1000
DEFAULT_CATEGORIES: Final[tuple[str, ...]] = (
    "prompt-injection-indirect",
    "data-exfiltration",
    "tool-misuse",
)
# Hard backstop independent of the orchestrator's per-session budget.
# LangGraph's recursion_limit must be > 4 * max_campaigns (one cycle of the
# four-node graph). The CLI exposes this so an operator can shrink the safety
# cap below the budget cap when smoke-testing.
DEFAULT_MAX_CAMPAIGNS: Final[int] = 5

# Wall-clock backstop for a single session. See `_invoke_with_timeout`
# in `run_session` for the rationale.
_SESSION_WALL_TIMEOUT_S: Final[float] = 30 * 60

# The manifest row is written BEFORE any agent runs and BEFORE the agents
# have surfaced their artefact SHAs to us. We stamp a placeholder string so
# the row obeys the ``NOT NULL`` constraints; the agents (and a future Task)
# rewrite these to real SHAs once their loaders have hashed the on-disk
# bytes. Using a single readable literal keeps the placeholder greppable
# from an audit dashboard.
_PENDING_SHA: Final[str] = "pending"


@dataclass(frozen=True, slots=True)
class SessionSummary:
    """Operator-facing snapshot of one completed (or halted) session.

    Holds only what the CLI prints + tests need to assert on. The full
    audit trail (one row per agent step, one row per attack, one row per
    verdict, one row per finding) lives in SQLite — this dataclass is a
    convenience handle, not a duplicate store.
    """

    session_id: str
    target_alias: str
    target_url: str
    campaigns_run: int
    cost_so_far_dollars: Decimal
    halt_reason: str | None
    confirmed_findings: int
    attack_records: int
    verdict_records: int


def _insert_manifest(engine: Engine, *, session_id: str, cost_cap_cents: int) -> None:
    """Insert a ``run_manifests`` row up front.

    A halt mid-session must still leave an audit trail. The artefact SHAs
    are placeholders the agents fill in as they resolve their loaders; the
    cost cap is the operator-supplied cents value, captured as-stamped so a
    later replay can detect drift between the configured cap and the
    policy-enforced one.
    """
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO run_manifests ("
                "session_id, target_sha, prompt_set_sha, rubric_set_sha, "
                "attack_library_sha, policy_sha, cost_cap_cents"
                ") VALUES (:sid, :sha, :sha, :sha, :sha, :sha, :cap)"
            ),
            {"sid": session_id, "sha": _PENDING_SHA, "cap": cost_cap_cents},
        )


def _coerce_state(result: Any) -> PlatformState:
    """Adapt LangGraph's ``ainvoke`` return value into a :class:`PlatformState`.

    Across LangGraph versions ``ainvoke`` returns either the Pydantic
    state model directly or a plain ``dict`` that constructs into one.
    We accept both rather than pinning a specific runtime version.
    """
    if isinstance(result, PlatformState):
        return result
    if isinstance(result, dict):
        return PlatformState(**result)
    raise TypeError(f"Unexpected graph result type: {type(result).__name__}")


def _build_summary(
    state: PlatformState,
    *,
    target_alias: str,
    target_url: str,
) -> SessionSummary:
    """Project a :class:`PlatformState` onto a :class:`SessionSummary`."""
    return SessionSummary(
        session_id=state.session_id,
        target_alias=target_alias,
        target_url=target_url,
        campaigns_run=state.campaigns_run,
        cost_so_far_dollars=state.cost_so_far,
        halt_reason=state.halt_reason,
        confirmed_findings=len(state.confirmed_findings),
        attack_records=len(state.attack_records),
        verdict_records=len(state.verdict_records),
    )


def run_session(
    *,
    session_id: str | None = None,
    target_alias: str = DEFAULT_TARGET_ALIAS,
    cost_cap_cents: int = DEFAULT_COST_CAP_CENTS,
    categories: tuple[str, ...] = DEFAULT_CATEGORIES,
    max_campaigns: int = DEFAULT_MAX_CAMPAIGNS,
    env: dict[str, str] | None = None,
    engine: Engine | None = None,
    rng_seed: int | None = None,
    http_client: Any | None = None,
    policy_path: Path | str = Path("orchestrator_policy.yaml"),
) -> SessionSummary:
    """Invoke the production graph end-to-end against ``target_alias``.

    Parameters
    ----------
    session_id:
        Operator-supplied session id. ``None`` (the default) generates a
        fresh ``uuid4`` so repeat invocations never collide on the
        ``run_manifests`` primary key.
    target_alias:
        Alias from ``targets.yaml`` to attack. An unknown alias raises
        :class:`ValueError` from the graph factory.
    cost_cap_cents:
        Hard session-cost ceiling, captured into ``run_manifests``. The
        actual budget enforcement still flows through
        ``orchestrator_policy.yaml``; this value is the operator's
        recorded intent.
    categories:
        Hint for which attack categories the orchestrator should focus on.
        The orchestrator's selection policy does not yet honour this filter
        (Task 27 enumerates from ``rubrics/`` directly). We log the value
        for future grep-ability and pass through.
    max_campaigns:
        Safety cap on the number of orchestrator cycles. Translates to a
        ``recursion_limit`` of ``4 * max_campaigns + 4`` on the compiled
        graph so a runaway orchestrator surfaces as a
        :class:`langgraph.errors.GraphRecursionError` rather than burning
        through the whole budget cap.
    env:
        Environment mapping forwarded to :func:`build_production_graph`.
        Defaults to ``os.environ.copy()`` inside the factory.
    engine:
        Optional caller-owned SQLAlchemy engine. When ``None`` the runner
        creates and disposes its own.
    rng_seed:
        Optional seed for the orchestrator's epsilon-greedy RNG. Lets
        tests pin selection across runs.
    http_client:
        Optional :class:`HTTPTargetClientLike` for the Red Team. Tests
        pass a deterministic fake to avoid live POSTs.
    policy_path:
        Path to ``orchestrator_policy.yaml``. Forwarded to the factory.

    Returns
    -------
    SessionSummary
        Snapshot of the final state. The summary is suitable for
        operator printing and test assertions.

    Raises
    ------
    ValueError
        Unknown ``target_alias`` (propagated from the graph factory).
    RuntimeError
        A stub LLM was invoked because the relevant API key was missing
        (the message mentions the specific env key).
    langgraph.errors.GraphRecursionError
        The graph looped past its recursion limit before any halt rule
        fired. The caller (CLI) maps this to a distinct exit code.
    """
    # TODO(category-filter): the orchestrator currently enumerates rubrics
    # directly; this hint is captured for traceability but does not yet
    # narrow the candidate set. Wire through when the orchestrator grows a
    # category filter parameter.
    _LOGGER.info(
        "starting session target=%s cost_cap_cents=%d categories=%s max_campaigns=%d",
        target_alias,
        cost_cap_cents,
        ",".join(categories),
        max_campaigns,
    )

    resolved_session_id = session_id if session_id is not None else str(uuid.uuid4())
    owns_engine = engine is None
    eng: Engine = engine if engine is not None else create_platform_engine()

    try:
        _insert_manifest(eng, session_id=resolved_session_id, cost_cap_cents=cost_cap_cents)

        rng = random.Random(rng_seed) if rng_seed is not None else None

        # Build the production graph. A bad ``target_alias`` raises
        # ``ValueError`` here before the loop ever spins up.
        app, config = build_production_graph(
            env=env,
            engine=eng,
            rng=rng,
            http_client=http_client,
            target_alias=target_alias,
            policy_path=policy_path,
        )

        initial = PlatformState(session_id=resolved_session_id)

        # ainvoke (not invoke) — every node in the production graph is
        # async, and the synchronous adapter LangGraph offers would block
        # the event loop while awaiting LLM responses. ``asyncio.run`` is
        # the right entry point because the session runner is itself a
        # script-style call site without an existing event loop.
        # Each campaign actually traverses more than the 4-node minimum cycle:
        # the orchestrator can attempt multiple attacks per (category, sub_attack)
        # before switching campaigns, and the doc-agent hop adds one node on
        # passing verdicts. Empirically a campaign uses ~6-10 graph hops, so
        # we budget 20 hops per campaign + 20 head-room. The real safety
        # backstops are the per-session and per-campaign cost caps, not this
        # recursion ceiling — the limit just protects against a logic bug
        # in the routing fns that would otherwise loop forever.
        recursion_limit = 20 * max_campaigns + 20

        # Wall-clock backstop. The orchestrator's cost cap, recursion limit,
        # and per-LLM-call timeouts are all per-step ceilings; none of them
        # bound the WHOLE session if a single async coroutine deadlocks
        # (observed: session 29488fc5 wedged silently for 5+ min between
        # campaigns 5 and 6 — see docs/EVIDENCE/2026-05-13-session-29488fc5/).
        # 30 minutes is well above any normal session at MVP scale (a 75¢
        # session typically runs 8-12 minutes wall-clock; the $10 cap
        # would still finish inside this window with budget headroom).
        # On expiry the dispatcher catches TimeoutError and writes
        # halt_reason="dispatcher_timeout" to the manifest.
        async def _invoke_with_timeout() -> Any:
            return await asyncio.wait_for(
                app.ainvoke(initial, config={"recursion_limit": recursion_limit}),
                timeout=_SESSION_WALL_TIMEOUT_S,
            )

        result = asyncio.run(_invoke_with_timeout())
        final_state = _coerce_state(result)

        return _build_summary(
            final_state,
            target_alias=target_alias,
            target_url=config.target_url,
        )
    finally:
        if owns_engine:
            eng.dispose()
