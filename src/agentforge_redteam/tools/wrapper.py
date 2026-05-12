"""Audited tool wrapper — the single point of trust for audit completeness.

Every tool call that any agent (Red Team, Judge, Orchestrator, Documentation)
makes routes through :func:`call_tool`. The wrapper provides the following
HIPAA-evidentiary guarantees, in order:

1. **Kill switch first.** Before any other side effect, the wrapper consults
   the ``kill_switch`` singleton row. If the flag is on, the wrapper raises
   :class:`~agentforge_redteam.kill_switch.KillSwitchTripped` without writing
   an ``agent_steps`` row. The contract is that a tripped switch means *no
   tool calls happen at all*, including no audit insert that might suggest
   the call was attempted.

2. **Open the audit row.** A new ``agent_steps`` row is inserted before the
   tool runs, capturing the (agent, tool, args, session_id) tuple. The row
   is initially marked with ``result=NULL`` and ``cost_cents=0``,
   ``latency_ms=0``. This insert happens in its own short transaction so
   the wrapper does not hold a DB lock across the (potentially slow) tool
   call.

3. **Start a Langfuse span** (optional). If a Langfuse-shaped client is
   supplied, the wrapper starts a span using ``step_id`` as both the span
   name and trace id so SQLite and Langfuse join cleanly later. The wrapper
   depends only on a :class:`Protocol`, so the real ``langfuse`` package is
   not imported here — tests stub it with a plain class.

4. **Execute the tool.** Async tools (coroutine functions) are awaited;
   plain callables are invoked directly. ``args`` is splatted as kwargs.
   Latency is measured via :func:`time.perf_counter`.

5. **Close the audit row in a ``finally`` block.** Whether the tool
   succeeded, raised, or produced a value that fails JSON serialization,
   the wrapper UPDATEs the ``agent_steps`` row with whatever it knows
   (result envelope or exception envelope, cost, latency). If the tool
   raised, the exception is re-raised *after* the row update so callers
   see the original exception while the audit log remains complete.

6. **Return ``(result, step_id, cost_cents, latency_ms)``** as a
   :class:`ToolCallResult` on success.

Non-PHI logging only. The wrapper never logs raw ``args`` or ``result``
payloads (they may contain attack payloads or target responses); it logs
only the step id, agent, tool name, and outcome.
"""

from __future__ import annotations

import inspect
import json
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol

import structlog
from sqlalchemy import text
from sqlalchemy.engine import Engine

from agentforge_redteam.kill_switch import KillSwitchTripped, is_kill_switch_enabled

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Langfuse-shaped protocols
# ---------------------------------------------------------------------------
#
# We deliberately do NOT import ``langfuse`` here. The real client is wired in
# a later task; tests stub these protocols with a tiny fake. Keeping the
# wrapper independent of the Langfuse package means the audit-write path
# stays runnable in environments where Langfuse isn't installed (e.g. unit
# tests, offline CI lanes).


class LangfuseSpanLike(Protocol):
    """Subset of the Langfuse span API the wrapper depends on."""

    def update(
        self,
        *,
        output: Any = None,
        level: str | None = None,
        status_message: str | None = None,
    ) -> None: ...

    def end(self) -> None: ...


class LangfuseClientLike(Protocol):
    """Subset of the Langfuse client API the wrapper depends on."""

    def span(
        self,
        *,
        name: str,
        trace_id: str | None = None,
        input: Any = None,
        metadata: dict[str, Any] | None = None,
    ) -> LangfuseSpanLike: ...


# ---------------------------------------------------------------------------
# Return type
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ToolCallResult:
    """The wrapper's success return value.

    Carries the tool's raw result, the audit-row primary key (``step_id``),
    and the recorded ``cost_cents`` / ``latency_ms`` so the caller can join
    against the database or report the figures upstream without re-reading.
    """

    result: Any
    step_id: str
    cost_cents: int
    latency_ms: int


# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------


def _safe_json_dumps(value: Any) -> str:
    """Serialise ``value`` to JSON, falling back to a structured envelope.

    Tools may return objects that are not JSON-serialisable by default
    (Decimals, UUIDs, datetimes, custom dataclasses). We first try a strict
    dump with ``default=str`` to coerce common stringy types. If even that
    fails (e.g. a circular reference), we store a structured error envelope
    so the audit row is never NULL on the result column for a successfully
    executed tool, and the caller-side bug becomes visible at the DB layer.
    """
    try:
        return json.dumps(value, default=str)
    except (TypeError, ValueError) as exc:
        logger.warning(
            "tool_wrapper.result_not_json_serializable",
            error=str(exc),
            value_type=type(value).__name__,
        )
        return json.dumps(
            {
                "error": "result_not_json_serializable",
                "repr": repr(value)[:500],
            }
        )


def _exception_envelope(exc: BaseException) -> str:
    """Serialise an exception into the JSON envelope stored on a failed row."""
    return json.dumps(
        {
            "error": type(exc).__name__,
            "message": str(exc),
        }
    )


# ---------------------------------------------------------------------------
# Audit row I/O
# ---------------------------------------------------------------------------


def _insert_step_row(
    engine: Engine,
    *,
    step_id: str,
    agent: str,
    tool_name: str,
    args: dict[str, Any],
    session_id: str,
) -> None:
    """Insert the initial (open) ``agent_steps`` row in its own transaction."""
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO agent_steps "
                "(step_id, agent, tool, args, result, cost_cents, latency_ms, session_id) "
                "VALUES (:step_id, :agent, :tool, :args, NULL, 0, 0, :session_id)"
            ),
            {
                "step_id": step_id,
                "agent": agent,
                "tool": tool_name,
                "args": json.dumps(args, default=str),
                "session_id": session_id,
            },
        )


def _update_step_row(
    engine: Engine,
    *,
    step_id: str,
    result_json: str,
    cost_cents: int,
    latency_ms: int,
) -> None:
    """Close the ``agent_steps`` row with the final result/cost/latency."""
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE agent_steps "
                "SET result = :result, cost_cents = :cost_cents, latency_ms = :latency_ms "
                "WHERE step_id = :step_id"
            ),
            {
                "result": result_json,
                "cost_cents": cost_cents,
                "latency_ms": latency_ms,
                "step_id": step_id,
            },
        )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def call_tool(
    *,
    agent: str,
    tool_name: str,
    tool: Callable[..., Awaitable[Any]] | Callable[..., Any],
    args: dict[str, Any],
    session_id: str,
    engine: Engine,
    langfuse: LangfuseClientLike | None = None,
    cost_estimator: Callable[[Any], int] | None = None,
) -> ToolCallResult:
    """Run ``tool`` under the audit wrapper.

    See the module docstring for the full contract. In one line: kill-switch
    check → open audit row → start span → run tool → close audit row in
    ``finally`` → end span in ``finally`` → re-raise on tool exception.
    """
    # ---- 1. Kill switch first. -------------------------------------------
    if is_kill_switch_enabled(engine):
        logger.warning(
            "tool_wrapper.kill_switch_tripped",
            agent=agent,
            tool=tool_name,
            session_id=session_id,
        )
        raise KillSwitchTripped(agent=agent, tool_name=tool_name)

    # ---- 2. Open the audit row. ------------------------------------------
    step_id = str(uuid.uuid4())
    _insert_step_row(
        engine,
        step_id=step_id,
        agent=agent,
        tool_name=tool_name,
        args=args,
        session_id=session_id,
    )
    logger.info(
        "tool_wrapper.start",
        agent=agent,
        tool=tool_name,
        step_id=step_id,
        session_id=session_id,
    )

    # ---- 3. Start Langfuse span (if provided). ---------------------------
    span: LangfuseSpanLike | None = None
    if langfuse is not None:
        span = langfuse.span(
            name=step_id,
            trace_id=step_id,
            input=args,
            metadata={"agent": agent, "tool": tool_name, "session_id": session_id},
        )

    # ---- 4. Execute the tool, capturing result OR exception. -------------
    t_start = time.perf_counter()
    raised: BaseException | None = None
    result: Any = None

    try:
        if inspect.iscoroutinefunction(tool):
            result = await tool(**args)
        else:
            maybe = tool(**args)
            # Defensive: a non-``iscoroutinefunction`` callable may still
            # return an awaitable (e.g. ``functools.partial`` over an async
            # function, or a wrapper class with ``__call__``). Await it if
            # so, otherwise treat it as a sync result.
            if inspect.isawaitable(maybe):
                result = await maybe
            else:
                result = maybe
    except BaseException as exc:
        raised = exc

    t_end = time.perf_counter()
    latency_ms = round((t_end - t_start) * 1000)

    # ---- 5. Determine result envelope and cost. --------------------------
    cost_cents: int = 0
    result_json: str
    if raised is None:
        result_json = _safe_json_dumps(result)
        if cost_estimator is not None:
            try:
                cost_cents = int(cost_estimator(result))
            except Exception as cost_exc:
                logger.warning(
                    "tool_wrapper.cost_estimator_failed",
                    error=str(cost_exc),
                    error_type=type(cost_exc).__name__,
                    step_id=step_id,
                )
                cost_cents = 0
    else:
        result_json = _exception_envelope(raised)

    # ---- 6. Close the audit row + end span in finally semantics. ---------
    #
    # We are no longer inside a try block (the tool call's try/except
    # already finished, capturing ``raised``). The write below must still
    # happen unconditionally, *before* we re-raise — so we run it inline
    # and guard it with its own try/finally to make absolutely sure the
    # Langfuse span ends even if the DB write itself fails.
    try:
        _update_step_row(
            engine,
            step_id=step_id,
            result_json=result_json,
            cost_cents=cost_cents,
            latency_ms=latency_ms,
        )
    finally:
        if span is not None:
            if raised is not None:
                span.update(level="ERROR", status_message=str(raised))
            else:
                span.update(output=result)
            span.end()

    if raised is not None:
        logger.error(
            "tool_wrapper.tool_raised",
            agent=agent,
            tool=tool_name,
            step_id=step_id,
            error_type=type(raised).__name__,
            latency_ms=latency_ms,
        )
        raise raised

    logger.info(
        "tool_wrapper.end",
        agent=agent,
        tool=tool_name,
        step_id=step_id,
        latency_ms=latency_ms,
        cost_cents=cost_cents,
    )
    return ToolCallResult(
        result=result,
        step_id=step_id,
        cost_cents=cost_cents,
        latency_ms=latency_ms,
    )
