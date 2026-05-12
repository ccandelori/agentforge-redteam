"""Session-scoped Langfuse helpers.

Langfuse groups traces into "sessions" via a ``session_id`` attribute
on each trace. The full nesting story (orchestrator-level trace ->
per-campaign span -> per-tool span via the audit wrapper) is wired in
the follow-up graph-integration task; this module provides the thin
context-manager primitive that the orchestrator will use to bound a
session and to guarantee best-effort flush on exit.

Design notes:

* **Flush is best-effort.** Langfuse outages must NOT crash the
  orchestrator at session end. We swallow every exception coming out
  of ``client.flush()`` and log it via :mod:`structlog` so it shows
  up in the structured log without breaking the call path.

* **The context manager does NOT currently start a Langfuse trace.**
  The Protocol exposed in :mod:`agentforge_redteam.tools.wrapper`
  intentionally only contains ``.span(...)``; trace nesting is the
  follow-up wiring task's job. For now, "session" means "a flush
  boundary keyed by an explicit :class:`SessionContext` value". The
  ``session_id`` field is plumbed through to per-tool spans via the
  audit wrapper's ``metadata`` argument already, so traces still
  cluster correctly in the Langfuse UI today.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

import structlog

from agentforge_redteam.observability.langfuse_client import LangfuseClientLike

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Session value object
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SessionContext:
    """Identifies one orchestrator session for Langfuse session grouping.

    ``session_id`` is the same UUID stored on
    :class:`agentforge_redteam.state.PlatformState.session_id` and on
    every ``agent_steps.session_id`` row, so traces in Langfuse can be
    joined back to the SQLite audit log by a simple equality predicate.

    ``user_id`` and ``metadata`` are optional Langfuse-side enrichments
    — kept here as plain fields so the follow-up task can lift them
    straight onto the trace when nesting is wired.
    """

    session_id: str
    user_id: str | None = None
    metadata: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Context manager
# ---------------------------------------------------------------------------


@contextmanager
def langfuse_session(
    client: LangfuseClientLike,
    *,
    session: SessionContext,
) -> Iterator[None]:
    """Run a block inside a Langfuse session boundary.

    On exit (success or exception), the client's ``flush()`` method is
    invoked best-effort. A Langfuse outage at flush time must not
    propagate out of the context manager — we log and swallow.

    The session value is captured in the structured log envelope so an
    operator can correlate "flush failed" entries with the session_id
    of the campaign that was running at the time.
    """
    logger.info(
        "langfuse.session.enter",
        session_id=session.session_id,
        user_id=session.user_id,
    )
    try:
        yield
    finally:
        flusher = getattr(client, "flush", None)
        if callable(flusher):
            try:
                flusher()
            except Exception as exc:
                # Best-effort: Langfuse being down must not crash the
                # orchestrator at session end. The audit log in SQLite
                # is the system of record; Langfuse is the
                # human-readable mirror, and a missed flush only loses
                # the *trace* — never the durable audit row.
                logger.warning(
                    "langfuse.session.flush_failed",
                    session_id=session.session_id,
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
        logger.info(
            "langfuse.session.exit",
            session_id=session.session_id,
        )
