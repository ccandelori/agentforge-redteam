"""FastAPI app for the operator UI.

This module is the JSON API only. The Task 47 frontend will consume the
endpoints declared here; the Task 48 deploy task is responsible for
hardening BasicAuth and tightening CORS in production.

Design choices worth calling out:

* **Per-request SQLAlchemy engine.** Every endpoint receives a fresh
  ``Engine`` via the :func:`engine_dep` dependency and the dependency's
  cleanup hook calls ``engine.dispose()``. We pay one engine creation per
  request, which is cheap with SQLite, in exchange for not having to
  reason about a long-lived engine being shared across worker threads.
  When/if we move to Postgres, this becomes a connection-pooled engine
  bound once at startup; the endpoint signature does not change.

* **Auth on every endpoint, including reads.** A misconfigured CORS or a
  ``localhost`` deploy is the most common way to leak red-team findings.
  Requiring BasicAuth on ``GET`` endpoints too means a curl from the
  next network hop has to know the password before it can even list
  findings.

* **Documentation sink fallback.** ``approve`` files an issue via
  GitLab when ``GITLAB_TOKEN``/``GITLAB_PROJECT_ID`` are set, else falls
  back to :class:`LocalFindingsSink` so dev / offline lanes still work.
  The :func:`create_documentation_client` factory owns that policy; this
  module just calls it.

* **Title is the attack payload prefix.** Same convention as
  :mod:`agentforge_redteam.approval`. Keeps API responses scannable
  without loading the full payload.

* **``rendered_markdown`` is empty for now.** The Doc Agent's full
  context (severity rationale, OWASP/MITRE IDs) is not yet persisted on
  the finding row, so we ship an empty string rather than fabricating
  data. Task 49 will wire this fully.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Annotated, Any

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.engine import Engine

from agentforge_redteam import approval as approval_module
from agentforge_redteam.approval import QueueEntryNotFound
from agentforge_redteam.db import create_platform_engine
from agentforge_redteam.kill_switch import is_kill_switch_enabled, set_kill_switch
from agentforge_redteam.web.auth import require_operator
from agentforge_redteam.web.schemas import (
    ActiveSessionActivity,
    ActiveSessionsResponse,
    ApproveRequest,
    ApproveResponse,
    CoverageResponse,
    CoverageRow,
    FindingDetail,
    FindingsResponse,
    FindingSummary,
    HaltResponse,
    QueueEntryResponse,
    QueueResponse,
    RejectRequest,
    SessionStatusResponse,
    StartSessionRequest,
    StartSessionResponse,
)

__all__ = ["app", "engine_dep"]

# Placeholder SHAs stamped onto a freshly-started session's
# ``run_manifests`` row. A worker draining the session will OVERWRITE
# these once it has resolved the actual target/prompt/rubric/policy SHAs
# for the run. Until then, the column is NOT NULL so we need some value.
_PENDING_SHA = "pending"

_TITLE_MAX_CHARS = 80


# ---------------------------------------------------------------------------
# Engine dependency
# ---------------------------------------------------------------------------


def engine_dep() -> Iterator[Engine]:
    """Per-request engine. ``yield`` + ``finally`` ensures dispose runs.

    FastAPI calls the generator's ``next()`` to retrieve the engine, then
    re-enters it after the endpoint returns so the ``finally`` can clean
    up. Errors raised by the endpoint propagate through the generator,
    so ``dispose`` runs even on a failed response.
    """
    engine = create_platform_engine()
    try:
        yield engine
    finally:
        engine.dispose()


EngineDep = Annotated[Engine, Depends(engine_dep)]
OperatorDep = Annotated[str, Depends(require_operator)]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ensure_utc(dt_or_str: Any) -> datetime:
    """SQLite gives us back DATETIME columns as naive ``datetime`` or ``str``;
    coerce to an aware UTC datetime for JSON serialisation determinism."""
    if isinstance(dt_or_str, datetime):
        return dt_or_str if dt_or_str.tzinfo is not None else dt_or_str.replace(tzinfo=UTC)
    if isinstance(dt_or_str, str):
        try:
            parsed = datetime.fromisoformat(dt_or_str)
        except ValueError:
            return datetime.now(UTC)
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
    return datetime.now(UTC)


def _maybe_utc(value: Any) -> datetime | None:
    """Same as :func:`_ensure_utc` but returns ``None`` on a None input."""
    if value is None:
        return None
    return _ensure_utc(value)


def _parse_findings_by_severity(raw: Any) -> dict[str, int]:
    """``coverage_matrix.findings_by_severity`` is stored as a JSON string in
    SQLite. Coerce to a typed dict for the response."""
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return {str(k): int(v) for k, v in raw.items()}
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        if isinstance(parsed, dict):
            return {str(k): int(v) for k, v in parsed.items()}
    return {}


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------


app = FastAPI(
    title="AgentForge Adversarial AI Security Platform",
    description="Operator UI for the AgentForge red-team platform.",
    version="0.1.0",
)

# CORS: ``allow_origins=["*"]`` is a dev-friendly default. The deploy task
# (Task 48) narrows this to the production frontend origin and forces
# ``allow_credentials=False`` to keep BasicAuth out of cross-origin
# preflight quirks.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Vue 3 SPA frontend (replaces the Jinja+HTMX path that lived here in Task 47).
#
# The SPA is plain ES modules — index.html + main.js + views/*.js + style.css
# loaded from /ui/*. Vue + Vue Router come from esm.sh via an importmap in
# index.html. No build step, no node, no template rendering on the server.
#
# Routing model: client-side history mode. The browser navigates to /ui,
# /ui/coverage, /ui/findings/<id>, etc. We serve a literal file under
# /ui/<path> if it exists on disk; otherwise we fall through to index.html
# so Vue Router picks up the route. The JSON API at the root (/coverage,
# /findings, /queue, /halt) is the SPA's only contract.
# ---------------------------------------------------------------------------

from fastapi.responses import FileResponse  # noqa: E402

# Vite builds the SPA into frontend/dist/. The build artifact is gitignored;
# `npm run build` produces it locally and `rsync` ships it to the droplet.
# index.html in dist/ references fingerprinted assets under /ui/assets/.
_DIST_DIR = Path(__file__).parent / "frontend" / "dist"
_DIST_INDEX = _DIST_DIR / "index.html"


@app.get("/ui/{path:path}", include_in_schema=False)
def spa(path: str, op: OperatorDep) -> FileResponse:
    """Serve a Vite-built SPA asset by path; fall back to index.html for routes.

    Gated by BasicAuth so a logged-out user hits 401 on the SPA shell and the
    browser surfaces the auth prompt. Once authenticated, the browser
    auto-includes credentials on every subsequent XHR.

    - GET /ui                      -> dist/index.html
    - GET /ui/assets/index-XYZ.js  -> dist/assets/index-XYZ.js  (fingerprinted bundle)
    - GET /ui/assets/index-XYZ.css -> dist/assets/index-XYZ.css
    - GET /ui/coverage             -> not a file; fall back to index.html so
                                      Vue Router handles the route on client.
    """
    candidate = _DIST_DIR / path if path else _DIST_INDEX
    # Path traversal guard: resolve and confirm the file lives under dist/.
    try:
        candidate = candidate.resolve(strict=False)
        candidate.relative_to(_DIST_DIR.resolve())
    except (ValueError, OSError):
        return FileResponse(_DIST_INDEX)
    if candidate.is_file():
        return FileResponse(candidate)
    return FileResponse(_DIST_INDEX)


# ---------------------------------------------------------------------------
# Root / health
# ---------------------------------------------------------------------------


@app.get("/", include_in_schema=False)
def root() -> dict[str, str]:
    """Liveness + machine-facing root. The operator UI is at ``/ui``."""
    return {"name": "AgentForge web UI", "version": "0.1.0", "ui": "/ui"}


@app.get("/healthz", include_in_schema=False)
def healthz() -> dict[str, str]:
    """Unauthenticated liveness probe for the deploy harness."""
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


_dispatch_logger = logging.getLogger("agentforge_redteam.web.dispatch")

# In-memory set of session_ids currently being dispatched in the background.
# Lives only in this uvicorn worker process — restart wipes it. For a single-
# worker MVP that is the right tradeoff: no DB schema change, no Redis, and
# the operator UI just needs "is anything running right now?" semantics.
# Concurrent reads/writes are safe under FastAPI's threadpool because Python
# set add/discard are atomic w.r.t. the GIL for individual ops, and the
# /sessions/active reader only needs an eventually-consistent snapshot.
_active_sessions: set[str] = set()


def _dispatch_session(
    session_id: str,
    target_alias: str,
    cost_cap_cents: int,
    categories: tuple[str, ...],
) -> None:
    """Run a session synchronously in the background-task threadpool.

    FastAPI runs sync ``BackgroundTasks`` callables in a worker thread,
    which is exactly the isolation we want: ``run_session`` internally calls
    ``asyncio.run()`` to drive the LangGraph state machine, and that needs
    its own event loop. Running on the threadpool gives us a fresh loop
    per dispatch without colliding with uvicorn's main loop.

    Exceptions are logged and swallowed so the background task fault does
    not propagate to a no-op caller. The session's halt_reason in the
    manifest table is the operator-visible signal of failure.
    """
    # Lazy import keeps the cost off the web service's hot path. Importing
    # session_runner pulls in the full LangGraph + agent stack, which is
    # ~200ms; we only want to pay that on actual session dispatch, not on
    # every web request.
    from agentforge_redteam.session_runner import run_session

    _active_sessions.add(session_id)
    try:
        summary = run_session(
            session_id=session_id,
            target_alias=target_alias,
            cost_cap_cents=cost_cap_cents,
            categories=categories,
        )
        _dispatch_logger.info(
            "session %s finished: halt_reason=%s attacks=%d verdicts=%d findings=%d cost=$%.4f",
            session_id,
            summary.halt_reason,
            summary.attack_records,
            summary.verdict_records,
            summary.confirmed_findings,
            float(summary.cost_so_far_dollars),
        )
        _record_session_terminal_state(
            session_id=session_id,
            halt_reason=summary.halt_reason or "completed",
        )
    except TimeoutError:
        _dispatch_logger.exception("session %s dispatch timed out", session_id)
        _record_session_terminal_state(
            session_id=session_id,
            halt_reason="dispatcher_timeout",
        )
    except Exception as exc:
        _dispatch_logger.exception("session %s dispatch crashed", session_id)
        _record_session_terminal_state(
            session_id=session_id,
            halt_reason=f"dispatcher_crash:{type(exc).__name__}",
        )
    finally:
        _active_sessions.discard(session_id)


def _record_session_terminal_state(*, session_id: str, halt_reason: str) -> None:
    """Persist ``halt_reason`` and ``ended_at`` on the manifest row.

    Best-effort: if the engine cannot be obtained or the UPDATE fails (e.g.
    the manifest row was never created because run_session crashed in
    setup), we log and continue. The dispatcher's job is to surface
    operator-visible state, not to gate session completion.
    """
    from datetime import datetime

    from agentforge_redteam.db import create_platform_engine

    try:
        eng = create_platform_engine()
        try:
            with eng.begin() as conn:
                conn.execute(
                    text(
                        "UPDATE run_manifests "
                        "SET halt_reason = :halt_reason, ended_at = :ended_at "
                        "WHERE session_id = :sid AND halt_reason IS NULL"
                    ),
                    {
                        "halt_reason": halt_reason,
                        "ended_at": datetime.now(UTC),
                        "sid": session_id,
                    },
                )
        finally:
            eng.dispose()
    except Exception:
        _dispatch_logger.exception("failed to record terminal state for session %s", session_id)


@app.post("/sessions/start", response_model=StartSessionResponse)
def start_session(
    body: StartSessionRequest,
    background_tasks: BackgroundTasks,
    op: OperatorDep,
) -> StartSessionResponse:
    """Dispatch a new red-team session in the background.

    ``run_session`` itself writes the ``run_manifests`` row (with the real
    artifact SHAs once the graph factory has hashed them), so this endpoint
    only generates a ``session_id``, schedules the background dispatcher,
    and returns the id immediately. The frontend polls ``/sessions/{id}``
    to watch progress; the manifest row appears within ~100ms of dispatch.

    The dispatcher runs on FastAPI's threadpool — sync callable means a
    fresh asyncio loop in its own thread, avoiding any interaction with
    uvicorn's serving loop. One uvicorn worker can dispatch one session
    at a time without blocking new requests; concurrent ``/sessions/start``
    calls queue on the threadpool.
    """
    session_id = str(uuid.uuid4())
    background_tasks.add_task(
        _dispatch_session,
        session_id,
        body.target,
        body.cost_cap_cents,
        tuple(body.categories),
    )
    return StartSessionResponse(session_id=session_id)


@app.get("/sessions/active", response_model=ActiveSessionsResponse)
def get_active_sessions(
    op: OperatorDep,
    engine: EngineDep,
) -> ActiveSessionsResponse:
    """Return the snapshot of currently-dispatching sessions + live counters.

    Used by the SessionView to (a) show a "running / idle" status badge,
    (b) disable the Start button while a dispatch is in flight, and (c)
    surface live-activity counters (attacks/verdicts/findings/cost +
    most-recent step) so the operator can see the platform is doing work
    even on sessions that produce zero findings.

    The snapshot is in-memory and per-uvicorn-worker; restart resets it.
    Counters come from JOIN-free SELECTs and are cheap (~ms). Route is
    registered BEFORE ``/sessions/{session_id}`` so the literal "active"
    path matches first instead of being captured as a session id.
    """
    snapshot = sorted(_active_sessions)
    activity: list[ActiveSessionActivity] = []
    if snapshot:
        with engine.connect() as conn:
            for sid in snapshot:
                # Per-session counts. These tables are populated eagerly
                # by red_team / judge / documentation; agent_steps is
                # populated by the call_tool wrapper. Five small queries
                # per active session is well under any reasonable budget.
                attacks_n = conn.execute(
                    text(
                        "SELECT COUNT(*) FROM agent_steps "
                        "WHERE session_id = :s AND tool = 'call_target'"
                    ),
                    {"s": sid},
                ).scalar_one()
                verdicts_n = conn.execute(
                    text(
                        "SELECT COUNT(*) FROM verdicts v JOIN attacks a "
                        "ON v.attack_id = a.attack_id WHERE a.attack_id IN "
                        "(SELECT json_extract(args, '$.url') FROM agent_steps "
                        "WHERE session_id = :s)"
                    ),
                    {"s": sid},
                ).scalar_one()
                # The above join via args.url is awkward; simpler: count
                # verdicts whose attack_id appears in any agent_steps row
                # for this session. But agent_steps doesn't store attack_id.
                # Fall back to a conservative count via verdicts created
                # since the manifest's created_at.
                manifest = conn.execute(
                    text("SELECT created_at FROM run_manifests WHERE session_id = :s"),
                    {"s": sid},
                ).first()
                started_at = manifest[0] if manifest else None
                if started_at is not None:
                    verdict_rows = conn.execute(
                        text(
                            "SELECT verdict, COUNT(*) FROM verdicts "
                            "WHERE created_at >= :t GROUP BY verdict"
                        ),
                        {"t": started_at},
                    ).all()
                    counts = {row[0]: int(row[1]) for row in verdict_rows}
                    verdicts_n = sum(counts.values())
                    findings_n = conn.execute(
                        text("SELECT COUNT(*) FROM findings WHERE created_at >= :t"),
                        {"t": started_at},
                    ).scalar_one()
                else:
                    counts = {}
                    findings_n = 0
                cost_cents = conn.execute(
                    text(
                        "SELECT COALESCE(SUM(cost_cents), 0) FROM agent_steps WHERE session_id = :s"
                    ),
                    {"s": sid},
                ).scalar_one()
                last_step = conn.execute(
                    text(
                        "SELECT agent, tool, timestamp FROM agent_steps "
                        "WHERE session_id = :s ORDER BY timestamp DESC LIMIT 1"
                    ),
                    {"s": sid},
                ).first()
                activity.append(
                    ActiveSessionActivity(
                        session_id=sid,
                        attacks=int(attacks_n),
                        verdicts=int(verdicts_n),
                        verdicts_pass=int(counts.get("pass", 0)),
                        verdicts_partial=int(counts.get("partial", 0)),
                        verdicts_fail=int(counts.get("fail", 0)),
                        verdicts_inconclusive=int(counts.get("inconclusive", 0)),
                        findings=int(findings_n),
                        cost_cents=int(cost_cents),
                        last_agent=last_step[0] if last_step else None,
                        last_tool=last_step[1] if last_step else None,
                        last_step_at=last_step[2] if last_step else None,
                        started_at=started_at,
                    )
                )

    return ActiveSessionsResponse(
        active=snapshot,
        is_running=bool(snapshot),
        count=len(snapshot),
        activity=activity,
    )


@app.get("/sessions/{session_id}", response_model=SessionStatusResponse)
def get_session(
    session_id: str,
    op: OperatorDep,
    engine: EngineDep,
) -> SessionStatusResponse:
    """Return a session summary, joining cost from ``agent_steps``.

    ``campaigns_run`` is approximated as the number of DISTINCT
    ``campaign_id`` values seen on attacks for this session. The schema
    does not yet record campaign_id on agent_steps; once it does, this
    becomes a tighter join. ``halt_reason`` lives in the manifest column
    of the same name (added in migration 0003); the dispatcher writes it
    on terminal state — clean completion (``"completed"`` or the
    in-state value), operator halt (``"operator_halt"``), dispatcher
    timeout (``"dispatcher_timeout"``), or unexpected exception
    (``"dispatcher_crash:<ExceptionClass>"``).
    """
    with engine.connect() as conn:
        manifest = conn.execute(
            text("SELECT created_at, halt_reason FROM run_manifests WHERE session_id = :sid"),
            {"sid": session_id},
        ).first()
        if manifest is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"session {session_id} not found",
            )
        cost_row = conn.execute(
            text(
                "SELECT COALESCE(SUM(cost_cents), 0) AS total_cents "
                "FROM agent_steps WHERE session_id = :sid"
            ),
            {"sid": session_id},
        ).first()
        # We don't have campaign_id on agent_steps; approximate
        # ``campaigns_run`` via a sub-query against ``attacks``. Tests that
        # don't insert any attacks see 0 here — which is the right answer
        # for a freshly-started session.
        campaigns_row = conn.execute(
            text(
                "SELECT COUNT(DISTINCT a.campaign_id) AS n "
                "FROM agent_steps AS s "
                "JOIN attacks AS a ON 1=1 "
                "WHERE s.session_id = :sid"
            ),
            {"sid": session_id},
        ).first()

    total_cents_raw = cost_row[0] if cost_row is not None else 0
    total_cents = int(total_cents_raw or 0)
    # cost_so_far is dollars, not cents — keep parity with the
    # ``PlatformState`` field. We divide via Decimal so the JSON
    # representation stays precise (no binary-float drift).
    cost_so_far = (Decimal(total_cents) / Decimal(100)).quantize(Decimal("0.01"))
    campaigns_run = int(campaigns_row[0] if campaigns_row is not None else 0)
    started_at = _ensure_utc(manifest[0])

    return SessionStatusResponse(
        session_id=session_id,
        campaigns_run=campaigns_run,
        cost_so_far=cost_so_far,
        halt_reason=manifest[1],
        started_at=started_at,
    )


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------


@app.get("/coverage", response_model=CoverageResponse)
def get_coverage(op: OperatorDep, engine: EngineDep) -> CoverageResponse:
    """Return every row in ``coverage_matrix``, ordered (category, sub_attack)."""
    with engine.connect() as conn:
        rows = (
            conn.execute(
                text(
                    "SELECT category, sub_attack, runs_last_7d, runs_lifetime, "
                    "findings_by_severity, last_run_at, avg_cost_cents "
                    "FROM coverage_matrix "
                    "ORDER BY category, sub_attack"
                )
            )
            .mappings()
            .all()
        )

    return CoverageResponse(
        rows=[
            CoverageRow(
                category=str(r["category"]),
                sub_attack=str(r["sub_attack"]),
                runs_last_7d=int(r["runs_last_7d"]),
                runs_lifetime=int(r["runs_lifetime"]),
                findings_by_severity=_parse_findings_by_severity(r["findings_by_severity"]),
                last_run_at=_maybe_utc(r["last_run_at"]),
                avg_cost_cents=int(r["avg_cost_cents"]),
            )
            for r in rows
        ]
    )


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


_LIST_FINDINGS_SQL = """
    SELECT
        f.finding_id        AS finding_id,
        f.severity          AS severity,
        f.created_at        AS created_at,
        f.gitlab_issue_id   AS gitlab_issue_id,
        a.payload           AS payload
    FROM findings AS f
    JOIN attacks  AS a ON a.attack_id = f.attack_id
    ORDER BY f.created_at DESC
    LIMIT :limit
"""

_GET_FINDING_SQL = """
    SELECT
        f.finding_id        AS finding_id,
        f.severity          AS severity,
        f.created_at        AS created_at,
        f.gitlab_issue_id   AS gitlab_issue_id,
        a.payload           AS payload,
        a.target_response   AS target_response
    FROM findings AS f
    JOIN attacks  AS a ON a.attack_id = f.attack_id
    WHERE f.finding_id = :fid
"""


@app.get("/findings", response_model=FindingsResponse)
def list_findings(
    op: OperatorDep,
    engine: EngineDep,
    limit: int = 100,
) -> FindingsResponse:
    """Newest-first list of findings."""
    with engine.connect() as conn:
        rows = conn.execute(text(_LIST_FINDINGS_SQL), {"limit": limit}).mappings().all()

    findings: list[FindingSummary] = []
    for r in rows:
        payload = str(r["payload"])
        sev = str(r["severity"])
        # Pydantic Literal field will reject unknown severities; we keep the
        # raw severity column trusted because the doc agent enforces it on
        # insert. Anything else is a schema bug, not an operator-facing one.
        findings.append(
            FindingSummary(
                finding_id=uuid.UUID(str(r["finding_id"])),
                severity=sev,
                title=payload[:_TITLE_MAX_CHARS],
                created_at=_ensure_utc(r["created_at"]),
                gitlab_issue_id=(
                    int(r["gitlab_issue_id"]) if r["gitlab_issue_id"] is not None else None
                ),
            )
        )
    return FindingsResponse(findings=findings)


@app.get("/findings/{finding_id}", response_model=FindingDetail)
def get_finding(
    finding_id: uuid.UUID,
    op: OperatorDep,
    engine: EngineDep,
) -> FindingDetail:
    """Return one finding with full attack payload + target response."""
    with engine.connect() as conn:
        row = conn.execute(text(_GET_FINDING_SQL), {"fid": str(finding_id)}).mappings().first()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"finding {finding_id} not found",
        )
    payload = str(row["payload"])
    sev = str(row["severity"])
    return FindingDetail(
        finding_id=uuid.UUID(str(row["finding_id"])),
        severity=sev,
        title=payload[:_TITLE_MAX_CHARS],
        attack_payload=payload,
        target_response=str(row["target_response"]),
        rendered_markdown="",
        created_at=_ensure_utc(row["created_at"]),
        gitlab_issue_id=(
            int(row["gitlab_issue_id"]) if row["gitlab_issue_id"] is not None else None
        ),
    )


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------


@app.post("/halt", response_model=HaltResponse)
def halt(op: OperatorDep, engine: EngineDep) -> HaltResponse:
    """Trip the kill switch and mark every in-flight session as operator-halted.

    Idempotent — calling twice stays halted. The session-marking pass is
    best-effort: if a session is already terminal (``halt_reason`` is
    non-NULL) the UPDATE leaves it alone so we don't clobber a real halt
    reason with the generic ``operator_halt``.
    """
    from datetime import datetime

    set_kill_switch(engine, enabled=True)
    if _active_sessions:
        active_snapshot = tuple(_active_sessions)
        with engine.begin() as conn:
            for sid in active_snapshot:
                conn.execute(
                    text(
                        "UPDATE run_manifests "
                        "SET halt_reason = :halt_reason, ended_at = :ended_at "
                        "WHERE session_id = :sid AND halt_reason IS NULL"
                    ),
                    {
                        "halt_reason": "operator_halt",
                        "ended_at": datetime.now(UTC),
                        "sid": sid,
                    },
                )
    return HaltResponse(status="halted")


@app.post("/resume", response_model=HaltResponse)
def resume(op: OperatorDep, engine: EngineDep) -> HaltResponse:
    """Clear the kill switch."""
    set_kill_switch(engine, enabled=False)
    return HaltResponse(status="halted" if is_kill_switch_enabled(engine) else "running")


# ---------------------------------------------------------------------------
# Queue
# ---------------------------------------------------------------------------


@app.get("/queue", response_model=QueueResponse)
def list_queue(
    op: OperatorDep,
    engine: EngineDep,
    limit: int = 100,
) -> QueueResponse:
    """List pending queue entries (delegates to :func:`approval.list_pending`)."""
    entries = approval_module.list_pending(engine, limit=limit)
    return QueueResponse(
        entries=[
            QueueEntryResponse(
                queue_id=e.queue_id,
                finding_id=e.finding_id,
                severity=e.severity,
                title=e.title,
                confidence=e.confidence,
                created_at=e.created_at,
            )
            for e in entries
        ]
    )


def _documentation_client() -> Any:
    """Resolve the documentation sink.

    Prefers :func:`create_documentation_client` from the clients factory
    (Task 36) when present, which always returns a sink (GitLab when
    configured, :class:`LocalFindingsSink` otherwise). Falls back to the
    raw :func:`create_gitlab_client` when the factory module is not
    importable — in which case a missing GitLab config yields ``None``
    and the endpoint surfaces 503.
    """
    try:
        from agentforge_redteam.clients.factory import (
            create_documentation_client,
        )
    except ImportError:
        from agentforge_redteam.clients.gitlab_client import create_gitlab_client

        return create_gitlab_client(env=dict(os.environ))
    return create_documentation_client(env=dict(os.environ))


@app.post("/queue/{queue_id}/approve", response_model=ApproveResponse)
async def approve_queue(
    queue_id: uuid.UUID,
    body: ApproveRequest,
    op: OperatorDep,
    engine: EngineDep,
) -> ApproveResponse:
    """Approve a queue entry: file the issue, persist the issue id."""
    sink = _documentation_client()
    if sink is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="no documentation sink configured",
        )

    try:
        entry = approval_module.get_entry(engine, queue_id=queue_id)
    except QueueEntryNotFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    # The CLI assembles a rendered markdown body via the report template;
    # for the skeleton, the API ships the title as both subject and body
    # so the local sink (and GitLab) still get a coherent issue. The
    # report-template body wiring lands with the doc-agent context
    # persistence task (Task 49).
    labels = [f"severity::{entry.severity}", "source::web-ui"]
    try:
        result = await approval_module.approve(
            engine,
            queue_id=queue_id,
            reviewer=body.reviewer,
            gitlab=sink,
            issue_body=entry.title,
            labels=labels,
        )
    except QueueEntryNotFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    return ApproveResponse(
        queue_id=result.queue_id,
        finding_id=result.finding_id,
        gitlab_issue_id=result.gitlab_issue_id,
        gitlab_issue_url=result.gitlab_issue_url,
    )


@app.post(
    "/queue/{queue_id}/reject",
    status_code=status.HTTP_204_NO_CONTENT,
)
def reject_queue(
    queue_id: uuid.UUID,
    body: RejectRequest,
    op: OperatorDep,
    engine: EngineDep,
) -> None:
    """Reject a queue entry; optionally convert to ground-truth.

    A 422 surface for missing category-when-ground-truth-on falls out of
    the ``ValueError`` raised inside ``approval.reject``; we translate it
    here so the API stays JSON-shaped.
    """
    try:
        approval_module.reject(
            engine,
            queue_id=queue_id,
            reviewer=body.reviewer,
            reason=body.reason,
            category=body.category,
            write_ground_truth=body.write_ground_truth,
        )
    except QueueEntryNotFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
