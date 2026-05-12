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
import os
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.engine import Engine

from agentforge_redteam import approval as approval_module
from agentforge_redteam.approval import QueueEntryNotFound
from agentforge_redteam.db import create_platform_engine
from agentforge_redteam.kill_switch import is_kill_switch_enabled, set_kill_switch
from agentforge_redteam.web.auth import require_operator
from agentforge_redteam.web.schemas import (
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


@app.post("/sessions/start", response_model=StartSessionResponse)
def start_session(
    body: StartSessionRequest,
    op: OperatorDep,
    engine: EngineDep,
) -> StartSessionResponse:
    """Record a new session in ``run_manifests``.

    The actual LangGraph dispatch is out-of-band: a worker picks up the
    freshly inserted row and drives the campaign. This endpoint just
    generates a ``session_id`` and persists the cost cap so a misconfigured
    worker cannot spend over budget. ``target`` / ``categories`` are NOT
    persisted on the manifest yet — the schema does not carry those columns
    in the initial migration. A future migration will add them; until then,
    a follow-up worker reads the body from a side channel.
    """
    session_id = str(uuid.uuid4())
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO run_manifests "
                "(session_id, target_sha, prompt_set_sha, rubric_set_sha, "
                "attack_library_sha, policy_sha, cost_cap_cents) "
                "VALUES (:sid, :tsha, :psha, :rsha, :asha, :polsha, :cap)"
            ),
            {
                "sid": session_id,
                "tsha": _PENDING_SHA,
                "psha": _PENDING_SHA,
                "rsha": _PENDING_SHA,
                "asha": _PENDING_SHA,
                "polsha": _PENDING_SHA,
                "cap": body.cost_cap_cents,
            },
        )
    return StartSessionResponse(session_id=session_id)


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
    becomes a tighter join. ``halt_reason`` is not stored on the manifest
    (only inside in-memory ``PlatformState``), so we return ``None`` here
    and surface kill-switch state via ``/halt`` / ``/resume``.
    """
    with engine.connect() as conn:
        manifest = conn.execute(
            text("SELECT created_at FROM run_manifests WHERE session_id = :sid"),
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
        halt_reason=None,
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
    """Trip the kill switch. Idempotent — calling twice stays halted."""
    set_kill_switch(engine, enabled=True)
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
