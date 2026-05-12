"""HTTP-layer request/response models for the operator web UI.

These are deliberately separate from :mod:`agentforge_redteam.state` (the
LangGraph aggregate). ``PlatformState`` is rich and includes per-attack
payloads / target responses that we do not want to ship over the
operator-facing API in bulk; the schemas here are the trimmed, audit-safe
shapes the JSON endpoints actually emit. Keeping them in their own module
also lets the frontend / typed clients import only ``schemas`` without
pulling the database engine plumbing.

Validation here is conservative — for example, ``cost_cap_cents`` is
capped at $1,000 per session so a typo cannot accidentally authorise a
huge spend. The deploy task (Task 48) can tighten further (e.g. lower
the cap per environment) without touching endpoints.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

__all__ = [
    "ApproveRequest",
    "ApproveResponse",
    "CoverageResponse",
    "CoverageRow",
    "FindingDetail",
    "FindingSummary",
    "FindingsResponse",
    "HaltResponse",
    "QueueEntryResponse",
    "QueueResponse",
    "RejectRequest",
    "SessionStatusResponse",
    "StartSessionRequest",
    "StartSessionResponse",
]


class StartSessionRequest(BaseModel):
    """Body for ``POST /sessions/start``.

    ``cost_cap_cents`` is capped at $1,000 per session as a guard against
    operator typos. ``target`` is an alias resolved against
    ``targets.yaml`` by the out-of-band worker; the API does not validate
    the alias here so the worker can give a more useful error if the
    alias has been retired.
    """

    cost_cap_cents: int = Field(gt=0, le=100_000)
    target: str = Field(min_length=1)
    categories: list[str] = Field(min_length=1)


class StartSessionResponse(BaseModel):
    """Body for ``POST /sessions/start``."""

    session_id: str


class SessionStatusResponse(BaseModel):
    """Body for ``GET /sessions/{session_id}``.

    Lightweight summary — full :class:`agentforge_redteam.state.PlatformState`
    is not exposed via the API (too big and includes PII-adjacent fields).
    """

    session_id: str
    campaigns_run: int
    cost_so_far: Decimal
    halt_reason: str | None
    started_at: datetime


class CoverageRow(BaseModel):
    """One denormalised coverage row."""

    category: str
    sub_attack: str
    runs_last_7d: int
    runs_lifetime: int
    findings_by_severity: dict[str, int]
    last_run_at: datetime | None
    avg_cost_cents: int


class CoverageResponse(BaseModel):
    """Body for ``GET /coverage``."""

    rows: list[CoverageRow]


class FindingSummary(BaseModel):
    """One row in ``GET /findings``."""

    finding_id: UUID
    severity: Literal["P0", "P1", "P2", "P3"]
    title: str
    created_at: datetime
    gitlab_issue_id: int | None


class FindingsResponse(BaseModel):
    """Body for ``GET /findings``."""

    findings: list[FindingSummary]


class FindingDetail(BaseModel):
    """Body for ``GET /findings/{finding_id}``."""

    finding_id: UUID
    severity: Literal["P0", "P1", "P2", "P3"]
    title: str
    attack_payload: str
    target_response: str
    # ``rendered_markdown`` is the report template rendered for the finding.
    # For the skeleton, the doc-agent has authoritative inputs (severity
    # rationale, OWASP/MITRE IDs) that are not yet persisted alongside the
    # finding — so the endpoint returns an empty string and the frontend
    # falls back to assembling its own preview. A future task wires this
    # through fully (Task 49+).
    rendered_markdown: str
    created_at: datetime
    gitlab_issue_id: int | None


class QueueEntryResponse(BaseModel):
    """One row in ``GET /queue``."""

    queue_id: UUID
    finding_id: UUID
    severity: str
    title: str
    confidence: float
    created_at: datetime


class QueueResponse(BaseModel):
    """Body for ``GET /queue``."""

    entries: list[QueueEntryResponse]


class HaltResponse(BaseModel):
    """Body for ``POST /halt`` and ``POST /resume``."""

    status: Literal["halted", "running"]


class ApproveRequest(BaseModel):
    """Body for ``POST /queue/{queue_id}/approve``."""

    reviewer: str = Field(min_length=1, max_length=80)


class ApproveResponse(BaseModel):
    """Body for ``POST /queue/{queue_id}/approve``."""

    queue_id: UUID
    finding_id: UUID
    gitlab_issue_id: int
    gitlab_issue_url: str


class RejectRequest(BaseModel):
    """Body for ``POST /queue/{queue_id}/reject``.

    ``category`` is optional because the operator may reject a queue
    entry without converting it to a ground-truth case
    (``write_ground_truth=False``). When ``write_ground_truth=True`` the
    backend enforces the category presence and surfaces a 422 if missing.
    """

    reviewer: str = Field(min_length=1, max_length=80)
    reason: str = Field(min_length=1, max_length=500)
    category: str | None = None
    write_ground_truth: bool = True
