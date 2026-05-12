"""Human approval queue: read, approve, reject.

The Doc Agent (Task 28) routes high-severity or low-confidence findings into
``human_approval_queue`` rather than autofiling them. This module is the
*operator* end of that queue:

* :func:`list_pending` — read the queue joined against the finding's attack
  and verdict so a reviewer sees severity, confidence, and an at-a-glance
  title without ``SELECT``-ing four tables by hand.
* :func:`approve` — flip the queue row to ``approved``, file a real GitLab
  issue, and persist the new ``gitlab_issue_id`` on the finding.
* :func:`reject` — flip the queue row to ``rejected`` and (optionally)
  convert it into a Judge ground-truth case. A rejection is a signal the
  Judge was wrong to flag this verdict; round-tripping it through
  ``ground_truth.write_case`` builds the canary corpus (Task 41) for free.

Design choices worth calling out:

* **Pure module — no Typer imports.** The CLI is the *only* caller that
  knows about argv. Keeping this module Typer-free lets future callers
  (a future web UI, an internal automation script) reuse the same logic.

* **GitLab first, SQLite second in :func:`approve`.** If GitLab fails, we
  want the queue entry to stay ``pending`` so the operator can retry the
  same ``queue_id`` after fixing the credentials. Updating SQLite first
  would leave a dangling ``approved`` queue entry with no issue, which is
  worse than a clean failure.

* **Category is a required parameter on :func:`reject` (when writing
  ground-truth).** We could try to infer it from the verdict's rubric,
  but the rubric_sha doesn't map to a category one-to-one (a sha is per-
  file content, not per-category), and the ``attacks`` table has no
  category column. Forcing the operator to confirm the category is more
  honest than guessing — and the CLI prompts for it interactively when the
  caller doesn't pass it.

* **Only ``pending`` rows are returned from :func:`list_pending` and
  :func:`get_entry`.** An ``approved`` or ``rejected`` row is no longer
  actionable; raising :class:`QueueEntryNotFound` for a non-pending lookup
  also makes idempotency / replay behave correctly (calling ``approve``
  twice on the same ``queue_id`` fails the second time).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Protocol
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Engine

from agentforge_redteam.ground_truth import GroundTruthCase, write_case

__all__ = [
    "DEFAULT_GROUND_TRUTH_ROOT",
    "ApprovalResult",
    "GitLabClientLike",
    "GitLabIssueRefLike",
    "QueueEntryNotFound",
    "QueueEntryView",
    "RejectionResult",
    "approve",
    "get_entry",
    "list_pending",
    "reject",
]

DEFAULT_GROUND_TRUTH_ROOT: Final[Path] = Path("evals/judge_ground_truth")

# The queue title is just the first N characters of the attack payload so a
# ``queue list`` line stays scannable. The full payload is reachable via the
# finding's attack_id in the report renderer.
_TITLE_MAX_CHARS: Final[int] = 80


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class QueueEntryView:
    """One row joined across human_approval_queue, findings, verdicts, attacks.

    ``severity`` is from ``findings`` (the doc agent stamps it during
    routing). ``confidence`` is from the verdict. ``title`` is synthesised —
    the first 80 characters of the attack payload — so a one-line summary
    can be shown without loading the full payload.

    ``created_at`` is the finding's created_at; the queue table does not
    record its own creation timestamp, and the finding is always inserted
    in the same transaction-of-routing, so the two are effectively the
    same instant.
    """

    queue_id: UUID
    finding_id: UUID
    severity: str
    title: str
    confidence: float
    created_at: datetime
    status: str


class QueueEntryNotFound(Exception):
    """Raised when a queue_id doesn't exist or is not pending.

    Used for both "no such row" and "row is no longer actionable" — the
    operator-facing error is the same: this queue_id can't be approved or
    rejected from here.
    """


class GitLabIssueRefLike(Protocol):
    """Structural duck-type for what :meth:`GitLabClientLike.create_issue` returns."""

    @property
    def issue_id(self) -> int: ...
    @property
    def url(self) -> str: ...


class GitLabClientLike(Protocol):
    """Structural duck-type matching the real GitLab client's create_issue."""

    async def create_issue(
        self, *, title: str, body: str, labels: list[str]
    ) -> GitLabIssueRefLike: ...


@dataclass(frozen=True, slots=True)
class ApprovalResult:
    """Returned from :func:`approve` so the CLI can confirm to the operator."""

    queue_id: UUID
    finding_id: UUID
    gitlab_issue_id: int
    gitlab_issue_url: str


@dataclass(frozen=True, slots=True)
class RejectionResult:
    """Returned from :func:`reject`.

    ``ground_truth_path`` is ``None`` when the caller passed
    ``write_ground_truth=False``.
    """

    queue_id: UUID
    finding_id: UUID
    ground_truth_path: Path | None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


_LIST_PENDING_SQL: Final[str] = """
    SELECT
        q.queue_id        AS queue_id,
        q.finding_id      AS finding_id,
        f.severity        AS severity,
        a.payload         AS payload,
        v.confidence      AS confidence,
        f.created_at      AS created_at,
        q.status          AS status
    FROM human_approval_queue AS q
    JOIN findings  AS f ON f.finding_id = q.finding_id
    JOIN verdicts  AS v ON v.verdict_id = f.verdict_id
    JOIN attacks   AS a ON a.attack_id  = f.attack_id
    WHERE q.status = 'pending'
    ORDER BY f.created_at DESC
    LIMIT :limit
"""

_GET_ENTRY_SQL: Final[str] = """
    SELECT
        q.queue_id        AS queue_id,
        q.finding_id      AS finding_id,
        f.severity        AS severity,
        a.payload         AS payload,
        v.confidence      AS confidence,
        f.created_at      AS created_at,
        q.status          AS status
    FROM human_approval_queue AS q
    JOIN findings  AS f ON f.finding_id = q.finding_id
    JOIN verdicts  AS v ON v.verdict_id = f.verdict_id
    JOIN attacks   AS a ON a.attack_id  = f.attack_id
    WHERE q.queue_id = :queue_id
      AND q.status = 'pending'
"""

# Look up the finding's attack/verdict so :func:`reject` can build a
# ground-truth case (it needs the attack payload + target_response).
_LOAD_ATTACK_FOR_QUEUE_SQL: Final[str] = """
    SELECT
        a.payload         AS payload,
        a.target_response AS target_response
    FROM human_approval_queue AS q
    JOIN findings AS f ON f.finding_id = q.finding_id
    JOIN attacks  AS a ON a.attack_id  = f.attack_id
    WHERE q.queue_id = :queue_id
      AND q.status = 'pending'
"""


def _to_datetime(value: object) -> datetime:
    """Coerce SQLite's TEXT-stored timestamp into a tz-aware ``datetime``.

    SQLAlchemy returns ``DateTime`` columns as naive ``datetime`` on SQLite
    because the server_default ``CURRENT_TIMESTAMP`` is naive. We stamp UTC
    on the way out so callers (and tests) can compare against an aware
    ``datetime.now(UTC)`` without worrying about implicit-naive warnings.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    if isinstance(value, str):
        # SQLite CURRENT_TIMESTAMP format: 'YYYY-MM-DD HH:MM:SS'
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            # Fall through to "now" rather than crash list/get — a malformed
            # row should not poison the queue.
            return datetime.now(UTC)
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
    return datetime.now(UTC)


def _row_to_view(row: object) -> QueueEntryView:
    """Convert a SQLAlchemy ``Row`` (with ._mapping) to a :class:`QueueEntryView`."""
    mapping = row._mapping  # type: ignore[attr-defined]
    payload = str(mapping["payload"])
    title = payload[:_TITLE_MAX_CHARS]
    return QueueEntryView(
        queue_id=UUID(str(mapping["queue_id"])),
        finding_id=UUID(str(mapping["finding_id"])),
        severity=str(mapping["severity"]),
        title=title,
        confidence=float(mapping["confidence"]),
        created_at=_to_datetime(mapping["created_at"]),
        status=str(mapping["status"]),
    )


# ---------------------------------------------------------------------------
# Public read API
# ---------------------------------------------------------------------------


def list_pending(engine: Engine, *, limit: int = 100) -> list[QueueEntryView]:
    """Return pending queue entries, newest finding first.

    Caps at ``limit`` rows — even an unattended queue should not blow up
    the operator's terminal. Pagination is a follow-up; until then the
    operator can raise ``--limit`` if needed.
    """
    with engine.connect() as conn:
        rows = conn.execute(text(_LIST_PENDING_SQL), {"limit": limit}).fetchall()
    return [_row_to_view(row) for row in rows]


def get_entry(engine: Engine, *, queue_id: UUID) -> QueueEntryView:
    """Return one pending queue entry by ``queue_id``.

    Raises :class:`QueueEntryNotFound` when the row doesn't exist OR has
    already been approved / rejected. The two cases share an exception
    type because the operator-facing remedy is the same: pick a different
    queue_id.
    """
    with engine.connect() as conn:
        row = conn.execute(
            text(_GET_ENTRY_SQL),
            {"queue_id": str(queue_id)},
        ).first()
    if row is None:
        raise QueueEntryNotFound(f"No pending queue entry for queue_id={queue_id}")
    return _row_to_view(row)


# ---------------------------------------------------------------------------
# Approve
# ---------------------------------------------------------------------------


async def approve(
    engine: Engine,
    *,
    queue_id: UUID,
    reviewer: str,
    gitlab: GitLabClientLike,
    issue_body: str,
    labels: list[str],
) -> ApprovalResult:
    """Mark the queue entry approved, file the issue, persist the issue id.

    Ordering is deliberate: **GitLab first, SQLite second.** If the GitLab
    POST fails (network, bad token, project not found), the queue row
    stays ``pending`` and the operator can retry the same ``queue_id``
    after fixing the credentials. The alternative — flipping SQLite first
    and rolling back on GitLab failure — costs an extra transaction and
    invites a half-applied state if the rollback itself fails.

    The ``issue_body`` and ``labels`` are passed in by the caller (the
    CLI) because the rendered report lives in
    :mod:`agentforge_redteam.report_template`, which has its own contract
    and shouldn't be re-imported here.
    """
    entry = get_entry(engine, queue_id=queue_id)

    issue_ref = await gitlab.create_issue(
        title=entry.title,
        body=issue_body,
        labels=labels,
    )
    gitlab_issue_id = int(issue_ref.issue_id)
    gitlab_issue_url = str(issue_ref.url)

    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE human_approval_queue "
                "SET status = 'approved', "
                "    reviewed_by = :reviewer, "
                "    reviewed_at = :reviewed_at "
                "WHERE queue_id = :queue_id AND status = 'pending'"
            ),
            {
                "reviewer": reviewer,
                "reviewed_at": datetime.now(UTC),
                "queue_id": str(queue_id),
            },
        )
        conn.execute(
            text(
                "UPDATE findings "
                "SET gitlab_issue_id = :gitlab_issue_id "
                "WHERE finding_id = :finding_id"
            ),
            {
                "gitlab_issue_id": gitlab_issue_id,
                "finding_id": str(entry.finding_id),
            },
        )

    return ApprovalResult(
        queue_id=queue_id,
        finding_id=entry.finding_id,
        gitlab_issue_id=gitlab_issue_id,
        gitlab_issue_url=gitlab_issue_url,
    )


# ---------------------------------------------------------------------------
# Reject
# ---------------------------------------------------------------------------


def reject(
    engine: Engine,
    *,
    queue_id: UUID,
    reviewer: str,
    reason: str,
    category: str | None = None,
    write_ground_truth: bool = True,
    ground_truth_root: Path | str = DEFAULT_GROUND_TRUTH_ROOT,
) -> RejectionResult:
    """Mark the queue entry rejected; optionally write a ground-truth case.

    The rejection is the operator's statement that the Judge was wrong to
    flag this finding. Converting it to a ground-truth case
    (``expected_verdict='fail'`` of the *finding* — i.e., the attack should
    not have produced a finding) feeds the canary harness (Task 41) and
    the Judge accuracy gate without any extra operator step.

    ``category`` is required when ``write_ground_truth=True``. We could try
    to infer it from the verdict's ``rubric_sha`` (which is a per-file
    content hash) — but rubrics may evolve, two files can have the same
    sha at different times, and the source-of-truth for category is the
    campaign that ran the attack, not a row currently in our schema. The
    cleaner contract is: the operator confirms the category.
    """
    if write_ground_truth and category is None:
        raise ValueError(
            "category is required when write_ground_truth=True. "
            "Pass --skip-ground-truth to reject without writing a case."
        )

    entry = get_entry(engine, queue_id=queue_id)

    ground_truth_path: Path | None = None
    if write_ground_truth:
        # Pull the attack payload + target_response *before* we flip the
        # status so the FK joins still find a pending row. The transaction
        # below atomically marks rejected; we do not need to hold a row
        # lock between the read and the write because the queue entry's
        # ``status`` field is what the CLI re-reads on retry.
        with engine.connect() as conn:
            row = conn.execute(
                text(_LOAD_ATTACK_FOR_QUEUE_SQL),
                {"queue_id": str(queue_id)},
            ).first()
        if row is None:  # pragma: no cover — get_entry would have raised
            raise QueueEntryNotFound(f"No pending queue entry for queue_id={queue_id}")
        mapping = row._mapping
        # ``category is None`` was guarded above when write_ground_truth=True.
        assert category is not None  # invariant established above
        case = GroundTruthCase(
            category=category,
            attack_input=str(mapping["payload"]),
            target_response=str(mapping["target_response"]),
            expected_verdict="fail",
            confidence=1.0,
            rubric_outcomes={},
            notes=f"Human-rejected. Reason: {reason}",
        )
        ground_truth_path = write_case(case, root=ground_truth_root)

    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE human_approval_queue "
                "SET status = 'rejected', "
                "    reviewed_by = :reviewer, "
                "    reviewed_at = :reviewed_at "
                "WHERE queue_id = :queue_id AND status = 'pending'"
            ),
            {
                "reviewer": reviewer,
                "reviewed_at": datetime.now(UTC),
                "queue_id": str(queue_id),
            },
        )

    return RejectionResult(
        queue_id=queue_id,
        finding_id=entry.finding_id,
        ground_truth_path=ground_truth_path,
    )
