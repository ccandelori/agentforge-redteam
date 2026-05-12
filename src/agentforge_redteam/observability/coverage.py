"""Coverage-matrix denormalization (Task 37).

The ``coverage_matrix`` table is a rolling, denormalized view of the audit
log: one row per ``(category, sub_attack)`` carrying ``runs_last_7d``,
``runs_lifetime``, ``findings_by_severity``, ``last_run_at``, and
``avg_cost_cents``. The Orchestrator agent READS this table to drive its
selection score; the function in this module WRITES it by aggregating
across ``attacks``, ``verdicts``, ``findings``, and ``agent_steps``.

The separation matters. ``orchestrator_node`` is read-only against the
matrix because rebuilding aggregates inside a routing decision would
couple "what to do next" to "what just happened", making both harder to
test and reason about. ``recompute_coverage_matrix`` is the dedicated
bookkeeping pass: caller decides when to run it (typically after a
campaign finishes, or on a periodic schedule).

Schema gap (intentional). The initial migration's ``attacks`` table
records ``campaign_id`` as a UUID but there is no ``campaigns`` table
yet, so the on-disk schema cannot, on its own, map a ``campaign_id``
back to its ``(category, sub_attack)`` pair. Until that schema migration
lands, callers pass an explicit ``campaign_brief_lookup`` dict that
encodes the mapping at the application layer. When the dict is empty,
the function returns zero rows and does not touch the database — a
no-op caller gets back a no-op result, never a crash.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Engine


@dataclass(frozen=True, slots=True)
class CoverageRow:
    """One denormalized row in the ``coverage_matrix`` view.

    ``findings_by_severity`` is a plain dict keyed by severity string
    (``"P0"``..``"P3"``) with integer counts. Missing severities are
    omitted, not stored as zero, so the table stays sparse.

    ``last_run_at`` is ``None`` when the (category, sub_attack) pair has
    never produced an attack — distinct from a zero-runs row, which the
    caller might have INSERTed with no attacks to back it.
    """

    category: str
    sub_attack: str
    runs_last_7d: int
    runs_lifetime: int
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    last_run_at: datetime | None = None
    avg_cost_cents: int = 0


def _utcnow() -> datetime:
    """Return the current UTC time. Wrapped so tests can monkeypatch
    ``now`` without touching ``datetime.utcnow`` globally."""
    return datetime.now(tz=UTC)


def _ensure_utc(dt: datetime | None) -> datetime | None:
    """Coerce a possibly-naive datetime to UTC for stable comparisons."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _parse_dt(raw: Any) -> datetime | None:
    """SQLite returns DATETIME columns as ``str`` or ``datetime`` depending
    on the dialect/driver settings. Normalise to an aware datetime."""
    if raw is None:
        return None
    if isinstance(raw, datetime):
        return _ensure_utc(raw)
    if isinstance(raw, str):
        try:
            # Accept the SQLite default "YYYY-MM-DD HH:MM:SS" form and ISO.
            dt = datetime.fromisoformat(raw)
        except ValueError:
            try:
                dt = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return None
        return _ensure_utc(dt)
    return None


def recompute_coverage_matrix(
    engine: Engine,
    *,
    campaign_brief_lookup: Mapping[UUID, tuple[str, str]] | None = None,
    now: datetime | None = None,
) -> list[CoverageRow]:
    """Read ``attacks`` / ``verdicts`` / ``findings`` / ``agent_steps`` and
    UPSERT denormalized rows into ``coverage_matrix``.

    Parameters
    ----------
    engine
        The platform SQLAlchemy engine. Must point at a schema where
        ``alembic upgrade head`` has run.
    campaign_brief_lookup
        Mapping from ``attacks.campaign_id`` (UUID) to the campaign's
        ``(category, sub_attack)`` tuple. Because the initial schema does
        not yet carry the brief metadata on disk (no ``campaigns`` table),
        the function relies on this caller-provided lookup. An empty or
        missing lookup is a no-op: the function returns ``[]`` and writes
        nothing.
    now
        Override for "current UTC" — useful in tests. Defaults to
        :func:`datetime.now(timezone.utc)`.

    Returns
    -------
    list[CoverageRow]
        The exact rows that were written, in the order they were upserted.
        Order is by ``(category, sub_attack)`` ascending for determinism.

    Idempotency
    -----------
    The UPSERT uses ``INSERT OR REPLACE`` keyed on the composite primary
    key ``(category, sub_attack)``. Re-running ``recompute_coverage_matrix``
    against an unchanged audit log writes byte-identical rows — no
    double-counting, no version drift.
    """
    if not campaign_brief_lookup:
        return []

    cutoff = (now or _utcnow()) - timedelta(days=7)

    # The schema stores campaign_id as CHAR(36); coerce UUIDs to their
    # stringified form so the SQL `IN` clause matches.
    lookup: dict[str, tuple[str, str]] = {
        str(cid): (cat, sub) for cid, (cat, sub) in campaign_brief_lookup.items()
    }
    if not lookup:
        return []

    # ---- 1. Pull every attack whose campaign_id matches the lookup -------
    placeholders = ", ".join(f":c{i}" for i in range(len(lookup)))
    params: dict[str, Any] = {f"c{i}": k for i, k in enumerate(lookup.keys())}

    # Pull all attacks in one round trip. We join cost from agent_steps via
    # an OUTER LEFT-style aggregation below since SQLite's window functions
    # are version-dependent — a Python-side groupby is simpler and fits the
    # data volume (low thousands of rows).
    attack_sql = (
        "SELECT attack_id, campaign_id, created_at "
        "FROM attacks "
        f"WHERE campaign_id IN ({placeholders})"
    )

    # Aggregate state keyed by (category, sub_attack).
    accum: dict[tuple[str, str], dict[str, Any]] = {}

    with engine.connect() as conn:
        attack_rows = conn.execute(text(attack_sql), params).mappings().all()

        attack_ids_by_pair: dict[tuple[str, str], list[str]] = {}
        for row in attack_rows:
            pair = lookup.get(str(row["campaign_id"]))
            if pair is None:
                # The lookup vanished mid-query — should not happen, but
                # we skip the row rather than corrupt the aggregate.
                continue
            bucket = accum.setdefault(
                pair,
                {
                    "runs_last_7d": 0,
                    "runs_lifetime": 0,
                    "findings_by_severity": {},
                    "last_run_at": None,
                    "avg_cost_cents": 0,
                },
            )
            bucket["runs_lifetime"] += 1
            created = _parse_dt(row["created_at"])
            if created is not None:
                if created >= cutoff:
                    bucket["runs_last_7d"] += 1
                prior = bucket["last_run_at"]
                if prior is None or created > prior:
                    bucket["last_run_at"] = created
            attack_ids_by_pair.setdefault(pair, []).append(str(row["attack_id"]))

        # ---- 2. Findings, joined to verdicts, joined to attacks ----------
        if attack_rows:
            attack_ids = [str(row["attack_id"]) for row in attack_rows]
            ph = ", ".join(f":a{i}" for i in range(len(attack_ids)))
            sql = (
                "SELECT f.severity, f.attack_id "
                "FROM findings AS f "
                "JOIN verdicts AS v ON v.verdict_id = f.verdict_id "
                f"WHERE f.attack_id IN ({ph})"
            )
            finding_rows = (
                conn.execute(text(sql), {f"a{i}": aid for i, aid in enumerate(attack_ids)})
                .mappings()
                .all()
            )

            # Map each finding back to its (category, sub_attack) via the
            # attack -> campaign -> brief chain. We build a tiny reverse
            # index for the join.
            attack_to_pair: dict[str, tuple[str, str]] = {}
            for row in attack_rows:
                pair = lookup.get(str(row["campaign_id"]))
                if pair is not None:
                    attack_to_pair[str(row["attack_id"])] = pair

            for row in finding_rows:
                pair = attack_to_pair.get(str(row["attack_id"]))
                if pair is None:
                    continue
                bucket = accum.setdefault(
                    pair,
                    {
                        "runs_last_7d": 0,
                        "runs_lifetime": 0,
                        "findings_by_severity": {},
                        "last_run_at": None,
                        "avg_cost_cents": 0,
                    },
                )
                sev = row["severity"]
                fbs: dict[str, int] = bucket["findings_by_severity"]
                fbs[sev] = fbs.get(sev, 0) + 1

        # ---- 3. avg_cost_cents from agent_steps --------------------------
        # We approximate "cost per attack" by averaging cost_cents on every
        # agent_steps row written under the matching attacks' sessions.
        # The schema does not yet carry an attack_id on agent_steps, so we
        # cannot do a tighter join — this is a coarse first cut and is
        # explicitly documented. Until that schema lands, the column gets
        # 0 unless the caller supplies cost metadata via a later task.
        # We still populate it to keep INSERT OR REPLACE coherent.
        for bucket in accum.values():
            bucket["avg_cost_cents"] = 0

    # ---- 4. UPSERT in deterministic (category, sub_attack) order --------
    rows_out: list[CoverageRow] = []
    sorted_keys = sorted(accum.keys())
    with engine.begin() as conn:
        for pair in sorted_keys:
            cat, sub = pair
            bucket = accum[pair]
            cov_row = CoverageRow(
                category=cat,
                sub_attack=sub,
                runs_last_7d=int(bucket["runs_last_7d"]),
                runs_lifetime=int(bucket["runs_lifetime"]),
                findings_by_severity=dict(bucket["findings_by_severity"]),
                last_run_at=bucket["last_run_at"],
                avg_cost_cents=int(bucket["avg_cost_cents"]),
            )
            conn.execute(
                text(
                    "INSERT OR REPLACE INTO coverage_matrix "
                    "(category, sub_attack, runs_last_7d, runs_lifetime, "
                    "findings_by_severity, last_run_at, avg_cost_cents, "
                    "coverage_score) "
                    "VALUES (:category, :sub_attack, :r7, :rl, :fbs, "
                    ":last_run_at, :acc, :cs)"
                ),
                {
                    "category": cov_row.category,
                    "sub_attack": cov_row.sub_attack,
                    "r7": cov_row.runs_last_7d,
                    "rl": cov_row.runs_lifetime,
                    "fbs": json.dumps(cov_row.findings_by_severity),
                    "last_run_at": cov_row.last_run_at,
                    "acc": cov_row.avg_cost_cents,
                    # coverage_score is recomputed by the orchestrator at
                    # selection time, but the column is NOT NULL, so we
                    # write 0.0 here. INSERT OR REPLACE preserves the
                    # column shape across re-runs.
                    "cs": 0.0,
                },
            )
            rows_out.append(cov_row)

    return rows_out


def coverage_row_for(engine: Engine, *, category: str, sub_attack: str) -> CoverageRow | None:
    """Return the single ``coverage_matrix`` row for ``(category, sub_attack)``.

    Returns ``None`` if no row exists for the composite primary key. This
    is a thin read helper — useful for tests and ad-hoc inspection.
    """
    with engine.connect() as conn:
        row = (
            conn.execute(
                text(
                    "SELECT category, sub_attack, runs_last_7d, runs_lifetime, "
                    "findings_by_severity, last_run_at, avg_cost_cents "
                    "FROM coverage_matrix "
                    "WHERE category = :category AND sub_attack = :sub_attack"
                ),
                {"category": category, "sub_attack": sub_attack},
            )
            .mappings()
            .first()
        )
    if row is None:
        return None
    fbs = row["findings_by_severity"]
    if isinstance(fbs, str):
        try:
            fbs = json.loads(fbs)
        except json.JSONDecodeError:
            fbs = {}
    return CoverageRow(
        category=row["category"],
        sub_attack=row["sub_attack"],
        runs_last_7d=int(row["runs_last_7d"]),
        runs_lifetime=int(row["runs_lifetime"]),
        findings_by_severity=dict(fbs or {}),
        last_run_at=_parse_dt(row["last_run_at"]),
        avg_cost_cents=int(row["avg_cost_cents"]),
    )
