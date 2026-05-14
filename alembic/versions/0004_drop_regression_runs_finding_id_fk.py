"""drop FK constraint on regression_runs.finding_id

Revision ID: 0004
Revises: 0003
Create Date: 2026-05-13

The original schema (0001) declared
``regression_runs.finding_id REFERENCES findings(finding_id)``. This made
sense when regression replays only ran on the same DB that produced the
finding. But promoted regression cases live in ``evals/regressions/`` as
the source of truth, decoupled from any specific DB. A clean checkout
running ``agentforge-redteam regress`` against a fresh ``var/platform.db``
has zero ``findings`` rows — every replay's ``INSERT INTO regression_runs``
trips the FK and aborts.

Audit-level reproduction:
    $ uv run agentforge-redteam regress --target-sha audit-check --root evals/regressions
    ... regression.case_failed error='(sqlite3.IntegrityError) FOREIGN KEY constraint failed
    ...
    held=0 regressed=6  # all 6 cases counted as regressed because the INSERT failed

Fix: drop the FK. The ``finding_id`` column stays as a non-NULL TEXT (so
historical results stay queryable by finding_id), but it no longer requires
a matching row in ``findings``. Semantically: "this regression run was for
finding X (in some DB)" rather than "finding X must exist locally."

Idempotency + downgrade safety mirrors 0002 / 0003: PRAGMA user_version
sentinel + introspection-based skip if the constraint is already absent.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | Sequence[str] | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Bit flag in PRAGMA user_version reserved for this migration. 0x1 was
# claimed by 0002, 0x2 by 0003; this migration claims 0x4.
_FLAG_DROPPED_FK = 0x4


def _has_fk_to_findings() -> bool:
    """Return True iff ``regression_runs.finding_id`` still has the FK
    referencing ``findings.finding_id``."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    fks = inspector.get_foreign_keys("regression_runs")
    return any(
        fk.get("referred_table") == "findings"
        and fk.get("constrained_columns") == ["finding_id"]
        for fk in fks
    )


def _get_user_version() -> int:
    bind = op.get_bind()
    if bind.dialect.name != "sqlite":
        return 0
    return int(bind.execute(sa.text("PRAGMA user_version")).scalar() or 0)


def _set_user_version(value: int) -> None:
    bind = op.get_bind()
    if bind.dialect.name != "sqlite":
        return
    bind.execute(sa.text(f"PRAGMA user_version = {int(value)}"))


def upgrade() -> None:
    """Drop the FK on ``regression_runs.finding_id`` (idempotent)."""
    if not _has_fk_to_findings():
        # FK already absent (fresh DB created from the post-0004 metadata,
        # or a hand-edit, or already-rolled-forward branch).
        return
    # SQLite cannot DROP CONSTRAINT in place — batch_alter_table copies
    # the table without the constraint and renames it back. The
    # ``finding_id`` column itself stays.
    with op.batch_alter_table("regression_runs", recreate="always") as batch_op:
        batch_op.drop_constraint("fk_regression_runs_finding_id_findings", type_="foreignkey")
    _set_user_version(_get_user_version() | _FLAG_DROPPED_FK)


def downgrade() -> None:
    """Re-add the FK only if this migration dropped it."""
    flags = _get_user_version()
    if not (flags & _FLAG_DROPPED_FK):
        return
    if _has_fk_to_findings():
        _set_user_version(flags & ~_FLAG_DROPPED_FK)
        return
    with op.batch_alter_table("regression_runs", recreate="always") as batch_op:
        batch_op.create_foreign_key(
            "fk_regression_runs_finding_id_findings",
            "findings",
            ["finding_id"],
            ["finding_id"],
            ondelete=None,
        )
    _set_user_version(flags & ~_FLAG_DROPPED_FK)
