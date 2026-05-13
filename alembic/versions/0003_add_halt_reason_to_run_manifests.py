"""add halt_reason + ended_at columns to run_manifests

Revision ID: 0003
Revises: 0002
Create Date: 2026-05-13

Persist the operator-visible terminal state of a session on the manifest
row. Until this migration, ``halt_reason`` lived only inside in-memory
``PlatformState`` and was lost when the session ended; ``GET
/sessions/{id}`` hardcoded ``halt_reason: null`` because there was nowhere
to read from. After this migration, the dispatcher writes the column on
clean completion, on operator halt, on dispatcher timeout, and on
unexpected exception — so a wedged session post-mortem is no longer
silent.

``ended_at`` lands alongside ``halt_reason`` because the only useful
question after a halt is "what was the halt reason and when did it end?"
Both nullable: in-flight sessions have ``halt_reason IS NULL AND
ended_at IS NULL``, terminal sessions have both populated.

Idempotency + downgrade safety
------------------------------
Mirrors the pattern in ``0002_add_prompt_sha_to_verdicts.py``: if the
columns already exist (from a dev branch), upgrade is a no-op and the
sentinel is not set, so downgrade leaves the schema alone. If this
migration adds them, the sentinel is set and downgrade drops them.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | Sequence[str] | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Bit flag in PRAGMA user_version reserved for this migration. 0x1 was
# claimed by 0002; this migration claims 0x2.
_FLAG_ADDED_HALT_COLS = 0x2


def _has_column(table: str, column: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    cols = [c["name"] for c in inspector.get_columns(table)]
    return column in cols


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
    """Add ``run_manifests.halt_reason`` and ``run_manifests.ended_at`` (idempotent)."""
    has_halt = _has_column("run_manifests", "halt_reason")
    has_ended = _has_column("run_manifests", "ended_at")
    if has_halt and has_ended:
        return
    with op.batch_alter_table("run_manifests", recreate="auto") as batch_op:
        if not has_halt:
            batch_op.add_column(sa.Column("halt_reason", sa.Text(), nullable=True))
        if not has_ended:
            batch_op.add_column(sa.Column("ended_at", sa.DateTime(), nullable=True))
    _set_user_version(_get_user_version() | _FLAG_ADDED_HALT_COLS)


def downgrade() -> None:
    """Drop the columns only if this migration added them."""
    flags = _get_user_version()
    if not (flags & _FLAG_ADDED_HALT_COLS):
        return
    has_halt = _has_column("run_manifests", "halt_reason")
    has_ended = _has_column("run_manifests", "ended_at")
    if not (has_halt or has_ended):
        _set_user_version(flags & ~_FLAG_ADDED_HALT_COLS)
        return
    with op.batch_alter_table("run_manifests", recreate="auto") as batch_op:
        if has_halt:
            batch_op.drop_column("halt_reason")
        if has_ended:
            batch_op.drop_column("ended_at")
    _set_user_version(flags & ~_FLAG_ADDED_HALT_COLS)
