"""add prompt_sha column to verdicts

Revision ID: 0002
Revises: 0001
Create Date: 2026-05-12

Persist the SHA-256 of the loaded Judge prompt alongside every verdict so
verdicts are fully reproducible per ``(rubric_sha, model_version, prompt_sha)``.

Why nullable, not NOT NULL?
---------------------------
Existing verdict rows (from earlier dev / demo seeds prior to this column
landing in production schemas) cannot supply a real prompt_sha — and SQLite
cannot ALTER TABLE ADD COLUMN with NOT NULL + default in one shot anyway.
We add ``prompt_sha`` as nullable here; a follow-up migration will tighten
to NOT NULL once historic rows are backfilled.

Idempotency + downgrade safety
------------------------------
Some dev branches landed the ``prompt_sha`` column directly in the initial
schema (revision ``0001``) while it was still being scoped. To keep this
migration safe in every starting state, ``upgrade`` introspects the live
table and only ADD COLUMN when ``prompt_sha`` is absent.

``downgrade`` uses a sentinel row written at upgrade time to know whether
*this migration* added the column. If 0001 already provides ``prompt_sha``,
the sentinel is never written and the downgrade is a strict no-op so the
schema 0001 promised remains intact when rolling back 0002 → 0001.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: str | Sequence[str] | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Sentinel marker stored in SQLite ``user_version`` PRAGMA so a future
# ``downgrade`` knows whether *this* migration added the column. We use
# a 32-bit bit flag (bit 1 = "0002 added prompt_sha") so future migrations
# can layer their own flags without colliding.
_FLAG_ADDED_PROMPT_SHA = 0x1


def _has_prompt_sha_column() -> bool:
    """Return True if the live ``verdicts`` table already has ``prompt_sha``."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    cols = [c["name"] for c in inspector.get_columns("verdicts")]
    return "prompt_sha" in cols


def _get_user_version() -> int:
    bind = op.get_bind()
    if bind.dialect.name != "sqlite":
        return 0
    return int(bind.execute(sa.text("PRAGMA user_version")).scalar() or 0)


def _set_user_version(value: int) -> None:
    bind = op.get_bind()
    if bind.dialect.name != "sqlite":
        return
    # PRAGMA user_version doesn't accept bind params; integer is safe here.
    bind.execute(sa.text(f"PRAGMA user_version = {int(value)}"))


def upgrade() -> None:
    """Add ``verdicts.prompt_sha`` as nullable TEXT (idempotent)."""
    if _has_prompt_sha_column():
        # Column already present from an earlier dev iteration — nothing to do.
        # We deliberately do NOT set the sentinel: this migration didn't add
        # the column, so downgrade must not drop it.
        return
    # SQLite cannot ALTER TABLE ADD COLUMN with NOT NULL + default in one shot.
    # Add as nullable first; a future migration tightens to NOT NULL once
    # historic rows are backfilled. Existing rows get NULL.
    with op.batch_alter_table("verdicts", recreate="auto") as batch_op:
        batch_op.add_column(sa.Column("prompt_sha", sa.Text(), nullable=True))
    # Record that we added it so downgrade knows to drop it.
    _set_user_version(_get_user_version() | _FLAG_ADDED_PROMPT_SHA)


def downgrade() -> None:
    """Drop ``verdicts.prompt_sha`` only if this migration added it."""
    flags = _get_user_version()
    if not (flags & _FLAG_ADDED_PROMPT_SHA):
        # Either the column was provided by 0001 (sentinel never set) or it
        # was already absent — either way, leave the schema alone.
        return
    if not _has_prompt_sha_column():
        # Sentinel says we added it but column is gone — already rolled back.
        _set_user_version(flags & ~_FLAG_ADDED_PROMPT_SHA)
        return
    with op.batch_alter_table("verdicts", recreate="auto") as batch_op:
        batch_op.drop_column("prompt_sha")
    _set_user_version(flags & ~_FLAG_ADDED_PROMPT_SHA)
