"""Tests for the Alembic initial schema migration (revision 0001).

Each test gets a *fresh* SQLite database under ``tmp_path`` so the real
``var/platform.db`` is never touched. We configure the Alembic Config in code
(rather than mutating env vars) so the tests are hermetic and parallel-safe.

The fixture also exposes a per-test SQLAlchemy ``Engine`` because most assertions
need to issue raw SQL (the platform doesn't have an ORM layer yet — the
migration is the source of truth for the schema).
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError

REPO_ROOT = Path(__file__).resolve().parents[2]
ALEMBIC_INI = REPO_ROOT / "alembic.ini"
ALEMBIC_DIR = REPO_ROOT / "alembic"

EXPECTED_TABLES = {
    "agent_steps",
    "attacks",
    "verdicts",
    "findings",
    "regression_runs",
    "coverage_matrix",
    "run_manifests",
    "kill_switch",
    "human_approval_queue",
}

EXPECTED_INDEXES = {
    "ix_attacks_campaign_id",
    "ix_attacks_target_sha",
    "ix_verdicts_attack_id",
    "ix_findings_attack_id",
    "ix_findings_verdict_id",
    "ix_regression_runs_finding_id",
    "ix_regression_runs_target_sha",
    "ix_agent_steps_session_timestamp",
    "ix_human_approval_queue_status",
}


def _make_alembic_config(db_path: Path) -> Config:
    """Build an Alembic Config that targets a tmp SQLite file."""
    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("script_location", str(ALEMBIC_DIR))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    return cfg


@pytest.fixture
def alembic_upgraded_db(tmp_path: Path) -> Iterator[Engine]:
    """Yield an Engine pointed at a fresh DB with ``alembic upgrade head`` run.

    Foreign keys are enabled per-connection by the env.py listener so FK
    constraint tests behave the way they would in production.
    """
    db_path = tmp_path / "platform.db"
    cfg = _make_alembic_config(db_path)
    command.upgrade(cfg, "head")
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        yield engine
    finally:
        engine.dispose()


def test_upgrade_creates_all_nine_tables(alembic_upgraded_db: Engine) -> None:
    """``upgrade head`` must produce the nine declared application tables."""
    with alembic_upgraded_db.connect() as conn:
        rows = conn.execute(
            sa.text(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%' "
                "AND name != 'alembic_version'"
            )
        ).fetchall()
    actual = {row[0] for row in rows}
    assert actual == EXPECTED_TABLES


def test_downgrade_base_drops_all_application_tables(tmp_path: Path) -> None:
    """``downgrade base`` from head must leave only alembic_version."""
    db_path = tmp_path / "platform.db"
    cfg = _make_alembic_config(db_path)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")

    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        with engine.connect() as conn:
            rows = conn.execute(
                sa.text(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            ).fetchall()
        remaining = {row[0] for row in rows}
        # downgrade leaves the alembic version table; nothing of ours should remain
        assert remaining.isdisjoint(EXPECTED_TABLES)
    finally:
        engine.dispose()


def test_kill_switch_seeded_with_singleton_row(alembic_upgraded_db: Engine) -> None:
    """The migration must seed exactly one ``(id=1, enabled=0)`` row."""
    with alembic_upgraded_db.connect() as conn:
        rows = conn.execute(sa.text("SELECT id, enabled FROM kill_switch")).fetchall()
    assert len(rows) == 1
    assert rows[0][0] == 1
    # SQLite stores BOOLEAN as INTEGER 0/1; accept either falsy form.
    assert rows[0][1] in (0, False)


def test_kill_switch_check_constraint_rejects_non_singleton(
    alembic_upgraded_db: Engine,
) -> None:
    """The CHECK ``id = 1`` must reject any insert with a different id."""
    with alembic_upgraded_db.begin() as conn, pytest.raises(IntegrityError):
        conn.execute(sa.text("INSERT INTO kill_switch (id, enabled) VALUES (2, 0)"))


def test_foreign_key_enforced_on_verdicts(alembic_upgraded_db: Engine) -> None:
    """Inserting a verdict pointing at a non-existent attack must fail."""
    with alembic_upgraded_db.begin() as conn, pytest.raises(IntegrityError):
        conn.execute(
            sa.text(
                "INSERT INTO verdicts "
                "(verdict_id, attack_id, verdict, confidence, evidence_refs, "
                "rubric_sha, model_version, prompt_sha) "
                "VALUES (:vid, :aid, 'pass', 0.5, '[]', 'rsha', 'mv', 'psha')"
            ),
            {"vid": "00000000-0000-0000-0000-000000000001", "aid": "does-not-exist"},
        )


def test_coverage_matrix_composite_primary_key(alembic_upgraded_db: Engine) -> None:
    """Duplicate ``(category, sub_attack)`` pairs must be rejected."""
    insert_sql = sa.text("INSERT INTO coverage_matrix (category, sub_attack) VALUES (:c, :s)")
    with alembic_upgraded_db.begin() as conn:
        conn.execute(insert_sql, {"c": "prompt_injection", "s": "system_override"})

    with alembic_upgraded_db.begin() as conn, pytest.raises(IntegrityError):
        conn.execute(insert_sql, {"c": "prompt_injection", "s": "system_override"})


def test_json_column_roundtrips_dict(alembic_upgraded_db: Engine) -> None:
    """``agent_steps.args`` must round-trip a dict through ``sa.JSON``."""
    payload = {"tool": "call_target", "url": "x"}
    args_col = sa.Column("args", sa.JSON())
    table = sa.Table(
        "agent_steps",
        sa.MetaData(),
        sa.Column("step_id", sa.CHAR(36), primary_key=True),
        sa.Column("agent", sa.Text()),
        sa.Column("tool", sa.Text()),
        args_col,
        sa.Column("session_id", sa.Text()),
    )

    with alembic_upgraded_db.begin() as conn:
        conn.execute(
            table.insert().values(
                step_id="00000000-0000-0000-0000-00000000aaaa",
                agent="red_team",
                tool="craft_attack",
                args=payload,
                session_id="sess-1",
            )
        )

    with alembic_upgraded_db.connect() as conn:
        row = conn.execute(
            sa.select(args_col)
            .select_from(table)
            .where(table.c.step_id == "00000000-0000-0000-0000-00000000aaaa")
        ).one()
    assert row[0] == payload


def test_all_declared_indexes_exist(alembic_upgraded_db: Engine) -> None:
    """All nine non-PK indexes declared in the migration must be present."""
    with alembic_upgraded_db.connect() as conn:
        rows = conn.execute(
            sa.text(
                "SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'"
            )
        ).fetchall()
    actual = {row[0] for row in rows}
    missing = EXPECTED_INDEXES - actual
    assert not missing, f"Missing indexes: {missing}"


def test_verdicts_has_prompt_sha_column_after_upgrade_head(
    alembic_upgraded_db: Engine,
) -> None:
    """Task 57: after ``upgrade head``, ``verdicts.prompt_sha`` must exist.

    ``prompt_sha`` is the third leg of the verdict reproducibility triple
    ``(rubric_sha, model_version, prompt_sha)``. The column lands at revision
    0002 (idempotent over 0001's variant that may also declare it). Either
    way, the live schema at head MUST expose it for the Judge to write into.
    """
    with alembic_upgraded_db.connect() as conn:
        cols = conn.execute(sa.text("PRAGMA table_info(verdicts)")).fetchall()
    # PRAGMA table_info row shape: (cid, name, type, notnull, dflt_value, pk)
    names = [row[1] for row in cols]
    assert "prompt_sha" in names, f"prompt_sha missing from verdicts; got: {names}"
