"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-05-11 21:52:48.405847

Creates the nine audit tables that back the AgentForge red-team platform:
agent_steps, attacks, verdicts, findings, regression_runs, coverage_matrix,
run_manifests, kill_switch, and human_approval_queue.

All UUIDs are stored as ``CHAR(36)`` text. All JSON payloads use SQLAlchemy's
``sa.JSON`` (TEXT under SQLite). The ``kill_switch`` table is seeded with the
singleton row ``(id=1, enabled=0)`` so the platform always has a well-defined
emergency-stop state to read.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create all nine tables, their indexes, and seed kill_switch."""
    # ------------------------------------------------------------------
    # agent_steps — append-only log of every (agent, tool) invocation
    # ------------------------------------------------------------------
    op.create_table(
        "agent_steps",
        sa.Column("step_id", sa.CHAR(36), primary_key=True, nullable=False),
        sa.Column("agent", sa.Text(), nullable=False),
        sa.Column("tool", sa.Text(), nullable=False),
        sa.Column("args", sa.JSON(), nullable=False),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("cost_cents", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("latency_ms", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column(
            "timestamp",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("session_id", sa.Text(), nullable=False),
        sqlite_autoincrement=False,
    )

    # ------------------------------------------------------------------
    # attacks — one row per adversarial probe
    # ------------------------------------------------------------------
    op.create_table(
        "attacks",
        sa.Column("attack_id", sa.CHAR(36), primary_key=True, nullable=False),
        sa.Column("campaign_id", sa.CHAR(36), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("target_response", sa.Text(), nullable=False, server_default=sa.text("''")),
        sa.Column("target_sha", sa.Text(), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sqlite_autoincrement=False,
    )

    # ------------------------------------------------------------------
    # verdicts — one Judge ruling per attack
    # ------------------------------------------------------------------
    op.create_table(
        "verdicts",
        sa.Column("verdict_id", sa.CHAR(36), primary_key=True, nullable=False),
        sa.Column("attack_id", sa.CHAR(36), nullable=False),
        sa.Column("verdict", sa.Text(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("rubric_sha", sa.Text(), nullable=False),
        sa.Column("model_version", sa.Text(), nullable=False),
        sa.Column("prompt_sha", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.ForeignKeyConstraint(
            ["attack_id"],
            ["attacks.attack_id"],
            name="fk_verdicts_attack_id_attacks",
            ondelete="CASCADE",
        ),
        sqlite_autoincrement=False,
    )

    # ------------------------------------------------------------------
    # findings — promoted verdicts that became tracked issues
    # ------------------------------------------------------------------
    op.create_table(
        "findings",
        sa.Column("finding_id", sa.CHAR(36), primary_key=True, nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("attack_id", sa.CHAR(36), nullable=False),
        sa.Column("verdict_id", sa.CHAR(36), nullable=False),
        sa.Column("gitlab_issue_id", sa.Integer(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "sanitized_evidence",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.ForeignKeyConstraint(
            ["attack_id"],
            ["attacks.attack_id"],
            name="fk_findings_attack_id_attacks",
        ),
        sa.ForeignKeyConstraint(
            ["verdict_id"],
            ["verdicts.verdict_id"],
            name="fk_findings_verdict_id_verdicts",
        ),
        sqlite_autoincrement=False,
    )

    # ------------------------------------------------------------------
    # regression_runs — re-runs of a finding against a new target_sha
    # ------------------------------------------------------------------
    op.create_table(
        "regression_runs",
        sa.Column("run_id", sa.CHAR(36), primary_key=True, nullable=False),
        sa.Column("finding_id", sa.CHAR(36), nullable=False),
        sa.Column("target_sha", sa.Text(), nullable=False),
        sa.Column("verdict_comparison", sa.JSON(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.finding_id"],
            name="fk_regression_runs_finding_id_findings",
        ),
        sqlite_autoincrement=False,
    )

    # ------------------------------------------------------------------
    # coverage_matrix — rolling per-(category, sub_attack) telemetry
    # ------------------------------------------------------------------
    op.create_table(
        "coverage_matrix",
        sa.Column("category", sa.Text(), nullable=False),
        sa.Column("sub_attack", sa.Text(), nullable=False),
        sa.Column("runs_last_7d", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("runs_lifetime", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column(
            "findings_by_severity",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.Column("last_run_at", sa.DateTime(), nullable=True),
        sa.Column("avg_cost_cents", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("coverage_score", sa.Float(), nullable=False, server_default=sa.text("0.0")),
        sa.PrimaryKeyConstraint("category", "sub_attack", name="pk_coverage_matrix"),
        sqlite_autoincrement=False,
    )

    # ------------------------------------------------------------------
    # run_manifests — pin every artefact SHA for a session
    # ------------------------------------------------------------------
    op.create_table(
        "run_manifests",
        sa.Column("session_id", sa.Text(), primary_key=True, nullable=False),
        sa.Column("target_sha", sa.Text(), nullable=False),
        sa.Column("prompt_set_sha", sa.Text(), nullable=False),
        sa.Column("rubric_set_sha", sa.Text(), nullable=False),
        sa.Column("attack_library_sha", sa.Text(), nullable=False),
        sa.Column("policy_sha", sa.Text(), nullable=False),
        sa.Column("cost_cap_cents", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sqlite_autoincrement=False,
    )

    # ------------------------------------------------------------------
    # kill_switch — singleton row, CHECK forces id == 1
    # ------------------------------------------------------------------
    op.create_table(
        "kill_switch",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.PrimaryKeyConstraint("id", name="pk_kill_switch"),
        sa.CheckConstraint("id = 1", name="ck_kill_switch_singleton"),
        sqlite_autoincrement=False,
    )

    # ------------------------------------------------------------------
    # human_approval_queue — out-of-band review for P0/P1 findings
    # ------------------------------------------------------------------
    op.create_table(
        "human_approval_queue",
        sa.Column("queue_id", sa.CHAR(36), primary_key=True, nullable=False),
        sa.Column("finding_id", sa.CHAR(36), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default=sa.text("'pending'")),
        sa.Column("reviewed_by", sa.Text(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.finding_id"],
            name="fk_human_approval_queue_finding_id_findings",
        ),
        sqlite_autoincrement=False,
    )

    # ------------------------------------------------------------------
    # Indexes
    # ------------------------------------------------------------------
    op.create_index("ix_attacks_campaign_id", "attacks", ["campaign_id"])
    op.create_index("ix_attacks_target_sha", "attacks", ["target_sha"])
    op.create_index("ix_verdicts_attack_id", "verdicts", ["attack_id"])
    op.create_index("ix_findings_attack_id", "findings", ["attack_id"])
    op.create_index("ix_findings_verdict_id", "findings", ["verdict_id"])
    op.create_index("ix_regression_runs_finding_id", "regression_runs", ["finding_id"])
    op.create_index("ix_regression_runs_target_sha", "regression_runs", ["target_sha"])
    op.create_index(
        "ix_agent_steps_session_timestamp",
        "agent_steps",
        ["session_id", "timestamp"],
    )
    op.create_index("ix_human_approval_queue_status", "human_approval_queue", ["status"])

    # ------------------------------------------------------------------
    # Seed the singleton kill_switch row
    # ------------------------------------------------------------------
    op.execute("INSERT INTO kill_switch (id, enabled) VALUES (1, 0)")


def downgrade() -> None:
    """Drop everything in reverse FK-safe order."""
    # Drop indexes first to avoid surprises on dialects that don't
    # auto-drop them with the parent table.
    op.drop_index("ix_human_approval_queue_status", table_name="human_approval_queue")
    op.drop_index("ix_agent_steps_session_timestamp", table_name="agent_steps")
    op.drop_index("ix_regression_runs_target_sha", table_name="regression_runs")
    op.drop_index("ix_regression_runs_finding_id", table_name="regression_runs")
    op.drop_index("ix_findings_verdict_id", table_name="findings")
    op.drop_index("ix_findings_attack_id", table_name="findings")
    op.drop_index("ix_verdicts_attack_id", table_name="verdicts")
    op.drop_index("ix_attacks_target_sha", table_name="attacks")
    op.drop_index("ix_attacks_campaign_id", table_name="attacks")

    # Drop in reverse FK dependency order: leaf tables first.
    op.drop_table("human_approval_queue")
    op.drop_table("kill_switch")
    op.drop_table("run_manifests")
    op.drop_table("coverage_matrix")
    op.drop_table("regression_runs")
    op.drop_table("findings")
    op.drop_table("verdicts")
    op.drop_table("attacks")
    op.drop_table("agent_steps")
