"""Tests for the operator CLI (Task 14).

These tests exercise the Typer app via :class:`typer.testing.CliRunner` and
assert against the *real* SQLite database under ``tmp_path``. We never mock
SQLAlchemy: the contract under test is "CLI flips the singleton row that
the audited wrapper reads on every call", and stubbing the engine would
make the test pass without proving that contract.

The fixture pattern mirrors ``tests/unit/test_tool_wrapper.py`` so failures
in either file can be diagnosed with the same mental model.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import anyio
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import Engine
from typer.testing import CliRunner

from agentforge_redteam.cli import app
from agentforge_redteam.db import create_platform_engine
from agentforge_redteam.kill_switch import (
    KillSwitchTripped,
    is_kill_switch_enabled,
    set_kill_switch,
)
from agentforge_redteam.tools.wrapper import call_tool

REPO_ROOT = Path(__file__).resolve().parents[2]
ALEMBIC_INI = REPO_ROOT / "alembic.ini"
ALEMBIC_DIR = REPO_ROOT / "alembic"

runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Engine]:
    """Yield a platform engine pointed at a freshly-migrated tmp database.

    Also sets ``PLATFORM_DB_PATH`` in the environment so any CLI invocation
    inside the test picks up the same database via
    :func:`agentforge_redteam.db.database_url`.
    """
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("PLATFORM_DB_PATH", str(db_path))

    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("script_location", str(ALEMBIC_DIR))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    command.upgrade(cfg, "head")

    eng = create_platform_engine(db_path)
    try:
        yield eng
    finally:
        eng.dispose()


# ---------------------------------------------------------------------------
# halt
# ---------------------------------------------------------------------------


def test_halt_enables_kill_switch_in_db(engine: Engine) -> None:
    result = runner.invoke(app, ["halt"])
    assert result.exit_code == 0, result.output
    assert is_kill_switch_enabled(engine) is True


def test_halt_prints_confirmation(engine: Engine) -> None:
    result = runner.invoke(app, ["halt"])
    assert result.exit_code == 0
    assert "Kill switch activated" in result.output


def test_halt_is_idempotent(engine: Engine) -> None:
    first = runner.invoke(app, ["halt"])
    second = runner.invoke(app, ["halt"])
    assert first.exit_code == 0
    assert second.exit_code == 0
    assert is_kill_switch_enabled(engine) is True


# ---------------------------------------------------------------------------
# resume
# ---------------------------------------------------------------------------


def test_resume_clears_kill_switch(engine: Engine) -> None:
    set_kill_switch(engine, enabled=True)
    assert is_kill_switch_enabled(engine) is True

    result = runner.invoke(app, ["resume"])
    assert result.exit_code == 0, result.output
    assert is_kill_switch_enabled(engine) is False


def test_resume_prints_message(engine: Engine) -> None:
    set_kill_switch(engine, enabled=True)
    result = runner.invoke(app, ["resume"])
    assert result.exit_code == 0
    # Accept either "resumed" or "cleared" in the message - both are
    # operationally meaningful for an incident-response runbook.
    out = result.output.lower()
    assert "resumed" in out or "cleared" in out


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


def test_status_running_on_fresh_db(engine: Engine) -> None:
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert "running" in result.output


def test_status_halted_after_halt(engine: Engine) -> None:
    runner.invoke(app, ["halt"])
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 1
    assert "halted" in result.output


# ---------------------------------------------------------------------------
# Env-var plumbing
# ---------------------------------------------------------------------------


def test_cli_honours_platform_db_path_env_var(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Setting ``PLATFORM_DB_PATH`` must redirect the CLI's engine.

    We migrate a database at a non-default location and verify the file
    appears there after a CLI command runs - proving the CLI did not silently
    fall back to ``var/platform.db``.
    """
    db_path = tmp_path / "elsewhere.db"
    monkeypatch.setenv("PLATFORM_DB_PATH", str(db_path))

    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("script_location", str(ALEMBIC_DIR))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    command.upgrade(cfg, "head")

    result = runner.invoke(app, ["halt"])
    assert result.exit_code == 0, result.output
    assert db_path.exists()

    # And the switch flipped in *that* DB, not the default one.
    eng = create_platform_engine(db_path)
    try:
        assert is_kill_switch_enabled(eng) is True
    finally:
        eng.dispose()


# ---------------------------------------------------------------------------
# Help smoke test
# ---------------------------------------------------------------------------


def test_help_succeeds() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "halt" in result.output
    assert "resume" in result.output
    assert "status" in result.output


# ---------------------------------------------------------------------------
# Integration with the audited tool wrapper
# ---------------------------------------------------------------------------


def test_wrapper_refuses_calls_after_cli_halt(engine: Engine) -> None:
    """End-to-end: CLI halt -> wrapper raises KillSwitchTripped.

    This is the load-bearing test for Task 14. It proves the CLI is writing
    to the same row the wrapper reads, not just a parallel field that
    coincidentally has the same name.
    """
    halt_result = runner.invoke(app, ["halt"])
    assert halt_result.exit_code == 0

    def tool() -> str:
        return "should not run"

    async def _attempt() -> None:
        await call_tool(
            agent="red_team",
            tool_name="craft_attack",
            tool=tool,
            args={},
            session_id="sess-cli-halt",
            engine=engine,
        )

    with pytest.raises(KillSwitchTripped):
        anyio.run(_attempt)


def test_wrapper_allows_calls_after_cli_resume(engine: Engine) -> None:
    """CLI halt then CLI resume must restore tool-call functionality."""
    runner.invoke(app, ["halt"])
    resume_result = runner.invoke(app, ["resume"])
    assert resume_result.exit_code == 0

    def tool(*, val: int) -> int:
        return val + 1

    async def _attempt() -> int:
        out = await call_tool(
            agent="red_team",
            tool_name="inc",
            tool=tool,
            args={"val": 41},
            session_id="sess-cli-resume",
            engine=engine,
        )
        assert isinstance(out.result, int)
        return out.result

    result = anyio.run(_attempt)
    assert result == 42
