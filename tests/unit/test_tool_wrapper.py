"""Tests for the audited tool wrapper.

These tests exercise the wrapper end-to-end against a real SQLite database
under ``tmp_path``. The migration is run via Alembic inside the fixture so
the schema under test is the same schema production uses — we never mock
SQLAlchemy.

The Langfuse client is the only external dependency we stub, via the
:class:`_FakeLangfuse` double below. It implements just enough of the
``LangfuseClientLike`` / ``LangfuseSpanLike`` protocols for the wrapper to
exercise the span code paths without importing ``langfuse`` itself.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import Engine

from agentforge_redteam.db import create_platform_engine
from agentforge_redteam.kill_switch import (
    KillSwitchTripped,
    is_kill_switch_enabled,
    set_kill_switch,
)
from agentforge_redteam.tools.wrapper import ToolCallResult, call_tool

REPO_ROOT = Path(__file__).resolve().parents[2]
ALEMBIC_INI = REPO_ROOT / "alembic.ini"
ALEMBIC_DIR = REPO_ROOT / "alembic"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Engine]:
    """Yield a platform engine pointed at a freshly-migrated tmp database."""
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
# Fakes
# ---------------------------------------------------------------------------


class _FakeSpan:
    """In-memory stand-in for a Langfuse span."""

    def __init__(self) -> None:
        self.updates: list[dict[str, Any]] = []
        self.ended: bool = False
        self.name: str | None = None
        self.trace_id: str | None = None
        self.input: Any = None
        self.metadata: dict[str, Any] | None = None

    def update(
        self,
        *,
        output: Any = None,
        level: str | None = None,
        status_message: str | None = None,
    ) -> None:
        self.updates.append({"output": output, "level": level, "status_message": status_message})

    def end(self) -> None:
        self.ended = True


class _FakeLangfuse:
    """In-memory stand-in for a Langfuse client."""

    def __init__(self) -> None:
        self.spans: list[_FakeSpan] = []

    def span(
        self,
        *,
        name: str,
        trace_id: str | None = None,
        input: Any = None,
        metadata: dict[str, Any] | None = None,
    ) -> _FakeSpan:
        sp = _FakeSpan()
        sp.name = name
        sp.trace_id = trace_id
        sp.input = input
        sp.metadata = metadata
        self.spans.append(sp)
        return sp


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fetch_step(engine: Engine, step_id: str) -> sa.Row[Any]:
    with engine.connect() as conn:
        return conn.execute(
            sa.text(
                "SELECT step_id, agent, tool, args, result, cost_cents, latency_ms, session_id "
                "FROM agent_steps WHERE step_id = :sid"
            ),
            {"sid": step_id},
        ).one()


def _count_steps(engine: Engine) -> int:
    with engine.connect() as conn:
        return int(conn.execute(sa.text("SELECT COUNT(*) FROM agent_steps")).scalar_one())


# ---------------------------------------------------------------------------
# Kill-switch module behaviour (sanity)
# ---------------------------------------------------------------------------


def test_is_kill_switch_enabled_returns_false_on_fresh_db(engine: Engine) -> None:
    assert is_kill_switch_enabled(engine) is False


def test_set_kill_switch_round_trips(engine: Engine) -> None:
    set_kill_switch(engine, enabled=True)
    assert is_kill_switch_enabled(engine) is True
    set_kill_switch(engine, enabled=False)
    assert is_kill_switch_enabled(engine) is False


def test_kill_switch_tripped_message_includes_agent_and_tool() -> None:
    exc = KillSwitchTripped(agent="red_team", tool_name="craft_attack")
    msg = str(exc)
    assert "red_team" in msg
    assert "craft_attack" in msg
    assert exc.agent == "red_team"
    assert exc.tool_name == "craft_attack"


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


async def test_sync_tool_happy_path_writes_full_audit_row(engine: Engine) -> None:
    def echo_tool(*, x: int, y: str) -> dict[str, Any]:
        return {"x": x, "y": y}

    out: ToolCallResult = await call_tool(
        agent="red_team",
        tool_name="echo",
        tool=echo_tool,
        args={"x": 1, "y": "two"},
        session_id="sess-A",
        engine=engine,
    )

    assert out.result == {"x": 1, "y": "two"}
    assert out.cost_cents == 0
    assert out.latency_ms >= 0
    assert isinstance(out.step_id, str) and len(out.step_id) == 36

    row = _fetch_step(engine, out.step_id)
    assert row.agent == "red_team"
    assert row.tool == "echo"
    assert row.session_id == "sess-A"
    decoded = row.result if isinstance(row.result, dict) else json.loads(row.result)
    assert decoded == {"x": 1, "y": "two"}
    assert row.cost_cents == 0
    assert row.latency_ms >= 0


async def test_cost_estimator_populates_cost_cents(engine: Engine) -> None:
    def tool(*, n: int) -> int:
        return n * 2

    out = await call_tool(
        agent="judge",
        tool_name="double",
        tool=tool,
        args={"n": 5},
        session_id="sess-B",
        engine=engine,
        cost_estimator=lambda _result: 42,
    )

    assert out.cost_cents == 42
    row = _fetch_step(engine, out.step_id)
    assert row.cost_cents == 42


async def test_returned_step_id_matches_primary_key(engine: Engine) -> None:
    def tool() -> str:
        return "ok"

    out = await call_tool(
        agent="orchestrator",
        tool_name="noop",
        tool=tool,
        args={},
        session_id="sess-C",
        engine=engine,
    )

    row = _fetch_step(engine, out.step_id)
    assert row.step_id == out.step_id


async def test_async_tool_is_awaited(engine: Engine) -> None:
    async def async_tool(*, val: int) -> int:
        await asyncio.sleep(0)
        return val + 1

    out = await call_tool(
        agent="red_team",
        tool_name="async_inc",
        tool=async_tool,
        args={"val": 7},
        session_id="sess-D",
        engine=engine,
    )
    assert out.result == 8
    row = _fetch_step(engine, out.step_id)
    # sa.JSON auto-decodes scalars; tolerate either form.
    decoded = row.result if not isinstance(row.result, str) else json.loads(row.result)
    assert decoded == 8


async def test_args_persisted_as_json(engine: Engine) -> None:
    args = {"a": 1, "b": [1, 2, 3], "c": {"nested": True}}

    def tool(**_kwargs: Any) -> str:
        return "ok"

    out = await call_tool(
        agent="judge",
        tool_name="inspect_args",
        tool=tool,
        args=args,
        session_id="sess-E",
        engine=engine,
    )

    row = _fetch_step(engine, out.step_id)
    # SQLAlchemy's JSON type may or may not auto-decode under raw text(); we
    # tolerate either pre-decoded dict or a JSON string.
    parsed = row.args if isinstance(row.args, dict) else json.loads(row.args)
    assert parsed == args


# ---------------------------------------------------------------------------
# Serialization fallback
# ---------------------------------------------------------------------------


async def test_non_json_serializable_result_uses_error_envelope(engine: Engine) -> None:
    class NotSerializable:
        def __repr__(self) -> str:
            return "<NotSerializable instance>"

    # Force a real serialization failure. ``json.dumps(..., default=str)``
    # absorbs many "weird" types by coercing to str, so we use an object
    # whose ``default=str`` path raises by registering a circular reference.
    bad: dict[str, Any] = {}
    bad["self"] = bad  # circular -> ValueError from json.dumps

    def tool() -> dict[str, Any]:
        return bad

    out = await call_tool(
        agent="red_team",
        tool_name="bad_result",
        tool=tool,
        args={},
        session_id="sess-F",
        engine=engine,
    )
    # Wrapper must NOT raise — result is still returned to the caller.
    assert out.result is bad

    row = _fetch_step(engine, out.step_id)
    envelope = row.result if isinstance(row.result, dict) else json.loads(row.result)
    assert envelope["error"] == "result_not_json_serializable"
    assert "repr" in envelope


# ---------------------------------------------------------------------------
# Kill-switch interactions
# ---------------------------------------------------------------------------


async def test_kill_switch_on_prevents_call_and_writes_no_row(engine: Engine) -> None:
    set_kill_switch(engine, enabled=True)

    def tool() -> str:
        return "should not run"

    with pytest.raises(KillSwitchTripped):
        await call_tool(
            agent="red_team",
            tool_name="craft_attack",
            tool=tool,
            args={},
            session_id="sess-G",
            engine=engine,
        )

    assert _count_steps(engine) == 0


async def test_kill_switch_flips_between_calls(engine: Engine) -> None:
    def tool() -> str:
        return "ok"

    out1 = await call_tool(
        agent="red_team",
        tool_name="t",
        tool=tool,
        args={},
        session_id="sess-H",
        engine=engine,
    )
    assert out1.result == "ok"
    assert _count_steps(engine) == 1

    set_kill_switch(engine, enabled=True)

    with pytest.raises(KillSwitchTripped):
        await call_tool(
            agent="red_team",
            tool_name="t",
            tool=tool,
            args={},
            session_id="sess-H",
            engine=engine,
        )

    # Still only the first call's row.
    assert _count_steps(engine) == 1


# ---------------------------------------------------------------------------
# Exception path
# ---------------------------------------------------------------------------


async def test_tool_exception_is_reraised_and_audit_row_is_written(
    engine: Engine,
) -> None:
    def tool(*, why: str) -> None:
        raise ValueError(f"bad ({why})")

    with pytest.raises(ValueError, match="bad"):
        await call_tool(
            agent="judge",
            tool_name="explode",
            tool=tool,
            args={"why": "testing"},
            session_id="sess-I",
            engine=engine,
        )

    # The audit row must still exist with the exception envelope.
    with engine.connect() as conn:
        rows = conn.execute(
            sa.text(
                "SELECT step_id, agent, tool, result, latency_ms "
                "FROM agent_steps WHERE agent = 'judge' AND tool = 'explode'"
            )
        ).fetchall()
    assert len(rows) == 1
    envelope = rows[0].result if isinstance(rows[0].result, dict) else json.loads(rows[0].result)
    assert envelope["error"] == "ValueError"
    assert "bad" in envelope["message"]


async def test_tool_exception_still_populates_latency(engine: Engine) -> None:
    def tool() -> None:
        raise RuntimeError("kaboom")

    with pytest.raises(RuntimeError):
        await call_tool(
            agent="orchestrator",
            tool_name="boom",
            tool=tool,
            args={},
            session_id="sess-J",
            engine=engine,
        )

    with engine.connect() as conn:
        latency = conn.execute(
            sa.text(
                "SELECT latency_ms FROM agent_steps WHERE agent = 'orchestrator' AND tool = 'boom'"
            )
        ).scalar_one()
    assert latency >= 0


# ---------------------------------------------------------------------------
# Concurrency smoke test
# ---------------------------------------------------------------------------


async def test_concurrent_calls_do_not_deadlock(engine: Engine) -> None:
    async def tool(*, i: int) -> int:
        await asyncio.sleep(0)
        return i

    tasks = [
        call_tool(
            agent="red_team",
            tool_name="parallel",
            tool=tool,
            args={"i": i},
            session_id="sess-K",
            engine=engine,
        )
        for i in range(5)
    ]
    results = await asyncio.gather(*tasks)
    assert sorted(r.result for r in results) == [0, 1, 2, 3, 4]
    assert _count_steps(engine) == 5


# ---------------------------------------------------------------------------
# Langfuse integration (via fake)
# ---------------------------------------------------------------------------


async def test_langfuse_none_makes_no_span_calls(engine: Engine) -> None:
    # Sanity: passing ``None`` (the default) must not raise. There's nothing
    # to assert on a None client other than that the wrapper completed.
    def tool() -> str:
        return "ok"

    out = await call_tool(
        agent="red_team",
        tool_name="t",
        tool=tool,
        args={},
        session_id="sess-L",
        engine=engine,
        langfuse=None,
    )
    assert out.result == "ok"


async def test_langfuse_span_started_and_ended_on_success(engine: Engine) -> None:
    lf = _FakeLangfuse()

    def tool(*, x: int) -> int:
        return x

    out = await call_tool(
        agent="red_team",
        tool_name="t",
        tool=tool,
        args={"x": 9},
        session_id="sess-M",
        engine=engine,
        langfuse=lf,
    )

    assert len(lf.spans) == 1
    sp = lf.spans[0]
    assert sp.name == out.step_id
    assert sp.trace_id == out.step_id
    assert sp.input == {"x": 9}
    assert sp.ended is True


async def test_langfuse_span_on_exception_records_error_level(engine: Engine) -> None:
    lf = _FakeLangfuse()

    def tool() -> None:
        raise ValueError("nope")

    with pytest.raises(ValueError):
        await call_tool(
            agent="judge",
            tool_name="t",
            tool=tool,
            args={},
            session_id="sess-N",
            engine=engine,
            langfuse=lf,
        )

    assert len(lf.spans) == 1
    sp = lf.spans[0]
    # ``update(level="ERROR", ...)`` must have been called before ``end()``.
    error_updates = [u for u in sp.updates if u.get("level") == "ERROR"]
    assert len(error_updates) == 1
    assert "nope" in (error_updates[0]["status_message"] or "")
    assert sp.ended is True
