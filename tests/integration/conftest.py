"""Shared fixtures for end-to-end smoke tests.

The smoke tests exercise the full agent stack (Orchestrator -> Red Team -> Judge ->
Documentation) against a tmp SQLite DB with mocked LLM, HTTP target, GitLab, and
Langfuse clients. We do NOT hit any live network.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import Engine

from agentforge_redteam.db import create_platform_engine


@pytest.fixture
def migrated_engine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Engine:
    """tmp SQLite DB with `alembic upgrade head` applied. Caller owns the engine
    (yielded with cleanup via the fixture lifecycle)."""
    db_path = tmp_path / "platform.db"
    monkeypatch.setenv("PLATFORM_DB_PATH", str(db_path))
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    command.upgrade(cfg, "head")
    engine = create_platform_engine(db_path)
    yield engine
    engine.dispose()


class _FakeSpan:
    def __init__(self) -> None:
        self.updates: list[dict[str, Any]] = []
        self.ended = False

    def update(self, **kw: Any) -> None:
        self.updates.append(kw)

    def end(self) -> None:
        self.ended = True


class FakeLangfuse:
    """Protocol-satisfying no-op client recording spans for assertions."""

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
        self.spans.append(sp)
        return sp


@pytest.fixture
def fake_langfuse() -> FakeLangfuse:
    return FakeLangfuse()
