"""Emergency stop flag backed by the ``kill_switch`` singleton row.

The ``kill_switch`` table holds exactly one row (CHECK constraint enforces
``id = 1``). When ``enabled`` is true, the audited tool wrapper refuses to
execute *any* tool call — this is the platform's last-resort halt for
operators when something is misbehaving (runaway costs, a Judge gone rogue,
PHI leak signals, etc.).

The flag is read on every tool invocation. We deliberately do NOT cache the
value: a halt must take effect within one tool call, not "eventually". The
read is a single primary-key lookup on a one-row table, so the overhead is
negligible compared to any real tool call (LLM round-trip, HTTP request).
"""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.engine import Engine


class KillSwitchTripped(Exception):
    """Raised by the audited wrapper when a tool call is attempted while the
    kill switch is enabled.

    The exception carries the offending ``agent`` and ``tool_name`` so log
    sinks (and the operator reading them) can see which call was refused
    without having to consult a separate trace.
    """

    def __init__(self, *, agent: str, tool_name: str) -> None:
        self.agent = agent
        self.tool_name = tool_name
        super().__init__(
            f"kill switch tripped: refusing to run tool {tool_name!r} for agent {agent!r}"
        )


def is_kill_switch_enabled(engine: Engine) -> bool:
    """Return the current value of ``kill_switch.enabled``.

    Issues a single ``SELECT`` against the singleton row. No caching: the
    wrapper calls this on every tool invocation, and SQLite handles tens of
    thousands of point reads per second on a row-cached singleton table.
    """
    with engine.connect() as conn:
        row = conn.execute(text("SELECT enabled FROM kill_switch WHERE id = 1")).first()
    if row is None:
        # The migration seeds (1, 0). A missing row means the migration was
        # never run or the row was manually deleted — fail closed so an
        # operator notices.
        raise RuntimeError("kill_switch singleton row missing; did you run `alembic upgrade head`?")
    return bool(row[0])


def set_kill_switch(engine: Engine, *, enabled: bool) -> None:
    """Update the singleton ``kill_switch`` row.

    Used by the CLI ``halt`` command and by tests. We always target ``id = 1``
    explicitly so a malformed table (extra rows) does not silently mass-update.
    """
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE kill_switch SET enabled = :enabled WHERE id = 1"),
            {"enabled": 1 if enabled else 0},
        )
