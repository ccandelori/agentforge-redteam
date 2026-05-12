"""Shared SQLAlchemy plumbing for the AgentForge red-team platform.

Every module that talks to the platform's SQLite database goes through this
module. Keeping the engine factory here gives us a single place to:

- resolve the database URL (env var > explicit arg > the default file under
  ``var/``), so tests can redirect the engine to a ``tmp_path`` without
  monkeypatching internal symbols;
- guarantee the parent directory of the SQLite file exists before any code
  tries to open it (SQLite will not create missing directories itself);
- attach a ``PRAGMA foreign_keys=ON`` listener to *this* engine only. We do
  not register the pragma against the global ``Engine`` class because that
  would leak into other engines (notably the one Alembic creates) and make
  reasoning about connection setup harder.

The module deliberately imports from no other ``agentforge_redteam`` module so
that the audit-tool wrapper, kill switch, and future ORM layer can all depend
on it without risking import cycles.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, create_engine, event

DEFAULT_DB_PATH: Path = Path("var/platform.db")


def database_url(db_path: Path | str | None = None) -> str:
    """Return a SQLAlchemy URL for the platform SQLite database.

    Precedence (highest first):

    1. The ``PLATFORM_DB_PATH`` environment variable. Tests and the CLI use
       this to redirect every component (Alembic, the wrapper, the kill
       switch) at the same database without threading a path through every
       call site.
    2. The explicit ``db_path`` argument, if provided.
    3. :data:`DEFAULT_DB_PATH` (``var/platform.db``).
    """
    override = os.environ.get("PLATFORM_DB_PATH")
    if override:
        return f"sqlite:///{override}"
    resolved = DEFAULT_DB_PATH if db_path is None else Path(db_path)
    return f"sqlite:///{resolved}"


def create_platform_engine(
    db_path: Path | str | None = None,
    *,
    echo: bool = False,
) -> Engine:
    """Create a SQLAlchemy ``Engine`` pointed at the platform database.

    The engine has a per-connection listener that issues
    ``PRAGMA foreign_keys=ON`` so every FK constraint declared in the
    migration is actually enforced. SQLite parses but ignores FK constraints
    by default — without this pragma, the audit log would silently accept
    orphaned rows.

    The caller owns the returned engine and is responsible for calling
    ``.dispose()`` when finished (typically in a fixture teardown or at
    process shutdown).
    """
    url = database_url(db_path)

    # Ensure the parent directory of the SQLite file exists. SQLite will not
    # create it for us, and ``create_engine`` is lazy enough that the failure
    # only surfaces on the first connection, which is a confusing place to
    # discover a missing directory.
    if url.startswith("sqlite:///"):
        file_path = Path(url[len("sqlite:///") :])
        parent = file_path.parent
        if parent and str(parent) not in ("", "."):
            parent.mkdir(parents=True, exist_ok=True)

    engine = create_engine(url, echo=echo, future=True)

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection: Any, _record: Any) -> None:
        """Enable SQLite FK enforcement on this engine's connections only."""
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()

    return engine
