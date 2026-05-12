"""Alembic environment for the AgentForge red-team platform.

Configures Alembic to:

- Use SQLite at ``var/platform.db`` by default, overridable via the
  ``PLATFORM_DB_PATH`` environment variable so tests can point to a tmp file.
- Enable batch mode (``render_as_batch=True``) for both online and offline
  contexts so future ALTER TABLE migrations work on SQLite.
- Force ``PRAGMA foreign_keys=ON`` on every new connection — SQLite ignores
  foreign keys by default, which would silently undermine the FK constraints
  we declare on every audit table.
- Use a Postgres-compatible naming convention on the MetaData so future
  autogenerate diffs are deterministic if/when we migrate off SQLite.
"""

from __future__ import annotations

import os
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import MetaData, engine_from_config, event, pool
from sqlalchemy.engine import Engine

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Naming convention shared by all migrations. Mirrors PostgreSQL defaults so
# the constraint names stay stable if/when we port off SQLite.
NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

# Models are declared imperatively in the migration files (no SQLAlchemy ORM
# layer yet), so target_metadata is just an empty MetaData with the naming
# convention attached for future autogenerate calls.
target_metadata = MetaData(naming_convention=NAMING_CONVENTION)


def _resolve_db_url() -> str:
    """Determine the SQLite URL Alembic should use.

    Precedence:

    1. ``PLATFORM_DB_PATH`` env var — used by tests to point at a tmp file.
    2. ``sqlalchemy.url`` from ``alembic.ini`` (default: ``var/platform.db``).

    Also ensures the parent directory of the resolved SQLite path exists,
    because SQLite will not create missing directories itself.
    """
    override = os.environ.get("PLATFORM_DB_PATH")
    if override:
        url = f"sqlite:///{override}"
    else:
        ini_url = config.get_main_option("sqlalchemy.url")
        if ini_url is None:
            raise RuntimeError("sqlalchemy.url is not set in alembic.ini")
        url = ini_url

    # Ensure the parent directory exists for any sqlite:/// URL.
    prefix = "sqlite:///"
    if url.startswith(prefix):
        db_path = Path(url[len(prefix) :])
        if db_path.parent and str(db_path.parent) not in ("", "."):
            db_path.parent.mkdir(parents=True, exist_ok=True)

    return url


@event.listens_for(Engine, "connect")
def _set_sqlite_pragma(dbapi_connection: object, _connection_record: object) -> None:
    """Enable SQLite foreign-key enforcement on every new connection.

    SQLite parses FK declarations but does not enforce them unless
    ``PRAGMA foreign_keys=ON`` is issued per-connection. Without this,
    every FK constraint in the schema would silently be a no-op.
    """
    cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emit SQL, no DB connection)."""
    url = _resolve_db_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode (real connection)."""
    url = _resolve_db_url()
    # Override the ini-supplied URL so PLATFORM_DB_PATH takes effect.
    config.set_main_option("sqlalchemy.url", url)

    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
