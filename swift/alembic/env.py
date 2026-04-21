"""Alembic migration environment for SWIFT.

Reads the database URL from the same environment variables used by the
application (DATABASE_URL for Postgres, SWIFT_DB_PATH for SQLite fallback)
and wires up the app's SQLAlchemy Base for autogenerate support.
"""
from __future__ import annotations

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import create_engine, pool

from alembic import context

# Ensure the swift package root is importable when running `alembic` from
# anywhere inside the swift/ directory.
_here = Path(__file__).resolve().parent.parent  # swift/
if str(_here) not in sys.path:
    sys.path.insert(0, str(_here))

from web.storage import Base  # noqa: E402  (import after sys.path tweak)

# Alembic Config object — provides access to alembic.ini values.
config = context.config

# Set up loggers from the ini file (if present).
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Expose app metadata so `alembic revision --autogenerate` can diff the schema.
target_metadata = Base.metadata


def _db_url() -> str:
    """Return the database URL from the environment, matching app logic."""
    database_url = os.environ.get("DATABASE_URL", "").strip()
    if database_url:
        return database_url
    db_path = os.environ.get("SWIFT_DB_PATH", "./swift_scans.db")
    return f"sqlite:///{db_path}"


def run_migrations_offline() -> None:
    """Run migrations without an active DB connection (SQL-script mode)."""
    url = _db_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live database connection."""
    connectable = create_engine(_db_url(), poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
