"""Add progress-tracking columns to scan_jobs.

Revision ID: 001
Revises:
Create Date: 2026-04-21

Adds eight columns that the ScanJob ORM model expects but that may be absent
from databases created before these fields were introduced:

    progress, signals_detected, batch_current, batch_total,
    files_total, files_scanned, current_file, detail

The upgrade is idempotent: each column is only added when it is not already
present, so re-running the migration against an up-to-date database is safe.

The downgrade is intentionally a no-op — removing these columns would destroy
production data.
"""
from __future__ import annotations

from alembic import op
from sqlalchemy import Inspector, text

# Alembic revision identifiers.
revision: str = "001"
down_revision: str | None = None
branch_labels = None
depends_on = None

# Ordered list of (column_name, SQL type + default fragment).
_COLUMNS: list[tuple[str, str]] = [
    ("progress", "INTEGER DEFAULT 0"),
    ("signals_detected", "INTEGER DEFAULT 0"),
    ("batch_current", "INTEGER DEFAULT 0"),
    ("batch_total", "INTEGER DEFAULT 0"),
    ("files_total", "INTEGER DEFAULT 0"),
    ("files_scanned", "INTEGER DEFAULT 0"),
    ("current_file", "TEXT"),
    ("detail", "TEXT"),
    ("started_at", "TEXT"),
    ("findings_json", "TEXT"),
]


def upgrade() -> None:
    """Add missing columns to scan_jobs — idempotent, no data loss."""
    bind = op.get_bind()
    inspector = Inspector.from_engine(bind)

    # If the table does not exist at all (brand-new database), skip — SQLAlchemy
    # create_all() will create it with every column already present.
    if "scan_jobs" not in inspector.get_table_names():
        return

    existing_columns = {c["name"] for c in inspector.get_columns("scan_jobs")}

    for col_name, col_def in _COLUMNS:
        if col_name not in existing_columns:
            bind.execute(
                text(f"ALTER TABLE scan_jobs ADD COLUMN {col_name} {col_def}")
            )


def downgrade() -> None:
    """No-op: dropping columns would destroy production data."""
    pass
