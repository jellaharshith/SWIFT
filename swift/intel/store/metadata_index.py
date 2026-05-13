"""SQLite metadata index — tracks ingested documents and sync state."""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from intel.sources.models import IntelDocument

DB_PATH = Path(os.path.expanduser("~/.swift/intel/metadata.db"))


class MetadataIndex:
    def __init__(self, db_path: Path = DB_PATH) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS documents (
                    doc_id TEXT PRIMARY KEY,
                    source TEXT,
                    content_hash TEXT,
                    ingested_at TEXT,
                    url TEXT,
                    metadata_json TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sync_log (
                    source TEXT PRIMARY KEY,
                    last_synced TEXT
                )
            """)

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self.db_path))

    def upsert(self, doc: IntelDocument) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO documents "
                "(doc_id, source, content_hash, ingested_at, url, metadata_json) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (doc.doc_id, doc.source, doc.content_hash,
                 doc.ingested_at.isoformat(), doc.url, json.dumps(doc.metadata)),
            )

    def is_known(self, content_hash: str) -> bool:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM documents WHERE content_hash = ?", (content_hash,)
            ).fetchone()
            return row is not None

    def get_last_sync(self, source: str) -> datetime | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT last_synced FROM sync_log WHERE source = ?", (source,)
            ).fetchone()
            if not row:
                return None
            return datetime.fromisoformat(row[0]).replace(tzinfo=timezone.utc)

    def mark_synced(self, source: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO sync_log (source, last_synced) VALUES (?, ?)",
                (source, datetime.now(timezone.utc).isoformat()),
            )
