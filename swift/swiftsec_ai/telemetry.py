"""Unified observability store — every run event, archived to SQLite + FTS5.

Mirrors the CVEStore pattern in cve.py: a standalone FTS5 index (not
external-content, to avoid drift corruption) with a transparent ``LIKE``
fallback when the local sqlite build lacks FTS5.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS run_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            REAL NOT NULL,
    engagement    TEXT NOT NULL,
    agent_role    TEXT,
    agent_token   TEXT,
    event_type    TEXT NOT NULL,
    tool_name     TEXT,
    target        TEXT,
    severity      TEXT,
    summary       TEXT,
    artifact_path TEXT,
    flags         TEXT
);
"""

FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS run_events_fts USING fts5(
    engagement, event_type, tool_name, target, summary
);
"""

EVENT_TYPES = {
    "recon_start", "recon_end", "tool_call", "finding_confirmed",
    "guardrail_violation", "agent_spawn", "agent_complete", "run_stop", "error",
}


class Telemetry:
    """Unified observability store for all SWIFTSEC run events."""

    def __init__(self, db_path: str | Path = "swiftsec_telemetry.db") -> None:
        self.db_path = str(db_path)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.execute(SCHEMA)
        self._has_fts = self._try_create_fts()
        self._conn.commit()

    def _try_create_fts(self) -> bool:
        try:
            self._conn.execute(FTS_SCHEMA)
            return True
        except sqlite3.OperationalError:
            return False

    def log(self, engagement: str, event_type: str, **kwargs: Any) -> None:
        row = {
            "ts": time.time(),
            "engagement": engagement,
            "agent_role": kwargs.get("agent_role"),
            "agent_token": kwargs.get("agent_token"),
            "event_type": event_type,
            "tool_name": kwargs.get("tool_name"),
            "target": kwargs.get("target"),
            "severity": kwargs.get("severity"),
            "summary": kwargs.get("summary"),
            "artifact_path": kwargs.get("artifact_path"),
            "flags": json.dumps(kwargs.get("flags") or []),
        }
        cur = self._conn.execute(
            "INSERT INTO run_events "
            "(ts, engagement, agent_role, agent_token, event_type, tool_name, target, "
            " severity, summary, artifact_path, flags) "
            "VALUES (:ts, :engagement, :agent_role, :agent_token, :event_type, :tool_name, "
            " :target, :severity, :summary, :artifact_path, :flags)",
            row,
        )
        if self._has_fts:
            self._conn.execute(
                "INSERT INTO run_events_fts (rowid, engagement, event_type, tool_name, target, summary) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (cur.lastrowid, row["engagement"], event_type, row["tool_name"] or "",
                 row["target"] or "", row["summary"] or ""),
            )
        self._conn.commit()

    def query(self, search_term: str, engagement: str | None = None) -> list[dict[str, Any]]:
        if self._has_fts and search_term:
            sql = "SELECT rowid FROM run_events_fts WHERE run_events_fts MATCH ?"
            try:
                rowids = [r[0] for r in self._conn.execute(sql, (search_term,)).fetchall()]
            except sqlite3.OperationalError:
                rowids = []
            if not rowids:
                return []
            placeholders = ",".join("?" * len(rowids))
            sql = f"SELECT * FROM run_events WHERE id IN ({placeholders})"
            params: list[Any] = list(rowids)
        else:
            like = f"%{search_term}%"
            sql = "SELECT * FROM run_events WHERE summary LIKE ? OR target LIKE ?"
            params = [like, like]
        if engagement:
            sql += " AND engagement = ?" if "WHERE" in sql else " WHERE engagement = ?"
            params.append(engagement)
        sql += " ORDER BY ts DESC"
        cols = [c[1] for c in self._conn.execute("PRAGMA table_info(run_events)")]
        return [dict(zip(cols, row)) for row in self._conn.execute(sql, params).fetchall()]

    def engagement_summary(self, engagement: str) -> dict[str, Any]:
        rows = self._conn.execute(
            "SELECT event_type, severity, ts FROM run_events WHERE engagement = ? ORDER BY ts",
            (engagement,),
        ).fetchall()
        total = len(rows)
        by_severity: dict[str, int] = {}
        tools_called = 0
        agents_spawned = 0
        guardrail_violations = 0
        for event_type, severity, _ts in rows:
            if event_type == "finding_confirmed" and severity:
                by_severity[severity] = by_severity.get(severity, 0) + 1
            if event_type == "tool_call":
                tools_called += 1
            if event_type == "agent_spawn":
                agents_spawned += 1
            if event_type == "guardrail_violation":
                guardrail_violations += 1
        duration = (rows[-1][2] - rows[0][2]) if rows else 0.0
        return {
            "engagement": engagement,
            "total_events": total,
            "findings_by_severity": by_severity,
            "tools_called": tools_called,
            "agents_spawned": agents_spawned,
            "guardrail_violations": guardrail_violations,
            "duration_seconds": duration,
        }

    def write_coverage(self, engagement: str, out_path: str | Path = "COVERAGE.md") -> Path:
        summary = self.engagement_summary(engagement)
        lines = [
            f"# COVERAGE — {engagement}",
            "",
            f"- total events: {summary['total_events']}",
            f"- tools called: {summary['tools_called']}",
            f"- agents spawned: {summary['agents_spawned']}",
            f"- guardrail violations: {summary['guardrail_violations']}",
            f"- duration: {summary['duration_seconds']:.1f}s",
            "",
            "## Findings by severity",
            "",
        ]
        for sev, count in sorted(summary["findings_by_severity"].items()):
            lines.append(f"- {sev}: {count}")
        path = Path(out_path)
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def close(self) -> None:
        self._conn.close()
