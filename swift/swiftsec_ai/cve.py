"""CVEStore — local NVD mirror for RAG.

Currency is a retrieval problem, not a weights problem: this store incrementally
syncs the NVD 2.0 feed into SQLite (+ an FTS5 full-text index) and serves a compact
context block that the assistant injects into the prompt at query time.

Design notes
------------
* The FTS5 table is **standalone** (its own content), not an external-content table.
  External-content FTS5 silently corrupts when the base table drifts; standalone is
  bulletproof at the cost of storing the description twice.
* If the sqlite build lacks FTS5, we transparently fall back to ``LIKE`` search.
* Network access lives only in :meth:`sync`. Everything else is offline and unit-testable.
"""
from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .config import NVD_CVE_API

# NVD caps any single lastMod window at 120 days; we chunk longer backfills.
_MAX_WINDOW_DAYS = 120
_RESULTS_PER_PAGE = 2000
# Public rate limit is 5 req/30s (~6s each); with an API key 50 req/30s (~0.6s each).
_PAUSE_WITH_KEY = 0.7
_PAUSE_NO_KEY = 6.5
_MAX_RETRIES = 4


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _nvd_ts(dt: datetime) -> str:
    """Format a datetime the way the NVD 2.0 API expects (UTC, millisecond)."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def parse_nvd_cve(cve: dict[str, Any]) -> dict[str, Any]:
    """Flatten one NVD ``vulnerabilities[].cve`` object into a storage row.

    Returns keys: id, published, last_modified, severity, cvss, vector, kev,
    description, raw.
    """
    cve_id = cve.get("id", "")

    description = ""
    for d in cve.get("descriptions", []) or []:
        if d.get("lang") == "en":
            description = d.get("value", "")
            break
    if not description:
        descs = cve.get("descriptions") or []
        if descs:
            description = descs[0].get("value", "")

    cvss: float | None = None
    vector = ""
    severity = ""
    metrics = cve.get("metrics", {}) or {}
    # Prefer CVSS v3.1 > v3.0 > v2.
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        data = entries[0].get("cvssData", {}) or {}
        cvss = data.get("baseScore")
        vector = data.get("vectorString", "") or ""
        # v3 carries baseSeverity in cvssData; v2 carries it on the metric entry.
        severity = (data.get("baseSeverity") or entries[0].get("baseSeverity") or "").upper()
        break

    if not severity and cvss is not None:
        severity = _severity_from_score(cvss)

    kev = 1 if cve.get("cisaExploitAdd") else 0

    return {
        "id": cve_id,
        "published": cve.get("published", "") or "",
        "last_modified": cve.get("lastModified", "") or "",
        "severity": severity or "UNKNOWN",
        "cvss": float(cvss) if cvss is not None else 0.0,
        "vector": vector,
        "kev": kev,
        "description": description,
        "raw": json.dumps(cve, separators=(",", ":")),
    }


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def _fts_query(text: str) -> str:
    """Turn free text into a safe FTS5 MATCH expression (token OR token ...)."""
    tokens = [t for t in "".join(c if c.isalnum() else " " for c in text).split() if t]
    if not tokens:
        return '""'
    return " OR ".join(f'"{t}"' for t in tokens)


class CVEStore:
    def __init__(self, db_path: str | Path = "swiftsec_cve.db", *, nvd_api_key: str = "") -> None:
        self.db_path = str(db_path)
        self.nvd_api_key = nvd_api_key or ""
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._fts = True
        self._init_schema()

    # ------------------------------------------------------------------ schema
    def _init_schema(self) -> None:
        c = self._conn
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS cves (
                id            TEXT PRIMARY KEY,
                published     TEXT,
                last_modified TEXT,
                severity      TEXT,
                cvss          REAL,
                vector        TEXT,
                kev           INTEGER DEFAULT 0,
                description   TEXT,
                raw           TEXT
            )
            """
        )
        c.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_cves_cvss ON cves(cvss)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_cves_kev ON cves(kev)")
        try:
            c.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS cve_fts "
                "USING fts5(cve_id UNINDEXED, description)"
            )
        except sqlite3.OperationalError:
            # sqlite built without FTS5 — degrade to LIKE search.
            self._fts = False
        c.commit()

    # ------------------------------------------------------------------ writes
    def upsert_cves(self, items: Iterable[dict[str, Any]]) -> int:
        """Insert/replace parsed CVE rows. Returns the number written."""
        c = self._conn
        n = 0
        for row in items:
            cve_id = row.get("id")
            if not cve_id:
                continue
            c.execute(
                """
                INSERT INTO cves
                    (id, published, last_modified, severity, cvss, vector, kev, description, raw)
                VALUES (:id, :published, :last_modified, :severity, :cvss, :vector, :kev, :description, :raw)
                ON CONFLICT(id) DO UPDATE SET
                    published=excluded.published,
                    last_modified=excluded.last_modified,
                    severity=excluded.severity,
                    cvss=excluded.cvss,
                    vector=excluded.vector,
                    kev=excluded.kev,
                    description=excluded.description,
                    raw=excluded.raw
                """,
                {
                    "id": cve_id,
                    "published": row.get("published", ""),
                    "last_modified": row.get("last_modified", ""),
                    "severity": row.get("severity", "UNKNOWN"),
                    "cvss": float(row.get("cvss", 0.0) or 0.0),
                    "vector": row.get("vector", ""),
                    "kev": int(row.get("kev", 0) or 0),
                    "description": row.get("description", ""),
                    "raw": row.get("raw", ""),
                },
            )
            if self._fts:
                c.execute("DELETE FROM cve_fts WHERE cve_id = ?", (cve_id,))
                c.execute(
                    "INSERT INTO cve_fts (cve_id, description) VALUES (?, ?)",
                    (cve_id, row.get("description", "")),
                )
            n += 1
        c.commit()
        return n

    def set_meta(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        self._conn.commit()

    def get_meta(self, key: str) -> str | None:
        row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    # ------------------------------------------------------------------ reads
    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) AS n FROM cves").fetchone()["n"])

    def search(
        self,
        query: str,
        limit: int = 10,
        min_cvss: float | None = None,
        kev_only: bool = False,
    ) -> list[dict[str, Any]]:
        """Search the store, ordered KEV → CVSS → recency (last_modified)."""
        params: list[Any] = []
        where: list[str] = []

        base = "SELECT c.* FROM cves c"
        if query and query.strip() and self._fts:
            base = (
                "SELECT c.* FROM cve_fts f JOIN cves c ON c.id = f.cve_id "
                "WHERE cve_fts MATCH ?"
            )
            params.append(_fts_query(query))
        elif query and query.strip():
            where.append("c.description LIKE ?")
            params.append(f"%{query.strip()}%")

        if min_cvss is not None:
            where.append("c.cvss >= ?")
            params.append(float(min_cvss))
        if kev_only:
            where.append("c.kev = 1")

        if where:
            joiner = " AND " if "WHERE" in base else " WHERE "
            base += joiner + " AND ".join(where)

        base += " ORDER BY c.kev DESC, c.cvss DESC, c.last_modified DESC LIMIT ?"
        params.append(int(limit))

        rows = self._conn.execute(base, params).fetchall()
        return [dict(r) for r in rows]

    def retrieve_context(self, query: str, limit: int = 5) -> str:
        """Compact, prompt-injectable text block of the most relevant CVEs."""
        hits = self.search(query, limit=limit)
        if not hits:
            return ""
        lines = ["# Retrieved CVE context (from local NVD mirror)"]
        for h in hits:
            kev = " [CISA-KEV]" if h.get("kev") else ""
            cvss = h.get("cvss") or 0.0
            desc = (h.get("description") or "").strip().replace("\n", " ")
            if len(desc) > 400:
                desc = desc[:397] + "..."
            lines.append(
                f"- {h['id']} (CVSS {cvss:.1f} {h.get('severity', '?')}{kev}): {desc}"
            )
        return "\n".join(lines)

    # ------------------------------------------------------------------ sync
    def sync(self, force: bool = False, initial_days: int | None = None) -> dict[str, Any]:
        """Incrementally pull NVD CVEs modified since the last sync.

        Honors a minimum sync interval unless ``force``. Chunks windows longer
        than 120 days and paginates each window. Returns a summary dict.
        """
        import requests  # local import keeps requests off the offline import path

        now = _now_utc()
        last_sync_raw = self.get_meta("last_sync")

        # Min-interval guard (skip unless forced).
        if not force and last_sync_raw:
            try:
                last_dt = datetime.fromisoformat(last_sync_raw)
                if last_dt.tzinfo is None:
                    last_dt = last_dt.replace(tzinfo=timezone.utc)
                interval = self.get_meta("min_sync_interval_seconds")
                gap = float(interval) if interval else 7200.0
                if (now - last_dt).total_seconds() < gap:
                    return {
                        "status": "skipped",
                        "reason": "within min sync interval (use force=True to override)",
                        "last_sync": last_sync_raw,
                        "count": self.count(),
                    }
            except (ValueError, TypeError):
                pass

        # Determine the start of the window to pull.
        if last_sync_raw and not force:
            try:
                start = datetime.fromisoformat(last_sync_raw)
                if start.tzinfo is None:
                    start = start.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                start = now - timedelta(days=initial_days or 30)
        else:
            start = now - timedelta(days=initial_days or 30)

        headers = {"apiKey": self.nvd_api_key} if self.nvd_api_key else {}
        pause = _PAUSE_WITH_KEY if self.nvd_api_key else _PAUSE_NO_KEY

        total_written = 0
        windows = list(_chunk_windows(start, now, _MAX_WINDOW_DAYS))
        for win_start, win_end in windows:
            total_written += self._sync_window(
                requests, headers, pause, win_start, win_end
            )

        self.set_meta("last_sync", _nvd_ts(now))
        return {
            "status": "ok",
            "windows": len(windows),
            "written": total_written,
            "count": self.count(),
            "last_sync": _nvd_ts(now),
        }

    def _sync_window(self, requests, headers, pause, win_start, win_end) -> int:
        written = 0
        start_index = 0
        while True:
            params = {
                "lastModStartDate": _nvd_ts(win_start),
                "lastModEndDate": _nvd_ts(win_end),
                "resultsPerPage": _RESULTS_PER_PAGE,
                "startIndex": start_index,
            }
            data = self._nvd_get(requests, headers, params, pause)
            vulns = data.get("vulnerabilities", []) or []
            rows = [parse_nvd_cve(v.get("cve", {})) for v in vulns if v.get("cve")]
            written += self.upsert_cves(rows)

            total = int(data.get("totalResults", 0) or 0)
            per_page = int(data.get("resultsPerPage", 0) or 0)
            start_index += per_page if per_page else len(rows)
            if not vulns or start_index >= total:
                break
            time.sleep(pause)
        return written

    @staticmethod
    def _nvd_get(requests, headers, params, pause) -> dict[str, Any]:
        last_err: Exception | None = None
        for attempt in range(_MAX_RETRIES):
            try:
                resp = requests.get(
                    NVD_CVE_API, params=params, headers=headers, timeout=60
                )
                if resp.status_code in (403, 429, 503):
                    # Rate-limited / throttled — back off and retry.
                    time.sleep(pause * (attempt + 2))
                    last_err = RuntimeError(f"NVD HTTP {resp.status_code}")
                    continue
                resp.raise_for_status()
                return resp.json()
            except Exception as e:
                last_err = e
                time.sleep(pause * (attempt + 1))
        raise RuntimeError(f"NVD request failed after {_MAX_RETRIES} retries: {last_err}")

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass


def _chunk_windows(start: datetime, end: datetime, max_days: int):
    """Yield (start, end) pairs no wider than ``max_days``."""
    if start >= end:
        return
    cur = start
    step = timedelta(days=max_days)
    while cur < end:
        nxt = min(cur + step, end)
        yield cur, nxt
        cur = nxt
