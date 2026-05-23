"""SQLite-backed attack graph with NetworkX for multi-hop queries.

Tables:
    nodes(id PK, kind, label, attrs JSON)
    edges(src, dst, relation, attrs JSON, PK(src, dst, relation))

Multi-hop, neighbor, and export operations rehydrate a :class:`networkx.DiGraph`
on demand. For interactive workflows this is fine up to ~100k nodes; beyond
that switch to :class:`Neo4jKG` by setting ``NEO4J_URI``.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Literal

try:
    import networkx as nx
except ImportError:  # pragma: no cover -- optional dep, fail late
    nx = None  # type: ignore

NodeId = str

_SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
    id    TEXT PRIMARY KEY,
    kind  TEXT NOT NULL,
    label TEXT NOT NULL,
    attrs TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS edges (
    src      TEXT NOT NULL,
    dst      TEXT NOT NULL,
    relation TEXT NOT NULL,
    attrs    TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (src, dst, relation),
    FOREIGN KEY (src) REFERENCES nodes(id) ON DELETE CASCADE,
    FOREIGN KEY (dst) REFERENCES nodes(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_nodes_kind ON nodes(kind);
CREATE INDEX IF NOT EXISTS idx_edges_relation ON edges(relation);
"""


def _nid(kind: str, key: str) -> NodeId:
    h = hashlib.sha1(f"{kind}::{key}".encode()).hexdigest()[:16]
    return f"{kind}:{h}"


class SQLiteKG:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ------------------------------------------------------------------ writes

    def _upsert_node(self, node_id: NodeId, kind: str, label: str, attrs: dict[str, Any]) -> NodeId:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO nodes(id, kind, label, attrs) VALUES (?, ?, ?, ?)",
                (node_id, kind, label, json.dumps(attrs, sort_keys=True, default=str)),
            )
            self._conn.commit()
        return node_id

    def add_host(self, host: str, **attrs: Any) -> NodeId:
        nid = _nid("host", host)
        return self._upsert_node(nid, "host", host, attrs)

    def add_service(self, host_id: NodeId, port: int, service: str, **attrs: Any) -> NodeId:
        key = f"{host_id}:{port}/{service}"
        nid = _nid("service", key)
        self._upsert_node(nid, "service", f"{service}:{port}", {"port": port, "service": service, **attrs})
        self.add_edge(host_id, nid, "HAS_SERVICE")
        return nid

    def add_vuln(self, target_id: NodeId, cve: str | None, finding: dict[str, Any]) -> NodeId:
        label = cve or finding.get("title") or finding.get("id") or "vuln"
        key = f"{target_id}::{label}::{finding.get('hash', '')}"
        nid = _nid("vuln", key)
        self._upsert_node(nid, "vuln", str(label), {"cve": cve, "finding": finding})
        self.add_edge(target_id, nid, "HAS_VULN")
        return nid

    def add_credential(self, target_id: NodeId, username: str, **attrs: Any) -> NodeId:
        nid = _nid("cred", f"{target_id}:{username}")
        self._upsert_node(nid, "credential", username, attrs)
        self.add_edge(target_id, nid, "HAS_CREDENTIAL")
        return nid

    def add_edge(self, src: NodeId, dst: NodeId, relation: str, **attrs: Any) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO edges(src, dst, relation, attrs) VALUES (?, ?, ?, ?)",
                (src, dst, relation, json.dumps(attrs, sort_keys=True, default=str)),
            )
            self._conn.commit()

    # ------------------------------------------------------------------ reads

    def neighbors(self, node_id: NodeId, *, relation: str | None = None) -> list[NodeId]:
        cur = self._conn.cursor()
        if relation:
            cur.execute("SELECT dst FROM edges WHERE src = ? AND relation = ?", (node_id, relation))
        else:
            cur.execute("SELECT dst FROM edges WHERE src = ?", (node_id,))
        return [row[0] for row in cur.fetchall()]

    def _hydrate(self) -> "nx.DiGraph":
        if nx is None:
            raise RuntimeError("networkx not installed; pip install swiftsec[graph]")
        g = nx.DiGraph()
        for row in self._conn.execute("SELECT id, kind, label, attrs FROM nodes"):
            g.add_node(row[0], kind=row[1], label=row[2], attrs=json.loads(row[3]))
        for row in self._conn.execute("SELECT src, dst, relation, attrs FROM edges"):
            g.add_edge(row[0], row[1], relation=row[2], attrs=json.loads(row[3]))
        return g

    def multi_hop(self, start: NodeId, *, max_hops: int = 5) -> list[list[NodeId]]:
        g = self._hydrate()
        if start not in g:
            return []
        paths: list[list[NodeId]] = []
        for target in g.nodes:
            if target == start:
                continue
            try:
                p = nx.shortest_path(g, source=start, target=target)
            except nx.NetworkXNoPath:
                continue
            if 1 < len(p) <= max_hops + 1:
                paths.append(p)
        return paths

    def export(self, fmt: Literal["json", "cypher", "graphml"]) -> str:
        if fmt == "json":
            nodes = [
                {"id": r[0], "kind": r[1], "label": r[2], "attrs": json.loads(r[3])}
                for r in self._conn.execute("SELECT id, kind, label, attrs FROM nodes")
            ]
            edges = [
                {"src": r[0], "dst": r[1], "relation": r[2], "attrs": json.loads(r[3])}
                for r in self._conn.execute("SELECT src, dst, relation, attrs FROM edges")
            ]
            return json.dumps({"nodes": nodes, "edges": edges}, indent=2, sort_keys=True)
        if fmt == "cypher":
            lines: list[str] = []
            for r in self._conn.execute("SELECT id, kind, label FROM nodes"):
                lines.append(f"MERGE (n:{r[1].title()} {{id: '{r[0]}', label: {json.dumps(r[2])}}});")
            for r in self._conn.execute("SELECT src, dst, relation FROM edges"):
                lines.append(
                    f"MATCH (a {{id: '{r[0]}'}}), (b {{id: '{r[1]}'}}) "
                    f"MERGE (a)-[:{r[2]}]->(b);"
                )
            return "\n".join(lines)
        if fmt == "graphml":
            g = self._hydrate()
            from io import BytesIO
            buf = BytesIO()
            nx.write_graphml(g, buf)
            return buf.getvalue().decode()
        raise ValueError(f"unknown export fmt: {fmt}")

    def close(self) -> None:
        with self._lock:
            self._conn.close()
