"""Neo4j-backed attack graph (opt-in).

Activated automatically by :func:`graph.open_kg` when ``NEO4J_URI`` env is set
(usually by ``swiftsec lab up``). Same :class:`graph.kg.AttackGraph` interface
as :class:`graph.sqlite_kg.SQLiteKG`; agents do not branch on which is active.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

try:
    from neo4j import GraphDatabase  # type: ignore
except ImportError:  # pragma: no cover -- optional
    GraphDatabase = None  # type: ignore

NodeId = str


def _nid(kind: str, key: str) -> NodeId:
    h = hashlib.sha1(f"{kind}::{key}".encode()).hexdigest()[:16]
    return f"{kind}:{h}"


class Neo4jKG:
    def __init__(self, *, uri: str, user: str = "neo4j", password: str = "neo4j") -> None:
        if GraphDatabase is None:
            raise RuntimeError("neo4j driver missing; pip install swiftsec[graph-neo4j]")
        self._driver = GraphDatabase.driver(uri, auth=(user, password))
        # Schema constraint: each node id is unique.
        with self._driver.session() as s:
            s.run("CREATE CONSTRAINT swiftsec_node_id IF NOT EXISTS FOR (n:Node) REQUIRE n.id IS UNIQUE")

    def _merge(self, node_id: NodeId, kind: str, label: str, attrs: dict[str, Any]) -> NodeId:
        with self._driver.session() as s:
            s.run(
                "MERGE (n:Node {id: $id}) "
                "SET n.kind = $kind, n.label = $label, n.attrs = $attrs",
                id=node_id, kind=kind, label=label,
                attrs=json.dumps(attrs, sort_keys=True, default=str),
            )
        return node_id

    def add_host(self, host: str, **attrs: Any) -> NodeId:
        return self._merge(_nid("host", host), "host", host, attrs)

    def add_service(self, host_id: NodeId, port: int, service: str, **attrs: Any) -> NodeId:
        nid = _nid("service", f"{host_id}:{port}/{service}")
        self._merge(nid, "service", f"{service}:{port}", {"port": port, "service": service, **attrs})
        self.add_edge(host_id, nid, "HAS_SERVICE")
        return nid

    def add_vuln(self, target_id: NodeId, cve: str | None, finding: dict[str, Any]) -> NodeId:
        label = cve or finding.get("title") or finding.get("id") or "vuln"
        nid = _nid("vuln", f"{target_id}::{label}::{finding.get('hash', '')}")
        self._merge(nid, "vuln", str(label), {"cve": cve, "finding": finding})
        self.add_edge(target_id, nid, "HAS_VULN")
        return nid

    def add_credential(self, target_id: NodeId, username: str, **attrs: Any) -> NodeId:
        nid = _nid("cred", f"{target_id}:{username}")
        self._merge(nid, "credential", username, attrs)
        self.add_edge(target_id, nid, "HAS_CREDENTIAL")
        return nid

    def add_edge(self, src: NodeId, dst: NodeId, relation: str, **attrs: Any) -> None:
        with self._driver.session() as s:
            s.run(
                "MATCH (a:Node {id: $src}), (b:Node {id: $dst}) "
                f"MERGE (a)-[r:{relation}]->(b) "
                "SET r.attrs = $attrs",
                src=src, dst=dst,
                attrs=json.dumps(attrs, sort_keys=True, default=str),
            )

    def neighbors(self, node_id: NodeId, *, relation: str | None = None) -> list[NodeId]:
        with self._driver.session() as s:
            if relation:
                res = s.run(
                    f"MATCH (a:Node {{id: $id}})-[:{relation}]->(b) RETURN b.id AS id",
                    id=node_id,
                )
            else:
                res = s.run(
                    "MATCH (a:Node {id: $id})-->(b) RETURN b.id AS id",
                    id=node_id,
                )
            return [r["id"] for r in res]

    def multi_hop(self, start: NodeId, *, max_hops: int = 5) -> list[list[NodeId]]:
        with self._driver.session() as s:
            res = s.run(
                "MATCH path = (a:Node {id: $id})-[*1..%d]->(b) "
                "RETURN [n IN nodes(path) | n.id] AS p" % int(max_hops),
                id=start,
            )
            return [r["p"] for r in res]

    def export(self, fmt: Literal["json", "cypher", "graphml"]) -> str:
        with self._driver.session() as s:
            nodes = [dict(r) for r in s.run("MATCH (n:Node) RETURN n.id AS id, n.kind AS kind, n.label AS label, n.attrs AS attrs")]
            edges = [dict(r) for r in s.run("MATCH (a)-[r]->(b) RETURN a.id AS src, b.id AS dst, type(r) AS relation, r.attrs AS attrs")]
        if fmt == "json":
            return json.dumps({"nodes": nodes, "edges": edges}, indent=2, sort_keys=True, default=str)
        if fmt == "cypher":
            lines: list[str] = []
            for n in nodes:
                lines.append(f"MERGE (n:{n['kind'].title()} {{id: '{n['id']}', label: {json.dumps(n['label'])}}});")
            for e in edges:
                lines.append(
                    f"MATCH (a {{id: '{e['src']}'}}), (b {{id: '{e['dst']}'}}) "
                    f"MERGE (a)-[:{e['relation']}]->(b);"
                )
            return "\n".join(lines)
        raise ValueError(f"export fmt={fmt} not implemented for Neo4j backend")

    def close(self) -> None:
        self._driver.close()
