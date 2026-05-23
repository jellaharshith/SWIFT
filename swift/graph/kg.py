"""Abstract attack-graph interface."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal, Protocol, runtime_checkable

NodeId = str


@runtime_checkable
class AttackGraph(Protocol):
    """Pentest knowledge graph.

    Implementations must be safe for sequential single-process use; concurrent
    access semantics are backend-specific (Neo4j: native; SQLite: caller must
    serialize writes).
    """

    def add_host(self, host: str, **attrs: Any) -> NodeId: ...
    def add_service(self, host_id: NodeId, port: int, service: str, **attrs: Any) -> NodeId: ...
    def add_vuln(self, target_id: NodeId, cve: str | None, finding: dict[str, Any]) -> NodeId: ...
    def add_credential(self, target_id: NodeId, username: str, **attrs: Any) -> NodeId: ...
    def add_edge(self, src: NodeId, dst: NodeId, relation: str, **attrs: Any) -> None: ...
    def neighbors(self, node_id: NodeId, *, relation: str | None = None) -> list[NodeId]: ...
    def multi_hop(self, start: NodeId, *, max_hops: int = 5) -> list[list[NodeId]]: ...
    def export(self, fmt: Literal["json", "cypher", "graphml"]) -> str: ...
    def close(self) -> None: ...


_singleton: AttackGraph | None = None


def open_kg(*, path: str | Path | None = None, force_new: bool = False) -> AttackGraph:
    """Return a process-wide :class:`AttackGraph`.

    Backend selection:

    * ``NEO4J_URI`` env set -> :class:`Neo4jKG`
    * otherwise              -> :class:`SQLiteKG` at ``path`` (default ``.swift-artifacts/kg.sqlite``)
    """
    global _singleton
    if _singleton is not None and not force_new:
        return _singleton

    neo4j_uri = os.getenv("NEO4J_URI")
    if neo4j_uri:
        from graph.neo4j_kg import Neo4jKG  # lazy: optional dep
        _singleton = Neo4jKG(
            uri=neo4j_uri,
            user=os.getenv("NEO4J_USER", "neo4j"),
            password=os.getenv("NEO4J_PASSWORD", "neo4j"),
        )
        return _singleton

    from graph.sqlite_kg import SQLiteKG
    db_path = Path(path) if path else Path(".swift-artifacts/kg.sqlite")
    db_path.parent.mkdir(parents=True, exist_ok=True)
    _singleton = SQLiteKG(db_path)
    return _singleton


def get_kg() -> AttackGraph:
    """Return the open graph or open a new one with defaults."""
    if _singleton is None:
        return open_kg()
    return _singleton
