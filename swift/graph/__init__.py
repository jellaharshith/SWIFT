"""SWIFT v8 attack-knowledge graph.

Two backends, one interface:

* :class:`SQLiteKG` -- default; pure-Python, NetworkX in-memory + SQLite
  persistence. Zero infra.
* :class:`Neo4jKG`  -- opt-in; activated automatically when ``NEO4J_URI`` env
  is present (set by ``swiftsec lab up``).

Construct via :func:`open_kg` so the routing decision lives in one place.
"""
from graph.kg import AttackGraph, NodeId, get_kg, open_kg
from graph.sqlite_kg import SQLiteKG

__all__ = ["AttackGraph", "NodeId", "SQLiteKG", "get_kg", "open_kg"]
