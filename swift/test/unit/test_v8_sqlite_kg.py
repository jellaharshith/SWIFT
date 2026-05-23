"""v8.0 -- SQLite knowledge graph."""
from __future__ import annotations

import json

import pytest

from graph.sqlite_kg import SQLiteKG


@pytest.fixture()
def kg(tmp_path):
    return SQLiteKG(tmp_path / "kg.sqlite")


def test_add_host_idempotent(kg):
    a = kg.add_host("example.com", note="seed")
    b = kg.add_host("example.com", note="seed-again")
    assert a == b


def test_add_service_creates_edge(kg):
    h = kg.add_host("example.com")
    s = kg.add_service(h, 443, "https", tls="1.3")
    assert s in kg.neighbors(h, relation="HAS_SERVICE")


def test_add_vuln_creates_edge_and_payload(kg):
    h = kg.add_host("example.com")
    s = kg.add_service(h, 443, "https")
    v = kg.add_vuln(s, cve="CVE-2024-9999", finding={"title": "demo", "hash": "abc"})
    assert v in kg.neighbors(s, relation="HAS_VULN")


def test_multi_hop_returns_paths(kg):
    h = kg.add_host("example.com")
    s = kg.add_service(h, 443, "https")
    v = kg.add_vuln(s, cve="CVE-2024-9999", finding={"hash": "h1"})
    paths = kg.multi_hop(h, max_hops=3)
    # At least one path from host -> service -> vuln
    assert any(s in p and v in p for p in paths)


def test_export_json_round_trip(kg):
    h = kg.add_host("example.com")
    kg.add_service(h, 80, "http")
    blob = kg.export("json")
    data = json.loads(blob)
    assert any(n["label"] == "example.com" for n in data["nodes"])
    assert any(e["relation"] == "HAS_SERVICE" for e in data["edges"])


def test_export_cypher_contains_merge(kg):
    h = kg.add_host("example.com")
    kg.add_service(h, 80, "http")
    cypher = kg.export("cypher")
    assert "MERGE" in cypher
