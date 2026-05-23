"""v8.0 -- LangGraph layer topology + dispatch (no real LLM calls)."""
from __future__ import annotations

from agent.langgraph_layer import GRAPH_NAMES, list_graphs, run_subgraph
from agent.langgraph_layer.specialists import SPECIALISTS


def test_specialist_count():
    # 16 specialists ported from Decepticon
    assert len(SPECIALISTS) == 16


def test_graph_names_stable():
    for expected in ("decepticon", "vulnresearch", "recon", "exploit",
                     "postexploit", "ad_operator", "cloud_hunter",
                     "contract_auditor", "reverser", "analyst", "soundwave"):
        assert expected in GRAPH_NAMES


def test_list_graphs_returns_descriptions():
    items = list_graphs()
    names = {i["name"] for i in items}
    assert "decepticon" in names
    for i in items:
        assert "entry" in i


def test_run_subgraph_unknown_raises():
    import pytest
    with pytest.raises(KeyError):
        run_subgraph("nonexistent_graph", {})
