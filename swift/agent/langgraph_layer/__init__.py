"""LangGraph multi-agent layer (Decepticon-ported).

The public surface is intentionally small:

    from agent.langgraph_layer import run_subgraph, list_graphs

``run_subgraph`` accepts a graph name (one of :data:`GRAPH_NAMES`) and a
shared :class:`State`. Findings are appended into ``state["findings"]`` as
plain dicts that :func:`output.report_normalizer.normalize` already handles.

The wrap-don't-replace decision means: SWIFT's existing
``agent/orchestrator.py`` keeps the Haiku->Sonnet pipeline; this layer is
only invoked from new CLI subcommands (``redteam --kill-chain full``,
``vuln-pipeline``, ``engage``, ...).

LangGraph itself is an *optional* dependency: when ``langgraph`` is
importable we use it; otherwise the in-process :class:`MiniGraph` runner
walks the same DAG. Either way the agent prompts and tool wirings are
identical.
"""
from agent.langgraph_layer.graphs import (
    GRAPH_NAMES,
    Specialist,
    State,
    list_graphs,
    run_subgraph,
)

__all__ = ["GRAPH_NAMES", "Specialist", "State", "list_graphs", "run_subgraph"]
