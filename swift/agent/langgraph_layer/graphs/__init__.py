"""Sub-graph definitions + dispatcher.

Ten graph topologies, each a DAG of :class:`agent.langgraph_layer.specialists.Specialist`
invocations. When ``langgraph`` is importable we use it; otherwise the in-
process :class:`MiniGraph` runner walks the same edges. Findings end up in
``state['findings']`` either way.
"""
from __future__ import annotations

import importlib
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from agent.langgraph_layer.runtime import run_specialist
from agent.langgraph_layer.specialists import SPECIALISTS, Specialist

log = logging.getLogger("swift.langgraph_layer.graphs")

# Re-export for callers that just want the type
State = dict


@dataclass
class _NodeDef:
    spec: Specialist
    next: tuple[str, ...] = ()         # downstream node names ("" = terminal)
    goal_template: str = ""            # filled into state['goal'] before running


@dataclass
class _GraphDef:
    name: str
    nodes: dict[str, _NodeDef]
    entry: str
    description: str = ""


def _node(name: str, *, next: Iterable[str] = (), goal: str = "") -> _NodeDef:
    spec = SPECIALISTS[name]
    return _NodeDef(spec=spec, next=tuple(next), goal_template=goal)


# --------------------------------------------------------------------- topology

# decepticon (main): recon -> exploit -> post_exploit -> analyst
_DECEPTICON = _GraphDef(
    name="decepticon",
    description="Main red-team kill chain.",
    entry="recon",
    nodes={
        "recon":        _node("recon",        next=("exploit",),       goal="Build a target inventory for the engagement."),
        "exploit":      _node("exploit",      next=("post_exploit",),  goal="Construct exploit chains from the recon inventory."),
        "post_exploit": _node("post_exploit", next=("analyst",),       goal="Assess persistence / lateral / exfil feasibility."),
        "analyst":      _node("analyst",      next=(),                 goal="Synthesize findings into a chained narrative."),
    },
)

# vulnresearch (5-stage pipeline)
_VULNRESEARCH = _GraphDef(
    name="vulnresearch",
    description="Scanner -> Detector -> Verifier -> Exploiter -> Patcher.",
    entry="scanner",
    nodes={
        "scanner":    _node("scanner",    next=("detector",),  goal="Surface candidate vulnerabilities for the target."),
        "detector":   _node("detector",   next=("verifier",),  goal="Label Scanner output TP/FP/needs-verification."),
        "verifier":   _node("verifier",   next=("exploiter",), goal="Prove or refute findings tagged needs-verification."),
        "exploiter":  _node("exploiter",  next=("patcher",),   goal="Build a non-destructive PoC for verified findings."),
        "patcher":    _node("patcher",    next=(),             goal="Propose a minimal fix per finding."),
    },
)

# Standalone phase graphs (callable independently)
_RECON_ONLY        = _GraphDef("recon",        {"recon":        _node("recon",        goal="Recon only.")},        "recon")
_EXPLOIT_ONLY      = _GraphDef("exploit",      {"exploit":      _node("exploit",      goal="Exploit only.")},      "exploit")
_POSTEXPLOIT_ONLY  = _GraphDef("postexploit",  {"post_exploit": _node("post_exploit", goal="Post-exploit only.")}, "post_exploit")

# Domain-specific graphs
_AD = _GraphDef(
    name="ad_operator",
    entry="ad_operator",
    nodes={"ad_operator": _node("ad_operator", goal="Enumerate authorized AD surface.")},
)
_CLOUD = _GraphDef(
    name="cloud_hunter",
    entry="cloud_hunter",
    nodes={"cloud_hunter": _node("cloud_hunter", goal="Audit authorized cloud surface.")},
)
_CONTRACTS = _GraphDef(
    name="contract_auditor",
    entry="contract_auditor",
    nodes={"contract_auditor": _node("contract_auditor", goal="Audit the supplied contracts.")},
)
_REVERSER = _GraphDef(
    name="reverser",
    entry="reverser",
    nodes={"reverser": _node("reverser", goal="Reverse-engineer the supplied artifact.")},
)
_ANALYST = _GraphDef(
    name="analyst",
    entry="analyst",
    nodes={"analyst": _node("analyst", goal="Summarize and chain prior findings.")},
)
_SOUNDWAVE = _GraphDef(
    name="soundwave",
    entry="soundwave",
    nodes={"soundwave": _node("soundwave", goal="Interview operator and draft engagement docs.")},
)


GRAPHS: dict[str, _GraphDef] = {
    g.name: g for g in (
        _DECEPTICON, _VULNRESEARCH,
        _RECON_ONLY, _EXPLOIT_ONLY, _POSTEXPLOIT_ONLY,
        _AD, _CLOUD, _CONTRACTS, _REVERSER, _ANALYST, _SOUNDWAVE,
    )
}
GRAPH_NAMES = tuple(GRAPHS.keys())


def list_graphs() -> list[dict[str, str]]:
    return [{"name": g.name, "entry": g.entry, "description": g.description} for g in GRAPHS.values()]


# --------------------------------------------------------------------- runner

class MiniGraph:
    """Tiny DAG runner used when ``langgraph`` is not installed.

    Runs nodes in topological order starting from ``entry``. Each node calls
    :func:`run_specialist`. Findings accumulate in ``state['findings']``.
    """

    def __init__(self, graph: _GraphDef) -> None:
        self.graph = graph

    def run(self, state: State) -> State:
        visited: set[str] = set()
        order: list[str] = []
        self._dfs(self.graph.entry, visited, order)
        for nname in order:
            node = self.graph.nodes[nname]
            state["goal"] = node.goal_template or state.get("goal", "")
            log.info("minigraph.run node=%s phase=%s", nname, node.spec.phase)
            run_specialist(node.spec, state)
        return state

    def _dfs(self, n: str, visited: set[str], order: list[str]) -> None:
        if n in visited or n not in self.graph.nodes:
            return
        visited.add(n)
        order.append(n)
        for nxt in self.graph.nodes[n].next:
            self._dfs(nxt, visited, order)


def _have_langgraph() -> bool:
    try:
        importlib.import_module("langgraph")
        return True
    except Exception:
        return False


def run_subgraph(graph_name: str, state: State | None = None) -> State:
    """Public entry-point. Looks up ``graph_name`` and executes it.

    The shared state must already contain (at minimum):

    * ``roe``         -- a loaded :class:`security.roe.ROE`
    * ``engagement``  -- engagement metadata dict (project to prompt)

    Optional keys ``llm_client``, ``goal``, ``answers`` (for soundwave),
    ``opplan`` are read when present.
    """
    if graph_name not in GRAPHS:
        raise KeyError(f"unknown graph: {graph_name}; known: {sorted(GRAPHS)}")
    state = state or {}
    state.setdefault("findings", [])
    state.setdefault("transcripts", {})
    graph = GRAPHS[graph_name]
    # Real-langgraph integration point: when present, build an equivalent
    # StateGraph here and run it. Same nodes + edges + state shape.
    return MiniGraph(graph).run(state)
