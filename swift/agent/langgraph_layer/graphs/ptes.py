"""PTES 7-phase graph.

Topology: pre_engage → intel → threat_model → vuln → exploit_phase → post_exploit → report_phase.

Each phase writes an artifact to state['phase_artifacts'][phase_name].
The report_phase node reads all prior artifacts to produce the Rosén narrative.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from agent.langgraph_layer.graphs import (
    _GraphDef, _NodeDef, _node, GRAPHS, MiniGraph, State, run_subgraph
)
from agent.langgraph_layer.specialists import get_specialist_with_doctrine

log = logging.getLogger("swift.ptes")

PHASE_NAMES = [
    "pre_engage", "intel", "threat_model", "vuln",
    "exploit_phase", "post_exploit", "report_phase",
]


def _ptes_node(spec_name: str, *, next: tuple[str, ...] = (), goal: str = "") -> _NodeDef:
    """Like _node() but uses doctrine-injected specialist."""
    spec = get_specialist_with_doctrine(spec_name)
    return _NodeDef(spec=spec, next=next, goal_template=goal)


_PTES_GRAPH = _GraphDef(
    name="ptes",
    description="PTES 7-phase: Pre-engage → Intel → Threat-model → Vuln → Exploit → Post-exploit → Report.",
    entry="pre_engage",
    nodes={
        "pre_engage":   _ptes_node("soundwave",         next=("intel",),          goal="Phase 1 Pre-Engagement: interview operator, confirm scope/ROE/contacts, produce OPPLAN artifact."),
        "intel":        _ptes_node("recon",             next=("threat_model",),   goal="Phase 2 Intelligence Gathering: expand the full attack surface using Haddix methodology before touching anything."),
        "threat_model": _ptes_node("threat_modeler",    next=("vuln",),           goal="Phase 3 Threat Modeling: rank attack paths by feasibility × impact using KG and intel. Apply Mitnick trust-gap lens."),
        "vuln":         _ptes_node("scanner",           next=("exploit_phase",),  goal="Phase 4 Vulnerability Analysis: run authorized scanners and classify findings TP/FP/needs-verification."),
        "exploit_phase":_ptes_node("exploiter",         next=("post_exploit",),   goal="Phase 5 Exploitation: build non-destructive PoCs for verified findings. Apply Mitnick mindset to auth/trust bugs."),
        "post_exploit": _ptes_node("post_exploit",      next=("report_phase",),   goal="Phase 6 Post-Exploitation: assess persistence, lateral movement, data exfil feasibility. Simulate-only."),
        "report_phase": _ptes_node("report_formatter",  next=(),                  goal="Phase 7 Reporting: produce Rosén-narrative report from accumulated findings and phase artifacts."),
    },
)

# Register in global GRAPHS
GRAPHS["ptes"] = _PTES_GRAPH


class PTESRunner:
    """Runs the PTES 7-phase graph with artifact capture and stop-after support."""

    def __init__(
        self,
        mode: str = "pentest",
        depth: str = "standard",
        stop_after: str | None = None,
        out_dir: str = ".swift-artifacts/ptes",
    ) -> None:
        self.mode = mode
        self.depth = depth
        self.stop_after = stop_after
        self.out_dir = Path(out_dir)

    def run(self, state: State) -> State:
        state.setdefault("findings", [])
        state.setdefault("phase_artifacts", {})
        state["ptes_mode"] = self.mode
        state["ptes_depth"] = self.depth

        self.out_dir.mkdir(parents=True, exist_ok=True)

        nodes_in_order = [
            "pre_engage", "intel", "threat_model", "vuln",
            "exploit_phase", "post_exploit", "report_phase",
        ]

        for i, node_name in enumerate(nodes_in_order):
            node = _PTES_GRAPH.nodes[node_name]
            state["goal"] = node.goal_template
            log.info("ptes.run phase=%d/%d node=%s", i + 1, len(nodes_in_order), node_name)

            from agent.langgraph_layer.runtime import run_specialist
            run_specialist(node.spec, state)

            artifact_key = f"phase_{i + 1}_{node_name}"
            artifact_path = self.out_dir / f"{artifact_key}.md"
            findings_snapshot = [f for f in state.get("findings", [])]
            _write_artifact(artifact_path, node_name, i + 1, findings_snapshot, state)
            state["phase_artifacts"][node_name] = str(artifact_path)
            log.info("ptes.artifact written path=%s", artifact_path)

            if self.stop_after and node_name == self.stop_after:
                log.info("ptes.stop_after=%s reached, halting.", self.stop_after)
                break

        return state


def _write_artifact(path: Path, phase_name: str, phase_num: int, findings: list, state: dict) -> None:
    lines = [
        f"# PTES Phase {phase_num}: {phase_name.replace('_', ' ').title()}",
        "",
        f"**Mode:** {state.get('ptes_mode', 'pentest')}  ",
        f"**Depth:** {state.get('ptes_depth', 'standard')}",
        "",
        f"## Findings at phase exit ({len(findings)} total)",
        "",
    ]
    for f in findings:
        fdict = f if isinstance(f, dict) else (f.__dict__ if hasattr(f, "__dict__") else {"finding": str(f)})
        severity = fdict.get("severity", "?")
        title = fdict.get("title", fdict.get("vuln_type", "unknown"))
        lines.append(f"- [{severity.upper()}] {title}")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def run_ptes(state: State, *, mode: str = "pentest", depth: str = "standard",
             stop_after: str | None = None, out_dir: str = ".swift-artifacts/ptes") -> State:
    """Public entry-point for the PTES 7-phase run."""
    return PTESRunner(mode=mode, depth=depth, stop_after=stop_after, out_dir=out_dir).run(state)
