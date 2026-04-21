"""Bounded exploit-chain auditing layer — graph-first, memory-safe pipeline.

Replaces the previous O(n²) pair-enumeration + unlimited DFS approach with:
1. Pre-filtered findings (≤ MAX_FINDINGS_FOR_CHAINING via prefilter_findings).
2. Bounded exploit graph (≤ MAX_GRAPH_NODES nodes, ≤ MAX_GRAPH_EDGES edges).
3. Bounded DFS path search (≤ MAX_CHAIN_CANDIDATES paths, ≤ MAX_CHAIN_DEPTH deep).
4. Deterministic ranking (top MAX_RANKED_CHAINS returned).
5. Memory guards at every stage — partial results returned instead of crashing.

The LLM is NOT called from this module. Chain construction is entirely
deterministic and can be audited without model access.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from agent.models import AttackStep, ExploitChain, Vulnerability
from triage.exploit_graph import (
    MAX_CHAIN_CANDIDATES,
    MAX_CHAIN_DEPTH,
    MAX_RANKED_CHAINS,
    AttackPath,
    ExploitGraph,
    GraphBuildResult,
    _is_memory_safe,
    _memory_usage_percent,
    build_graph,
    find_bounded_attack_paths,
    rank_attack_paths,
    summarize_graph_metrics,
)
from triage.severity_ranker import SeverityRanker

logger = logging.getLogger("swift.vuln_chain_auditor")


@dataclass
class AuditorResult:
    """Result from the bounded exploit-chain auditor.

    Fields:
        exploit_chains:    Ranked ExploitChain objects (may be empty on limits).
        ranked_findings:   Top findings by combined risk + chain-impact score.
        status:            "complete" or "partial" (a resource limit was hit).
        reason:            Cutoff reason when status is "partial", else "".
        graph_metrics:     Node/edge counts and memory % for status reporting.
        dropped_candidates: Path candidates pruned by the ranking cap.
    """
    exploit_chains: List[ExploitChain]
    ranked_findings: List[Vulnerability]
    status: str = "complete"
    reason: str = ""
    graph_metrics: Dict = field(default_factory=dict)
    dropped_candidates: int = 0


def _attack_path_to_chain(
    path: AttackPath,
    graph: ExploitGraph,
    vuln_map: Dict[str, Vulnerability],
    index: int,
) -> Optional[ExploitChain]:
    """Convert an AttackPath to an ExploitChain data model object.

    Returns None when fewer than two valid (mapped) nodes exist — a single-node
    "chain" is not a chain and should be excluded from results.
    """
    valid_nodes = [nid for nid in path.nodes if nid in vuln_map]
    if len(valid_nodes) < 2:
        return None

    attack_steps = [
        AttackStep(
            step=i + 1,
            description=(
                f"Exploit {vuln_map[nid].vuln_type} in "
                f"{vuln_map[nid].file_path}:{vuln_map[nid].line_number}"
            ),
            vuln_id=nid,
            entry_point=f"{vuln_map[nid].file_path}:{vuln_map[nid].line_number}",
        )
        for i, nid in enumerate(valid_nodes)
    ]

    _sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    severities = [vuln_map[nid].severity.upper() for nid in valid_nodes]
    max_sev = max(severities, key=lambda s: _sev_order.get(s, 0), default="LOW")

    confidence = min(
        0.99,
        sum(vuln_map[nid].confidence for nid in valid_nodes) / len(valid_nodes),
    )

    # Build chain name from graph's canonical vuln_class labels
    chain_name = " → ".join(
        (graph.nodes[nid].vuln_class if nid in graph.nodes else vuln_map[nid].vuln_type)
        for nid in valid_nodes
    )

    attack_path_str = "\n".join(
        f"{step.step}. {step.description}" for step in attack_steps
    )

    return ExploitChain(
        chain_id=f"CHAIN-{index:03d}",
        name=chain_name,
        vulnerability_ids=valid_nodes,
        attack_path=attack_path_str,
        entry_point=attack_steps[0].entry_point if attack_steps else "",
        impact=(
            f"Chained exploit with {path.estimated_impact} impact "
            f"(composite score={path.score:.2f}, depth={len(valid_nodes)})"
        ),
        severity=max_sev,
        confidence=round(confidence, 3),
        attack_steps=attack_steps,
    )


class VulnerabilityChainAuditor:
    """Bounded exploit-chain auditor using the deterministic graph-first pipeline.

    This class orchestrates the complete chain detection workflow without
    calling any LLM — it is purely deterministic and bounded by design.
    The LLM enhancement step is handled separately in chains/detector.py.
    """

    def __init__(self) -> None:
        self._ranker = SeverityRanker()

    def audit(self, findings: List[Vulnerability]) -> AuditorResult:
        """Run the bounded chain audit pipeline on a list of pre-triaged findings.

        Stages (each guarded by memory check):
        1. Pre-audit memory guard.
        2. Build bounded exploit graph via build_graph().
        3. Post-graph memory guard.
        4. Bounded DFS path search via find_bounded_attack_paths().
        5. Post-path-search memory guard.
        6. Deterministic ranking via rank_attack_paths().
        7. Convert AttackPath objects to ExploitChain data models.
        8. Rank findings by combined risk + chain-impact score.

        On any resource limit, returns a partial AuditorResult with
        status="partial" and the specific reason string set. The process
        is never killed: partial results are always structurally valid.
        """
        if not findings:
            logger.info("[CHAIN-AUDIT] No findings to audit; returning empty result")
            return AuditorResult(exploit_chains=[], ranked_findings=[])

        logger.info(
            "[CHAIN-AUDIT] Starting audit: %d findings, memory=%.1f%%",
            len(findings), _memory_usage_percent(),
        )

        # --- Stage 1: pre-audit memory guard ---
        if not _is_memory_safe("pre-audit"):
            logger.warning("[CHAIN-AUDIT] Memory threshold exceeded before audit; aborting early")
            return AuditorResult(
                exploit_chains=[],
                ranked_findings=[],
                status="partial",
                reason="memory_limit_hit",
            )

        # --- Stage 2: build bounded graph ---
        try:
            graph, build_result = build_graph(findings)
        except Exception as exc:
            logger.error("[CHAIN-AUDIT] Graph build raised exception: %s", exc, exc_info=True)
            return AuditorResult(
                exploit_chains=[],
                ranked_findings=[],
                status="partial",
                reason="model_output_invalid",
            )

        metrics = summarize_graph_metrics(graph)
        logger.info(
            "[CHAIN-AUDIT] Graph: nodes=%d edges=%d node_limit=%s edge_limit=%s",
            build_result.nodes_created, build_result.edges_created,
            build_result.node_limit_hit, build_result.edge_limit_hit,
        )

        if not build_result.memory_safe:
            return AuditorResult(
                exploit_chains=[],
                ranked_findings=[],
                status="partial",
                reason="memory_limit_hit",
                graph_metrics=metrics,
            )

        # --- Stage 3: post-graph memory guard ---
        if not _is_memory_safe("post-graph-build"):
            return AuditorResult(
                exploit_chains=[],
                ranked_findings=[],
                status="partial",
                reason="memory_limit_hit",
                graph_metrics=metrics,
            )

        # --- Stage 4: bounded path search ---
        try:
            raw_paths = find_bounded_attack_paths(
                graph,
                max_depth=MAX_CHAIN_DEPTH,
                max_paths=MAX_CHAIN_CANDIDATES,
            )
        except Exception as exc:
            logger.error("[CHAIN-AUDIT] Path search raised exception: %s", exc, exc_info=True)
            raw_paths = []

        logger.info("[CHAIN-AUDIT] Path candidates found: %d", len(raw_paths))

        # --- Stage 5: post-path-search memory guard ---
        if not _is_memory_safe("post-path-search"):
            return AuditorResult(
                exploit_chains=[],
                ranked_findings=[],
                status="partial",
                reason="memory_limit_hit",
                graph_metrics=metrics,
                dropped_candidates=len(raw_paths),
            )

        # --- Stage 6: deterministic ranking ---
        ranked_paths = rank_attack_paths(raw_paths, graph, max_ranked=MAX_RANKED_CHAINS)
        dropped = max(0, len(raw_paths) - len(ranked_paths))
        if dropped:
            logger.info("[CHAIN-AUDIT] Dropped %d candidates beyond MAX_RANKED_CHAINS=%d", dropped, MAX_RANKED_CHAINS)

        # --- Stage 7: convert to ExploitChain data models ---
        vuln_map: Dict[str, Vulnerability] = {v.id: v for v in findings}
        chains: List[ExploitChain] = []
        for i, path in enumerate(ranked_paths, start=1):
            chain = _attack_path_to_chain(path, graph, vuln_map, i)
            if chain is not None:
                chains.append(chain)

        logger.info("[CHAIN-AUDIT] Exploit chains built: %d", len(chains))

        # --- Stage 8: rank findings by combined risk + chain-impact ---
        chain_impact_by_vuln_id: Dict[str, float] = {}
        for path in ranked_paths:
            for nid in path.nodes:
                chain_impact_by_vuln_id[nid] = max(
                    chain_impact_by_vuln_id.get(nid, 0.0),
                    min(100.0, path.score * 10.0),
                )

        try:
            ranked = self._ranker.rank_findings(
                vulnerabilities=findings,
                chain_impact_by_vuln_id=chain_impact_by_vuln_id,
                top_n=10,
            )
            ranked_findings = [v for v, _ in ranked]
            for vuln, score in ranked:
                vuln.risk_score = score
        except Exception as exc:
            logger.warning("[CHAIN-AUDIT] Finding ranking failed: %s", exc)
            ranked_findings = findings[:10]

        # Propagate the most informative cutoff reason from graph build
        status = "complete"
        reason = ""
        if build_result.cutoff_reason:
            status = "partial"
            reason = build_result.cutoff_reason

        logger.info(
            "[CHAIN-AUDIT] Audit complete: chains=%d ranked_findings=%d "
            "status=%s reason=%s memory=%.1f%%",
            len(chains), len(ranked_findings),
            status, reason or "none", _memory_usage_percent(),
        )

        return AuditorResult(
            exploit_chains=chains,
            ranked_findings=ranked_findings,
            status=status,
            reason=reason,
            graph_metrics=metrics,
            dropped_candidates=dropped,
        )
