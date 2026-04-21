"""Exploit-chain auditing layer for graph construction and ranking."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from agent.models import AttackStep, ExploitChain, Vulnerability
from triage.exploit_graph import VulnerabilityGraph
from triage.severity_ranker import SeverityRanker


@dataclass
class AuditorResult:
    exploit_chains: List[ExploitChain]
    ranked_findings: List[Vulnerability]


class VulnerabilityChainAuditor:
    """Builds exploit graph, detects chains, and ranks top findings."""

    def __init__(self) -> None:
        self._ranker = SeverityRanker()

    def audit(self, findings: List[Vulnerability]) -> AuditorResult:
        graph = VulnerabilityGraph()
        for vuln in findings:
            graph.add_node(vuln)

        for idx, vuln_a in enumerate(findings):
            for vuln_b in findings[idx + 1:]:
                rel_forward = VulnerabilityGraph.detect_relationships(vuln_a, vuln_b)
                if rel_forward:
                    graph.add_edge(vuln_a, vuln_b, rel_forward)
                rel_reverse = VulnerabilityGraph.detect_relationships(vuln_b, vuln_a)
                if rel_reverse:
                    graph.add_edge(vuln_b, vuln_a, rel_reverse)

        paths = graph.find_attack_paths(min_length=2, max_length=5)
        ranked_paths = graph.rank_chains(paths)
        vuln_map = {v.id: v for v in findings}

        chains: List[ExploitChain] = []
        chain_impact_by_vuln_id: Dict[str, float] = {}
        for index, (path, score) in enumerate(ranked_paths, start=1):
            chain_id = f"CHAIN-{index:03d}"
            confidence = min(
                0.99,
                sum(vuln_map[node].confidence for node in path if node in vuln_map) / max(1, len(path)),
            )
            max_sev = self._max_severity([vuln_map[node].severity for node in path if node in vuln_map])
            attack_steps = [
                AttackStep(
                    step=i + 1,
                    description=f"Exploit {vuln_map[node].vuln_type} in {vuln_map[node].file_path}",
                    vuln_id=node,
                    entry_point=f"{vuln_map[node].file_path}:{vuln_map[node].line_number}",
                )
                for i, node in enumerate(path)
                if node in vuln_map
            ]

            chain = ExploitChain(
                chain_id=chain_id,
                name=" -> ".join(vuln_map[node].vuln_type for node in path if node in vuln_map),
                vulnerability_ids=[node for node in path if node in vuln_map],
                attack_path="\n".join(f"{step.step}. {step.description}" for step in attack_steps),
                entry_point=attack_steps[0].entry_point if attack_steps else "",
                impact=f"Multi-step chain with impact score {score:.1f}",
                severity=max_sev,
                confidence=confidence,
                attack_steps=attack_steps,
            )
            chains.append(chain)
            for node in chain.vulnerability_ids:
                chain_impact_by_vuln_id[node] = max(chain_impact_by_vuln_id.get(node, 0.0), min(100.0, score * 10.0))

        ranked = self._ranker.rank_findings(
            vulnerabilities=findings,
            chain_impact_by_vuln_id=chain_impact_by_vuln_id,
            top_n=10,
        )
        ranked_findings = [v for v, score in ranked]
        for vuln, score in ranked:
            vuln.risk_score = score

        return AuditorResult(exploit_chains=chains, ranked_findings=ranked_findings)

    @staticmethod
    def _max_severity(severities: List[str]) -> str:
        order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        highest = max(severities, key=lambda sev: order.get(sev.upper(), 0), default="LOW")
        return highest.upper()
