"""Composite severity ranking engine for prioritized findings."""
from __future__ import annotations

from typing import Dict, List, Tuple

from agent.models import Vulnerability


class SeverityRanker:
    """Ranks vulnerabilities using base risk and chain impact."""

    SEVERITY_WEIGHTS: Dict[str, float] = {
        "CRITICAL": 1.0,
        "HIGH": 0.75,
        "MEDIUM": 0.5,
        "LOW": 0.25,
    }

    def base_risk(self, vuln: Vulnerability) -> float:
        severity = self.SEVERITY_WEIGHTS.get(vuln.severity.upper(), 0.5)
        exploitability = vuln.exploitability if vuln.exploitability is not None else 0.6
        confidence = vuln.confidence
        return max(0.0, min(100.0, severity * exploitability * confidence * 100.0))

    def score_vulnerability(self, vuln: Vulnerability, chain_impact: float = 0.0) -> float:
        """Score = 60% base risk + 40% chain impact."""
        base = self.base_risk(vuln)
        combined = (base * 0.6) + (chain_impact * 0.4)
        return max(0.0, min(100.0, combined))

    def rank_findings(
        self,
        vulnerabilities: List[Vulnerability],
        chain_impact_by_vuln_id: Dict[str, float] | None = None,
        top_n: int = 10,
    ) -> List[Tuple[Vulnerability, float]]:
        chain_impact_by_vuln_id = chain_impact_by_vuln_id or {}
        scored = [
            (
                vuln,
                self.score_vulnerability(
                    vuln,
                    chain_impact=float(chain_impact_by_vuln_id.get(vuln.id, 0.0)),
                ),
            )
            for vuln in vulnerabilities
        ]
        scored.sort(key=lambda item: item[1], reverse=True)
        return scored[:top_n]
