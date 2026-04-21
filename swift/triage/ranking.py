"""Risk scoring and vulnerability ranking module.

Implements a quantitative risk formula that combines severity, exploitability,
confidence, and business impact to produce a normalized risk score (0-100).

Risk Score Formula:
    risk_score = (severity_weight × exploitability × confidence × impact_weight) × 100

Where:
- severity_weight: CRITICAL=1.0, HIGH=0.75, MEDIUM=0.5, LOW=0.25
- exploitability: complex=0.2, specific=0.4, moderate=0.6, trivial=0.9 (0.0-1.0)
- confidence: Model confidence (0.0-1.0)
- impact_weight: Business impact category weight (0.0-1.0)

Output range: 0-100 (higher = riskier)
"""
from __future__ import annotations

from typing import List, Optional

from agent.models import Vulnerability

# Maximum findings to pass to expensive chain detection analysis.
# Prevents timeouts from processing 600+ signals at once.
# Only top 30 most risky findings analyzed for exploit chains.
MAX_TRIAGE_FINDINGS = 30


class RiskScorer:
    """Quantitative risk scoring engine for vulnerabilities.

    Computes risk scores using a normalized formula that balances multiple
    factors: severity, exploitability, confidence, and business impact.
    Scores are output as 0-100 for easy percentile ranking.
    """

    # Severity weights: higher severity = higher base risk
    SEVERITY_WEIGHTS = {
        "CRITICAL": 1.0,
        "HIGH": 0.75,
        "MEDIUM": 0.5,
        "LOW": 0.25,
    }

    # Exploitability scores: how easy is it to exploit?
    # trivial=0.9 (very easy), moderate=0.6 (medium effort), complex=0.2 (hard)
    EXPLOITABILITY_SCORES = {
        "trivial": 0.9,
        "moderate": 0.6,
        "specific": 0.4,
        "complex": 0.2,
    }

    # Business impact weights: what's the real-world consequence?
    IMPACT_WEIGHTS = {
        "customer_data_breach": 1.0,    # Worst: GDPR, liability, brand damage
        "compliance_violation": 0.9,    # Severe: SOC2, PCI-DSS, ISO 27001 failures
        "financial_loss": 0.8,          # High: Direct monetary impact
        "service_disruption": 0.7,      # Medium-high: Availability impact
        "data_exposure": 0.6,           # Medium: Information disclosure
        "no_impact": 0.0,               # None: Finding with no real impact
    }

    @staticmethod
    def calculate_risk_score(vuln: Vulnerability) -> float:
        """Calculate risk score for a single vulnerability (0-100).

        Args:
            vuln: Vulnerability to score.

        Returns:
            Risk score (0.0-100.0). Higher is riskier.

        Formula:
            risk = (severity_weight × exploitability × confidence × impact_weight) × 100
        """
        # Get severity weight (default to MEDIUM if unknown)
        severity_weight = RiskScorer.SEVERITY_WEIGHTS.get(vuln.severity.upper(), 0.5)

        # Get exploitability score (default to moderate if not specified)
        exploitability = 0.6
        if hasattr(vuln, "exploitability") and vuln.exploitability is not None:
            exploitability = vuln.exploitability
        else:
            # Infer from severity: CRITICAL/HIGH are often more exploitable
            if vuln.severity.upper() == "CRITICAL":
                exploitability = 0.85
            elif vuln.severity.upper() == "HIGH":
                exploitability = 0.70

        # Use confidence as-is (already 0.0-1.0)
        confidence = vuln.confidence

        # Get impact weight (default to data_exposure if not specified)
        impact_weight = 0.6
        if hasattr(vuln, "business_impact_category") and vuln.business_impact_category:
            impact_weight = RiskScorer.IMPACT_WEIGHTS.get(
                vuln.business_impact_category.lower(), 0.6
            )

        # Calculate: multiply factors and scale to 0-100
        raw_score = severity_weight * exploitability * confidence * impact_weight
        risk_score = raw_score * 100

        # Clamp to 0-100 range
        return max(0.0, min(100.0, risk_score))

    @staticmethod
    def rank_vulnerabilities(
        vulns: List[Vulnerability],
    ) -> List[tuple[Vulnerability, float]]:
        """Sort vulnerabilities by risk score (highest risk first).

        Args:
            vulns: List of vulnerabilities to rank.

        Returns:
            List of (vulnerability, risk_score) tuples sorted by risk score
            descending (highest risk first).
        """
        scored = [
            (vuln, RiskScorer.calculate_risk_score(vuln))
            for vuln in vulns
        ]
        # Sort by score descending (highest risk first)
        return sorted(scored, key=lambda x: x[1], reverse=True)

    @staticmethod
    def get_impact_category(vuln: Vulnerability) -> str:
        """Infer business impact category from vulnerability properties.

        Args:
            vuln: Vulnerability to analyze.

        Returns:
            Impact category string (one of IMPACT_WEIGHTS keys).
        """
        # If already set, return it
        if hasattr(vuln, "business_impact_category") and vuln.business_impact_category:
            return vuln.business_impact_category

        # Otherwise, infer from vuln_type and description
        vuln_type_lower = vuln.vuln_type.lower()
        desc_lower = vuln.description.lower()

        # Determine impact from vuln type and description
        if any(
            x in vuln_type_lower
            for x in [
                "sql_injection",
                "auth_bypass",
                "privilege_escalation",
                "rce",
                "command_injection",
            ]
        ):
            # High-impact attack vectors
            if "password" in desc_lower or "credential" in desc_lower:
                return "customer_data_breach"
            elif "admin" in desc_lower or "privilege" in desc_lower:
                return "compliance_violation"
            else:
                return "financial_loss"

        if any(
            x in vuln_type_lower
            for x in [
                "xxe",
                "deserialization",
                "data_exposure",
                "information_disclosure",
            ]
        ):
            return "data_exposure"

        if any(
            x in vuln_type_lower
            for x in ["dos", "denial_of_service", "crash", "hang"]
        ):
            return "service_disruption"

        if any(
            x in vuln_type_lower
            for x in ["pci", "hipaa", "gdpr", "compliance", "encryption"]
        ):
            return "compliance_violation"

        # Default: data exposure
        return "data_exposure"

    @staticmethod
    def get_exploitability_score(vuln: Vulnerability) -> float:
        """Infer exploitability score from vulnerability properties.

        Args:
            vuln: Vulnerability to analyze.

        Returns:
            Exploitability score (0.0-1.0).
        """
        # If already set, return it
        if hasattr(vuln, "exploitability") and vuln.exploitability is not None:
            return vuln.exploitability

        # Otherwise, infer from vuln_type
        vuln_type_lower = vuln.vuln_type.lower()

        # Trivial to exploit (0.9)
        if any(x in vuln_type_lower for x in ["xss", "csrf", "xxe"]):
            return 0.9

        # Moderate to exploit (0.6)
        if any(x in vuln_type_lower for x in ["sql_injection", "command_injection"]):
            return 0.6

        # Specific conditions required (0.4)
        if any(
            x in vuln_type_lower
            for x in [
                "auth_bypass",
                "privilege_escalation",
                "deserialization",
            ]
        ):
            return 0.4

        # Complex to exploit (0.2)
        if any(
            x in vuln_type_lower
            for x in ["race_condition", "timing_attack", "cryptography"]
        ):
            return 0.2

        # Default: moderate
        return 0.6

    @staticmethod
    def triage_findings(
        vulns: List[Vulnerability],
        max_findings: int = MAX_TRIAGE_FINDINGS,
    ) -> List[Vulnerability]:
        """Return top-ranked findings for expensive analysis (chain detection).

        Prevents timeout by limiting vulnerabilities sent to LLM reasoning.
        Only top findings by risk score are passed downstream.

        Args:
            vulns: All vulnerabilities detected.
            max_findings: Maximum findings to return (default: 30).

        Returns:
            Top N vulnerabilities ranked by risk score.
        """
        if not vulns:
            return []

        # Rank all findings
        ranked = RiskScorer.rank_vulnerabilities(vulns)

        # Return top N
        return [vuln for vuln, _ in ranked[:max_findings]]
