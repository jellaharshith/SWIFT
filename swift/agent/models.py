"""Core data models for SWIFT — zero internal dependencies."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Vulnerability:
    """Vulnerability model with evidence bundle fields for Phase 3.

    Core fields (required):
        id: Unique vulnerability identifier (e.g., "SWIFT-001")
        file_path: Path to vulnerable file
        line_number: Line number of vulnerability
        vuln_type: Type of vulnerability (e.g., "sql_injection")
        description: Brief description of the vulnerability
        confidence: Confidence score (0.0–1.0, NOT percent)
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
        code_snippet: Code containing the vulnerability
        status: Confidence status (CONFIRMED ≥95%, REVIEW_REQUIRED 65-95%)

    Evidence bundle fields (optional):
        cwe_id: CWE identifier (e.g., "CWE-89")
        cwe_url: URL to CWE definition on MITRE website
        owasp_category: OWASP category (e.g., "A03:2021 – Injection")
        exploit_description: Description of how attacker exploits this vulnerability
        exploit_impact: Description of what attacker can compromise
        remediation: Recommended fix/remediation steps
        remediation_code: Fixed code example
        remediation_effort: Effort required (LOW/MEDIUM/HIGH)
        remediation_time_minutes: Estimated time to fix in minutes
        affected_code: Dict with "before" and "after" code snippets
        references: List of URLs to security documentation

    Risk scoring fields (Phase 3, optional):
        exploitability: How easy to exploit (0.0-1.0), trivial=0.9, complex=0.2
        business_impact_category: Real-world impact category (customer_data_breach, etc.)
        risk_score: Calculated risk score (0-100), higher = riskier
    """
    id: str
    file_path: str
    line_number: int
    vuln_type: str
    description: str
    confidence: float  # 0.0–1.0, NOT percent
    severity: str      # CRITICAL, HIGH, MEDIUM, LOW
    code_snippet: str
    # Internal pipeline status (set by SonnetAnalysisScanner).
    # The normalised report formatter remaps these to the three allowed output
    # labels: HIGH_CONFIDENCE_VULNERABILITY | LIKELY_VULNERABILITY | REVIEW_REQUIRED.
    # "CONFIRMED" is retained here for pipeline compatibility but must NEVER be
    # written directly to customer-facing reports — use NormalizedReportFormatter.
    status: str = "CONFIRMED"  # CONFIRMED (≥95%) or REVIEW_REQUIRED (65-95%)
    cwe_id: Optional[str] = None
    cwe_url: Optional[str] = None
    owasp_category: Optional[str] = None
    exploit_description: Optional[str] = None
    exploit_impact: Optional[str] = None
    remediation: Optional[str] = None
    remediation_code: Optional[str] = None
    remediation_effort: Optional[str] = None
    remediation_time_minutes: Optional[int] = None
    affected_code: Optional[Dict[str, str]] = None
    references: List[str] = field(default_factory=list)
    exploitability: Optional[float] = None  # 0.0-1.0, inferred if not set
    business_impact_category: Optional[str] = None  # e.g., customer_data_breach
    risk_score: Optional[float] = None  # 0-100, calculated by RiskScorer


@dataclass
class Patch:
    id: str
    vuln_id: str
    file_path: str
    original_code: str
    patched_code: str
    diff: str
    confidence: float
    reasoning: Optional[str] = None
    sandbox_tested: bool = False
    test_passed: Optional[bool] = None
    test_logs: Optional[str] = None


@dataclass
class AttackStep:
    """Single step in an exploit chain attack sequence.

    Attributes:
        step: Step number in the chain (1-indexed).
        description: Human-readable description of this attack step.
        vuln_id: Vulnerability ID involved in this step (e.g., "SWIFT-001").
        entry_point: Location where this step occurs (e.g., "auth/views.py:42").
    """
    step: int
    description: str
    vuln_id: str
    entry_point: str


@dataclass
class ExploitChain:
    chain_id: str
    name: str
    vulnerability_ids: List[str]
    attack_path: str
    entry_point: str
    impact: str
    severity: str
    confidence: float
    attack_steps: List[AttackStep] = field(default_factory=list)


@dataclass
class ScanResult:
    scan_id: str
    repo_path: str
    files_scanned: int
    vulnerabilities: List[Vulnerability]
    patches: List[Patch]
    duration_seconds: float
    total_cost_usd: float
    timestamp: str
    exploit_chains: List[ExploitChain] = field(default_factory=list)
    ranked_findings: List[Vulnerability] = field(default_factory=list)
    status: str = "complete"  # "complete" or "partial_success"
    signals_detected: int = 0  # Total signals/findings detected
    signals_triaged: int = 0  # Signals selected for chain detection
    chain_detection_error: Optional[str] = None


@dataclass
class TestResult:
    patch_id: str
    passed: bool
    output: str
    exit_code: int

    @property
    def summary(self) -> str:
        return "PASSED" if self.passed else "FAILED"
