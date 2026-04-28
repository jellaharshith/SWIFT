"""Core data models for SWIFT — zero internal dependencies."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, List, Optional

if TYPE_CHECKING:
    from feeds.live_cve import CVEMatch


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


@dataclass
class MergedFinding:
    """Unified vulnerability finding across multiple sources (code, Kali, CVE).

    Represents a vulnerability detected by one or more scanning sources,
    with consolidated severity, sources, and cross-referenced evidence.

    Attributes:
        id: Unique identifier for merged finding (e.g., "MERGED-{hex8}")
        vuln_type: Type of vulnerability (e.g., "sql_injection")
        severity: Max severity across sources (CRITICAL, HIGH, MEDIUM, LOW)
        sources: List of detection sources (e.g., ["code", "kali", "cve"])
        code_finding: Original Vulnerability from code analysis (if any)
        kali_finding: Finding object from Kali scanning (if any)
        cve_matches: List of CVEMatch objects correlated with this finding
        actively_exploited: Whether CVE is actively exploited in the wild
        correlation_confidence: Confidence score for source correlation (0.0-1.0)
        mitre_techniques: MITRE ATT&CK techniques from Kali findings (list of dicts)
    """
    id: str
    vuln_type: str
    severity: str
    sources: List[str]
    code_finding: Optional[Vulnerability] = None
    kali_finding: Optional[dict] = None
    cve_matches: List["CVEMatch"] = field(default_factory=list)
    actively_exploited: bool = False
    correlation_confidence: float = 0.0
    mitre_techniques: List[dict] = field(default_factory=list)


@dataclass
class UnifiedScanResult:
    """Complete scan results unified across code, Kali, and CVE sources.

    Represents the final output of a unified scan combining static code
    analysis, Kali VM scanning, and CVE database lookups, with correlated
    findings, exploit chains, and generated patches.

    Attributes:
        scan_id: Unique scan identifier
        started_at: ISO 8601 timestamp of scan start
        duration: Total scan duration in seconds
        repo_path: Path to scanned repository (if code scan)
        kali_target: Target IP/hostname for Kali scan (if Kali scan)
        merged_findings: Unified findings across all sources
        code_only_findings: Vulnerabilities from code scan only
        kali_only_findings: Findings from Kali scan only
        all_cve_matches: All CVE matches found across scans
        exploit_chains: Exploit chains detected
        patches: Generated patches for confirmed vulnerabilities
        report_md_path: Path to generated Markdown report (if any)
        report_txt_path: Path to generated text report (if any)
    """
    scan_id: str
    started_at: str
    duration: float
    repo_path: Optional[str] = None
    kali_target: Optional[str] = None
    merged_findings: List[MergedFinding] = field(default_factory=list)
    code_only_findings: List[Vulnerability] = field(default_factory=list)
    kali_only_findings: List[dict] = field(default_factory=list)
    all_cve_matches: List["CVEMatch"] = field(default_factory=list)
    exploit_chains: List[ExploitChain] = field(default_factory=list)
    patches: List[Patch] = field(default_factory=list)
    report_md_path: Optional[str] = None
    report_txt_path: Optional[str] = None


@dataclass
class EscalationPath:
    """Privilege escalation path connecting vulnerabilities to impact.

    Represents a chain of vulnerabilities that can be exploited sequentially
    to achieve privilege escalation or critical impact.

    Attributes:
        from_vuln: Starting vulnerability identifier (e.g., "sql_injection")
        steps: List of escalation steps (human-readable descriptions)
        to_impact: Final impact achieved (e.g., "account_takeover")
        severity: Severity level of the escalation path (CRITICAL, HIGH, etc.)
        finding_ids: List of finding IDs involved in this escalation chain
        ascii_chain: ASCII visualization of the escalation path
    """
    from_vuln: str
    steps: List[str]
    to_impact: str
    severity: str
    finding_ids: List[str]
    ascii_chain: str
