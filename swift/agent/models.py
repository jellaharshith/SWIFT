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
    """
    id: str
    file_path: str
    line_number: int
    vuln_type: str
    description: str
    confidence: float  # 0.0–1.0, NOT percent
    severity: str      # CRITICAL, HIGH, MEDIUM, LOW
    code_snippet: str
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
class ExploitChain:
    chain_id: str
    name: str
    vulnerability_ids: List[str]
    attack_path: str
    entry_point: str
    impact: str
    severity: str
    confidence: float


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


@dataclass
class TestResult:
    patch_id: str
    passed: bool
    output: str
    exit_code: int

    @property
    def summary(self) -> str:
        return "PASSED" if self.passed else "FAILED"
