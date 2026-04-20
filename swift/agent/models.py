"""Core data models for SWIFT — zero internal dependencies."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Vulnerability:
    id: str
    file_path: str
    line_number: int
    vuln_type: str
    description: str
    confidence: float  # 0.0–1.0, NOT percent
    severity: str      # CRITICAL, HIGH, MEDIUM, LOW
    code_snippet: str
    cwe_id: Optional[str] = None
    exploit_description: Optional[str] = None
    remediation: Optional[str] = None


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
