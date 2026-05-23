"""Stage 2 scanner: static semgrep findings mapper (replaces Claude Sonnet API)."""
from __future__ import annotations

import itertools
import json
import re
import subprocess
from typing import Any, Optional

from agent.models import Vulnerability
from log.logger import get_logger

logger = get_logger()

# OWASP category mapping from semgrep rule IDs
_OWASP_MAP: dict[str, str] = {
    "injection": "A03:2021 – Injection",
    "sqli": "A03:2021 – Injection",
    "xss": "A03:2021 – Injection",
    "broken-auth": "A07:2021 – Identification and Authentication Failures",
    "secrets": "A02:2021 – Cryptographic Failures",
    "crypto": "A02:2021 – Cryptographic Failures",
    "xxe": "A05:2021 – Security Misconfiguration",
    "ssrf": "A10:2021 – Server-Side Request Forgery",
    "insecure-deserialization": "A08:2021 – Software and Data Integrity Failures",
    "idor": "A01:2021 – Broken Access Control",
    "open-redirect": "A01:2021 – Broken Access Control",
    "command-injection": "A03:2021 – Injection",
    "hardcoded": "A02:2021 – Cryptographic Failures",
}


def _infer_owasp(rule_id: str) -> Optional[str]:
    rule_lower = rule_id.lower()
    for key, category in _OWASP_MAP.items():
        if key in rule_lower:
            return category
    return None


class SonnetAnalysisScanner:
    """Maps semgrep findings to Vulnerability objects.

    Replaces the former Claude Sonnet deep-analysis stage.
    No API key required. Re-runs semgrep per file (results cached) and
    looks up the finding closest to ``line_number``.

    Args:
        client: Ignored (kept for import compatibility).
        model:  Ignored.
        mode:   Informational only.
        semgrep_timeout: Per-file timeout in seconds (default 30).
    """

    HIGH_CONFIDENCE_THRESHOLD = 0.95
    REVIEW_THRESHOLD = 0.65
    _counter: itertools.count = itertools.count(1)

    _SEMGREP_CONFIGS = [
        "p/owasp-top-ten",
        "p/cwe-top-25",
        "p/secrets",
    ]
    _SEVERITY_MAP = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
    }

    def __init__(
        self,
        client: Any = None,
        model: str = "",
        mode: str = "pentester",
        semgrep_timeout: int = 30,
        **_kwargs: Any,
    ) -> None:
        self._mode = mode
        self._timeout = semgrep_timeout
        self._cache: dict[str, list[dict]] = {}

    def analyze_line(
        self, file_path: str, line_number: int, source_code: str
    ) -> Optional[Vulnerability]:
        """Find and map a semgrep finding at ``line_number``.

        Args:
            file_path: Path for context.
            line_number: 1-indexed line to analyze.
            source_code: Full file source (used for snippet extraction).

        Returns:
            Vulnerability if a semgrep finding covers this line, else None.
        """
        findings = self._get_findings(file_path)
        # Find the semgrep finding whose range includes line_number
        for f in findings:
            start = f.get("start", {}).get("line", 0)
            end = f.get("end", {}).get("line", start)
            if start <= line_number <= end:
                return self._map_finding(f, file_path, line_number, source_code)

        # No semgrep finding for this exact line — create signal finding
        return self._signal_finding(file_path, line_number, source_code)

    # ------------------------------------------------------------------

    def _get_findings(self, file_path: str) -> list[dict]:
        if file_path in self._cache:
            return self._cache[file_path]
        findings = self._run_semgrep(file_path)
        self._cache[file_path] = findings
        return findings

    def _run_semgrep(self, file_path: str) -> list[dict]:
        cmd = ["semgrep", "--json", "--quiet", "--no-git-ignore"]
        for cfg in self._SEMGREP_CONFIGS:
            cmd += ["--config", cfg]
        cmd.append(file_path)
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self._timeout
            )
            if result.returncode > 1:
                return []
            data = json.loads(result.stdout)
            return data.get("results", [])
        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            return []

    def _map_finding(
        self,
        finding: dict,
        file_path: str,
        line_number: int,
        source_code: str,
    ) -> Vulnerability:
        meta = finding.get("extra", {})
        rule_id = finding.get("check_id", "unknown")
        severity_raw = meta.get("severity", "WARNING").upper()
        severity = self._SEVERITY_MAP.get(severity_raw, "MEDIUM")
        message = meta.get("message", "")
        metadata = meta.get("metadata", {})
        cwe_list = metadata.get("cwe", [])
        cwe_id = cwe_list[0] if cwe_list else None
        cwe_num = re.search(r"\d+", cwe_id or "")
        cwe_url = (
            f"https://cwe.mitre.org/data/definitions/{cwe_num.group()}.html"
            if cwe_num
            else None
        )
        owasp_category = (
            metadata.get("owasp") or _infer_owasp(rule_id) or "Uncategorized"
        )
        snippet = self._get_snippet(source_code, line_number)
        confidence = 0.85  # semgrep rule match = high confidence
        vuln_id = f"SWIFT-{next(self._counter):03d}"
        return Vulnerability(
            id=vuln_id,
            file_path=file_path,
            line_number=line_number,
            vuln_type=rule_id,
            description=message,
            confidence=confidence,
            severity=severity,
            code_snippet=snippet,
            status="CONFIRMED" if confidence >= self.HIGH_CONFIDENCE_THRESHOLD else "REVIEW_REQUIRED",
            cwe_id=cwe_id,
            cwe_url=cwe_url,
            owasp_category=owasp_category,
            exploit_description=None,
            exploit_impact=None,
            remediation=metadata.get("fix"),
            remediation_code=None,
            remediation_effort="MEDIUM",
            remediation_time_minutes=15,
            references=metadata.get("references", []),
        )

    def _signal_finding(
        self, file_path: str, line_number: int, source_code: str
    ) -> Optional[Vulnerability]:
        """Create a REVIEW_REQUIRED signal when no semgrep finding matches."""
        snippet = self._get_snippet(source_code, line_number)
        vuln_id = f"SWIFT-{next(self._counter):03d}"
        return Vulnerability(
            id=vuln_id,
            file_path=file_path,
            line_number=line_number,
            vuln_type="signal_requires_review",
            description=f"Pattern match on line {line_number} — manual review required",
            confidence=0.7,
            severity="MEDIUM",
            code_snippet=snippet,
            status="REVIEW_REQUIRED",
            cwe_id=None,
            cwe_url=None,
            owasp_category=None,
            exploit_description=None,
            exploit_impact=None,
            remediation=None,
            remediation_code=None,
            remediation_effort=None,
            remediation_time_minutes=None,
            references=[],
        )

    @staticmethod
    def _get_snippet(source_code: str, line_number: int) -> str:
        lines = source_code.split("\n")
        if 0 < line_number <= len(lines):
            return lines[line_number - 1]
        return ""
