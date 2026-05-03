"""Bridge: converts BrowserFinding → Vulnerability for the main pipeline.

Only findings with confidence ≥ 0.95 are emitted (SWIFT's non-negotiable gate).
"""
from __future__ import annotations

from typing import Optional

from agent.models import Vulnerability
from browser.playwright_runner import BrowserFinding, BrowserScanResult

# ---------------------------------------------------------------------------
# Confidence mapping: kind → float (0.0–1.0)
# Anything not in map → 0.80 (below gate, not emitted)
# ---------------------------------------------------------------------------
_KIND_CONFIDENCE: dict[str, float] = {
    "xss_reflected": 0.97,
    "xss_stored": 0.98,
    "sqli_error": 0.97,
    "sqli_blind": 0.95,
    "open_redirect": 0.95,
    "ssrf": 0.96,
    "ssti": 0.97,
    "nosql_injection": 0.95,
    "auth_bypass": 0.95,
    "prototype_pollution": 0.95,
    "crlf_injection": 0.95,
    "jwt_alg_none": 0.97,
    "idor": 0.95,
    "xxe": 0.98,
}

# ---------------------------------------------------------------------------
# CWE mapping: kind → (cwe_id, cwe_url)
# ---------------------------------------------------------------------------
_KIND_CWE: dict[str, tuple[str, str]] = {
    "xss_reflected": ("CWE-79", "https://cwe.mitre.org/data/definitions/79.html"),
    "xss_stored": ("CWE-79", "https://cwe.mitre.org/data/definitions/79.html"),
    "sqli_error": ("CWE-89", "https://cwe.mitre.org/data/definitions/89.html"),
    "sqli_blind": ("CWE-89", "https://cwe.mitre.org/data/definitions/89.html"),
    "open_redirect": ("CWE-601", "https://cwe.mitre.org/data/definitions/601.html"),
    "ssrf": ("CWE-918", "https://cwe.mitre.org/data/definitions/918.html"),
    "ssti": ("CWE-94", "https://cwe.mitre.org/data/definitions/94.html"),
    "nosql_injection": ("CWE-943", "https://cwe.mitre.org/data/definitions/943.html"),
    "auth_bypass": ("CWE-306", "https://cwe.mitre.org/data/definitions/306.html"),
    "prototype_pollution": ("CWE-1321", "https://cwe.mitre.org/data/definitions/1321.html"),
    "crlf_injection": ("CWE-93", "https://cwe.mitre.org/data/definitions/93.html"),
    "jwt_alg_none": ("CWE-347", "https://cwe.mitre.org/data/definitions/347.html"),
    "idor": ("CWE-639", "https://cwe.mitre.org/data/definitions/639.html"),
    "xxe": ("CWE-611", "https://cwe.mitre.org/data/definitions/611.html"),
}

# ---------------------------------------------------------------------------
# OWASP 2021 category mapping
# ---------------------------------------------------------------------------
_KIND_OWASP: dict[str, str] = {
    "xss_reflected": "A03:2021 – Injection",
    "xss_stored": "A03:2021 – Injection",
    "sqli_error": "A03:2021 – Injection",
    "sqli_blind": "A03:2021 – Injection",
    "ssti": "A03:2021 – Injection",
    "nosql_injection": "A03:2021 – Injection",
    "open_redirect": "A01:2021 – Broken Access Control",
    "ssrf": "A10:2021 – Server-Side Request Forgery",
    "auth_bypass": "A07:2021 – Identification and Authentication Failures",
    "idor": "A01:2021 – Broken Access Control",
    "prototype_pollution": "A08:2021 – Software and Data Integrity Failures",
    "crlf_injection": "A03:2021 – Injection",
    "jwt_alg_none": "A02:2021 – Cryptographic Failures",
    "xxe": "A05:2021 – Security Misconfiguration",
}

# ---------------------------------------------------------------------------
# Remediation text mapping: kind → short string
# ---------------------------------------------------------------------------
_KIND_REMEDIATION: dict[str, str] = {
    "xss_reflected": "Encode output before rendering to prevent XSS; use a Content Security Policy.",
    "xss_stored": "Sanitize user input on storage and encode on output; use a Content Security Policy.",
    "sqli_error": "Use parameterized queries or prepared statements to prevent SQL injection.",
    "sqli_blind": "Use parameterized queries or prepared statements to prevent SQL injection.",
    "open_redirect": "Validate redirect URLs against an allowlist of trusted destinations.",
    "ssrf": "Validate and restrict outbound requests to trusted internal IP ranges and hostnames.",
    "ssti": "Use sandboxed template engines and avoid passing user input directly to template renderers.",
    "nosql_injection": "Sanitize and validate user input; use typed query builders instead of raw operators.",
    "auth_bypass": "Enforce authentication on all protected endpoints; audit missing auth middleware.",
    "prototype_pollution": "Freeze Object.prototype or use Object.create(null); validate all merge/extend inputs.",
    "crlf_injection": "Strip or reject carriage-return and line-feed characters in HTTP response headers.",
    "jwt_alg_none": "Reject JWTs with algorithm 'none'; enforce an explicit allowlist of accepted algorithms.",
    "idor": "Enforce server-side ownership checks on every resource access; use indirect object references.",
    "xxe": "Disable external entity processing in the XML parser and use a secure XML library configuration.",
}


def browser_finding_to_vulnerability(
    finding: BrowserFinding,
    scan_id: str,
    idx: int = 0,
) -> Optional[Vulnerability]:
    """Convert BrowserFinding to Vulnerability, or None if below 95% confidence gate.

    Args:
        finding: Browser probe finding to convert.
        scan_id: Parent scan identifier for ID generation.
        idx: Finding index within the scan (for unique ID).

    Returns:
        Vulnerability if confidence >= 0.95, else None.
    """
    confidence = _KIND_CONFIDENCE.get(finding.kind, 0.80)

    # Non-negotiable gate: findings below 95% are silently dropped.
    if confidence < 0.95:
        return None

    vuln_id = f"SWIFT-WEB-{scan_id[:8].upper()}-{idx:03d}"

    cwe_entry = _KIND_CWE.get(finding.kind)
    cwe_id: Optional[str] = cwe_entry[0] if cwe_entry else None
    cwe_url: Optional[str] = cwe_entry[1] if cwe_entry else None

    references: list[str] = [cwe_url] if cwe_url else []

    remediation_effort = "HIGH" if finding.severity in ("critical",) else "MEDIUM"

    return Vulnerability(
        id=vuln_id,
        file_path=finding.url,
        line_number=0,
        vuln_type=finding.kind,
        description=finding.evidence,
        confidence=confidence,
        severity=finding.severity,
        code_snippet=finding.payload or "",
        status="CONFIRMED",
        cwe_id=cwe_id,
        cwe_url=cwe_url,
        owasp_category=_KIND_OWASP.get(finding.kind),
        exploit_description=f"Browser probe confirmed {finding.kind} at {finding.url}",
        exploit_impact="Attacker can exploit this vulnerability in a live web application",
        remediation=_KIND_REMEDIATION.get(
            finding.kind, "Review and fix the identified vulnerability"
        ),
        remediation_code="",
        remediation_effort=remediation_effort,
        remediation_time_minutes=30,
        references=references,
    )


def browser_scan_to_vulnerabilities(
    result: BrowserScanResult,
    scan_id: str,
) -> list[Vulnerability]:
    """Convert all BrowserFindings in a scan result to gated Vulnerabilities.

    Args:
        result: BrowserScanResult containing zero or more BrowserFindings.
        scan_id: Parent scan identifier used for Vulnerability ID generation.

    Returns:
        List of Vulnerability objects that passed the 95% confidence gate.
        Findings whose kind maps to confidence < 0.95 are excluded.
    """
    vulns: list[Vulnerability] = []
    for idx, finding in enumerate(result.findings):
        vuln = browser_finding_to_vulnerability(finding, scan_id, idx)
        if vuln is not None:
            vulns.append(vuln)
    return vulns
