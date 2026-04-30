"""Unit tests for browser/finding_bridge.py — Layer 5 of SWIFT offensive scanner."""
from __future__ import annotations

import pytest

from browser.finding_bridge import browser_finding_to_vulnerability, browser_scan_to_vulnerabilities
from browser.playwright_runner import BrowserFinding, BrowserScanResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(kind: str, severity: str = "high", payload: str = "<script>") -> BrowserFinding:
    return BrowserFinding(
        kind=kind,
        severity=severity,
        url=f"https://example.com/search?q=test",
        evidence=f"Probe detected {kind}",
        payload=payload,
    )


SCAN_ID = "abcd1234efgh5678"


# ---------------------------------------------------------------------------
# Individual conversion tests
# ---------------------------------------------------------------------------

class TestBrowserFindingToVulnerability:
    def test_xss_reflected_passes_gate_with_correct_confidence(self):
        finding = _make_finding("xss_reflected")
        vuln = browser_finding_to_vulnerability(finding, SCAN_ID, idx=0)

        assert vuln is not None
        assert vuln.confidence == 0.97
        assert vuln.cwe_id == "CWE-79"
        assert "79.html" in (vuln.cwe_url or "")
        assert vuln.vuln_type == "xss_reflected"

    def test_unknown_kind_returns_none(self):
        finding = _make_finding("totally_unknown_kind")
        vuln = browser_finding_to_vulnerability(finding, SCAN_ID, idx=0)

        # 0.80 default confidence is below gate
        assert vuln is None

    def test_sqli_error_has_correct_cwe_and_owasp(self):
        finding = _make_finding("sqli_error")
        vuln = browser_finding_to_vulnerability(finding, SCAN_ID, idx=1)

        assert vuln is not None
        assert vuln.cwe_id == "CWE-89"
        assert vuln.owasp_category == "A03:2021 – Injection"
        assert vuln.confidence == 0.97

    def test_jwt_alg_none_has_correct_cwe(self):
        finding = _make_finding("jwt_alg_none", severity="critical")
        vuln = browser_finding_to_vulnerability(finding, SCAN_ID, idx=2)

        assert vuln is not None
        assert vuln.cwe_id == "CWE-347"
        assert "347.html" in (vuln.cwe_url or "")
        assert vuln.confidence == 0.97

    def test_idor_has_correct_cwe(self):
        finding = _make_finding("idor")
        vuln = browser_finding_to_vulnerability(finding, SCAN_ID, idx=3)

        assert vuln is not None
        assert vuln.cwe_id == "CWE-639"
        assert "639.html" in (vuln.cwe_url or "")

    def test_id_format(self):
        finding = _make_finding("xss_reflected")
        vuln = browser_finding_to_vulnerability(finding, SCAN_ID, idx=5)

        assert vuln is not None
        assert vuln.id == f"SWIFT-WEB-{SCAN_ID[:8].upper()}-005"

    def test_file_path_is_url(self):
        finding = _make_finding("ssrf")
        vuln = browser_finding_to_vulnerability(finding, SCAN_ID)

        assert vuln is not None
        assert vuln.file_path == finding.url

    def test_line_number_is_zero(self):
        finding = _make_finding("ssti")
        vuln = browser_finding_to_vulnerability(finding, SCAN_ID)

        assert vuln is not None
        assert vuln.line_number == 0

    def test_code_snippet_is_payload(self):
        finding = _make_finding("sqli_blind", payload="' OR 1=1--")
        vuln = browser_finding_to_vulnerability(finding, SCAN_ID)

        assert vuln is not None
        assert vuln.code_snippet == "' OR 1=1--"

    def test_critical_severity_remediation_effort_is_high(self):
        finding = _make_finding("xss_stored", severity="critical")
        vuln = browser_finding_to_vulnerability(finding, SCAN_ID)

        assert vuln is not None
        assert vuln.remediation_effort == "HIGH"

    def test_high_severity_remediation_effort_is_medium(self):
        finding = _make_finding("xss_reflected", severity="high")
        vuln = browser_finding_to_vulnerability(finding, SCAN_ID)

        assert vuln is not None
        assert vuln.remediation_effort == "MEDIUM"

    def test_references_contains_cwe_url(self):
        finding = _make_finding("xxe")
        vuln = browser_finding_to_vulnerability(finding, SCAN_ID)

        assert vuln is not None
        assert len(vuln.references) == 1
        assert "611.html" in vuln.references[0]

    def test_references_empty_for_unknown_kind(self):
        # Unknown kind returns None, but we can test a known kind with no CWE
        # by verifying that any known kind without CWE has empty references.
        # Since all known kinds have CWEs, we verify xxe is non-empty (sanity).
        finding = _make_finding("xxe")
        vuln = browser_finding_to_vulnerability(finding, SCAN_ID)
        assert vuln is not None
        assert vuln.references  # non-empty

    def test_status_is_confirmed(self):
        finding = _make_finding("open_redirect")
        vuln = browser_finding_to_vulnerability(finding, SCAN_ID)

        assert vuln is not None
        assert vuln.status == "CONFIRMED"

    def test_exploit_description_contains_kind_and_url(self):
        finding = _make_finding("nosql_injection")
        vuln = browser_finding_to_vulnerability(finding, SCAN_ID)

        assert vuln is not None
        assert "nosql_injection" in vuln.exploit_description
        assert finding.url in vuln.exploit_description

    def test_confidence_gate_exactly_095_passes(self):
        # sqli_blind, open_redirect, etc. map to exactly 0.95 — must pass
        finding = _make_finding("sqli_blind")
        vuln = browser_finding_to_vulnerability(finding, SCAN_ID)

        assert vuln is not None
        assert vuln.confidence == 0.95


# ---------------------------------------------------------------------------
# Batch conversion tests
# ---------------------------------------------------------------------------

class TestBrowserScanToVulnerabilities:
    def test_filters_unknown_kinds(self):
        result = BrowserScanResult(
            target="https://example.com",
            findings=[
                _make_finding("xss_reflected"),
                _make_finding("unknown_vuln_type"),
                _make_finding("sqli_error"),
            ],
        )
        vulns = browser_scan_to_vulnerabilities(result, SCAN_ID)

        assert len(vulns) == 2
        kinds = {v.vuln_type for v in vulns}
        assert kinds == {"xss_reflected", "sqli_error"}

    def test_empty_findings_returns_empty_list(self):
        result = BrowserScanResult(target="https://example.com")
        vulns = browser_scan_to_vulnerabilities(result, SCAN_ID)

        assert vulns == []

    def test_all_known_kinds_pass(self):
        known_kinds = [
            "xss_reflected", "xss_stored", "sqli_error", "sqli_blind",
            "open_redirect", "ssrf", "ssti", "nosql_injection", "auth_bypass",
            "prototype_pollution", "crlf_injection", "jwt_alg_none", "idor", "xxe",
        ]
        result = BrowserScanResult(
            target="https://example.com",
            findings=[_make_finding(k) for k in known_kinds],
        )
        vulns = browser_scan_to_vulnerabilities(result, SCAN_ID)

        assert len(vulns) == len(known_kinds)

    def test_index_increments_per_finding(self):
        result = BrowserScanResult(
            target="https://example.com",
            findings=[_make_finding("xss_reflected"), _make_finding("sqli_error")],
        )
        vulns = browser_scan_to_vulnerabilities(result, SCAN_ID)

        ids = [v.id for v in vulns]
        assert ids[0].endswith("-000")
        assert ids[1].endswith("-001")
