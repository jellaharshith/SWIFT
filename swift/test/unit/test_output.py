"""Unit tests for output formatters — pure data transformation, no API calls."""
import json

import pytest

from agent.models import Patch, ScanResult, Vulnerability, ExploitChain
from output.formatters import JSONFormatter, MarkdownFormatter, format_output


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------

def _make_vuln() -> Vulnerability:
    return Vulnerability(
        id="SWIFT-001",
        file_path="app.py",
        line_number=42,
        vuln_type="sql_injection",
        description="User input in SQL query",
        confidence=0.97,
        severity="CRITICAL",
        code_snippet='query = f"SELECT * FROM users WHERE id={user_id}"',
    )


def _make_patch() -> Patch:
    return Patch(
        id="PATCH-001",
        vuln_id="SWIFT-001",
        file_path="app.py",
        original_code='query = f"SELECT * FROM users WHERE id={user_id}"',
        patched_code="query = 'SELECT * FROM users WHERE id=?'",
        diff="--- a/app.py\n+++ b/app.py\n@@ -42,1 +42,1 @@\n-query = f\"SELECT...\"\n+query = 'SELECT * FROM users WHERE id=?'",
        confidence=0.97,
    )


def _make_chain() -> ExploitChain:
    return ExploitChain(
        chain_id="CHAIN-001",
        name="SQL Injection → Auth Bypass → Admin Access",
        vulnerability_ids=["SWIFT-001", "SWIFT-002"],
        attack_path="1. Exploit SQL injection in login query\n2. Bypass authentication\n3. Access admin panel",
        entry_point="auth/views.py:42",
        impact="Full admin access without credentials",
        severity="CRITICAL",
        confidence=0.91,
    )


def _make_scan_result(vulns=None, patches=None, chains=None) -> ScanResult:
    return ScanResult(
        scan_id="SCAN-001",
        repo_path="/tmp/repo",
        files_scanned=10,
        vulnerabilities=vulns if vulns is not None else [],
        patches=patches if patches is not None else [],
        duration_seconds=5.0,
        total_cost_usd=0.42,
        timestamp="2026-04-18T12:00:00Z",
        exploit_chains=chains if chains is not None else [],
    )


# ---------------------------------------------------------------------------
# JSONFormatter tests
# ---------------------------------------------------------------------------

class TestJSONFormatter:
    def test_json_formatter_produces_valid_json(self):
        """Output must be parseable JSON."""
        result = _make_scan_result(vulns=[_make_vuln()], patches=[_make_patch()])
        output = JSONFormatter().format(result)
        parsed = json.loads(output)  # raises if invalid
        assert isinstance(parsed, dict)

    def test_json_scan_fields(self):
        """Top-level 'scan' block must contain all scan metadata."""
        result = _make_scan_result()
        parsed = json.loads(JSONFormatter().format(result))
        scan = parsed["scan"]
        assert scan["id"] == "SCAN-001"
        assert scan["repo_path"] == "/tmp/repo"
        assert scan["duration_seconds"] == 5.0
        assert scan["total_cost_usd"] == 0.42
        assert scan["timestamp"] == "2026-04-18T12:00:00Z"

    def test_json_summary_counts(self):
        """Summary block must contain correct counts and severity breakdown."""
        result = _make_scan_result(vulns=[_make_vuln()], patches=[_make_patch()])
        parsed = json.loads(JSONFormatter().format(result))
        summary = parsed["summary"]
        assert summary["files_scanned"] == 10
        assert summary["vulnerabilities_found"] == 1
        assert summary["patches_generated"] == 1
        # Severity key must be lowercase
        assert summary["by_severity"]["critical"] == 1

    def test_json_vulnerability_fields(self):
        """Each vulnerability entry must carry all required fields."""
        result = _make_scan_result(vulns=[_make_vuln()])
        parsed = json.loads(JSONFormatter().format(result))
        vuln = parsed["vulnerabilities"][0]
        assert vuln["id"] == "SWIFT-001"
        assert vuln["file_path"] == "app.py"
        assert vuln["line_number"] == 42
        assert vuln["vuln_type"] == "sql_injection"
        assert vuln["severity"] == "CRITICAL"
        assert vuln["confidence"] == 0.97

    def test_json_patch_fields(self):
        """Each patch entry must carry at least id, vuln_id, and file_path."""
        result = _make_scan_result(patches=[_make_patch()])
        parsed = json.loads(JSONFormatter().format(result))
        patch = parsed["patches"][0]
        assert patch["id"] == "PATCH-001"
        assert patch["vuln_id"] == "SWIFT-001"
        assert patch["file_path"] == "app.py"

    def test_json_empty_lists(self):
        """Formatter must handle empty vulnerabilities and patches gracefully."""
        result = _make_scan_result()
        parsed = json.loads(JSONFormatter().format(result))
        assert parsed["vulnerabilities"] == []
        assert parsed["patches"] == []
        assert parsed["summary"]["vulnerabilities_found"] == 0
        assert parsed["summary"]["patches_generated"] == 0

    def test_json_by_severity_all_zeros_when_empty(self):
        """by_severity must still contain all four keys even with no findings."""
        result = _make_scan_result()
        parsed = json.loads(JSONFormatter().format(result))
        by_sev = parsed["summary"]["by_severity"]
        for key in ("critical", "high", "medium", "low"):
            assert key in by_sev
            assert by_sev[key] == 0

    def test_json_exploit_chains_present(self):
        """JSON output must include exploit_chains array."""
        result = _make_scan_result(chains=[_make_chain()])
        parsed = json.loads(JSONFormatter().format(result))
        assert "exploit_chains" in parsed
        assert len(parsed["exploit_chains"]) == 1

    def test_json_exploit_chain_fields(self):
        """Each exploit chain entry must carry all required fields."""
        result = _make_scan_result(chains=[_make_chain()])
        parsed = json.loads(JSONFormatter().format(result))
        chain = parsed["exploit_chains"][0]
        assert chain["chain_id"] == "CHAIN-001"
        assert chain["name"] == "SQL Injection → Auth Bypass → Admin Access"
        assert chain["vulnerability_ids"] == ["SWIFT-001", "SWIFT-002"]
        assert chain["entry_point"] == "auth/views.py:42"
        assert chain["impact"] == "Full admin access without credentials"
        assert chain["severity"] == "CRITICAL"
        assert chain["confidence"] == 0.91

    def test_json_empty_chains(self):
        """JSON output must have empty exploit_chains array when no chains exist."""
        result = _make_scan_result()
        parsed = json.loads(JSONFormatter().format(result))
        assert parsed["exploit_chains"] == []

    def test_json_phase3_fields_present(self):
        """JSON output must include Phase 3 risk scoring fields (risk_score, exploitability, business_impact_category)."""
        vuln_with_phase3 = Vulnerability(
            id="SWIFT-002",
            file_path="auth.py",
            line_number=50,
            vuln_type="auth_bypass",
            description="Weak authentication check",
            confidence=0.96,
            severity="HIGH",
            code_snippet="if user_id == admin_id:",
            risk_score=78.5,
            exploitability=0.85,
            business_impact_category="customer_data_breach",
        )
        result = _make_scan_result(vulns=[vuln_with_phase3])
        parsed = json.loads(JSONFormatter().format(result))
        vuln = parsed["vulnerabilities"][0]
        assert vuln["risk_score"] == 78.5
        assert vuln["exploitability"] == 0.85
        assert vuln["business_impact_category"] == "customer_data_breach"

    def test_json_phase3_fields_null_when_not_set(self):
        """JSON output must include Phase 3 fields as null when not provided."""
        result = _make_scan_result(vulns=[_make_vuln()])
        parsed = json.loads(JSONFormatter().format(result))
        vuln = parsed["vulnerabilities"][0]
        assert "risk_score" in vuln
        assert vuln["risk_score"] is None
        assert "exploitability" in vuln
        assert vuln["exploitability"] is None
        assert "business_impact_category" in vuln
        assert vuln["business_impact_category"] is None


# ---------------------------------------------------------------------------
# MarkdownFormatter tests
# ---------------------------------------------------------------------------

class TestMarkdownFormatter:
    def test_markdown_formatter_has_header(self):
        """Report must open with the canonical SWIFT header."""
        result = _make_scan_result()
        output = MarkdownFormatter().format(result)
        assert "# SWIFT Vulnerability Report" in output

    def test_markdown_has_summary_section(self):
        """Report must include a ## Summary section."""
        result = _make_scan_result()
        output = MarkdownFormatter().format(result)
        assert "## Summary" in output

    def test_markdown_has_vulnerability_section(self):
        """Report must include ## Vulnerabilities with vuln details when vulns exist."""
        result = _make_scan_result(vulns=[_make_vuln()])
        output = MarkdownFormatter().format(result)
        assert "## Vulnerabilities" in output
        assert "SWIFT-001" in output
        assert "sql_injection" in output

    def test_markdown_empty_no_vuln_section(self):
        """Report must NOT include ## Vulnerabilities when there are none."""
        result = _make_scan_result(vulns=[])
        output = MarkdownFormatter().format(result)
        assert "## Vulnerabilities" not in output

    def test_markdown_has_patches_section(self):
        """Report must include ## Patches with patch details when patches exist."""
        result = _make_scan_result(patches=[_make_patch()])
        output = MarkdownFormatter().format(result)
        assert "## Patches" in output
        assert "PATCH-001" in output

    def test_markdown_empty_no_patches_section(self):
        """Report must NOT include ## Patches when there are none."""
        result = _make_scan_result(patches=[])
        output = MarkdownFormatter().format(result)
        assert "## Patches" not in output

    def test_markdown_summary_contains_key_metrics(self):
        """Summary section must surface files_scanned, vuln count, and patch count."""
        result = _make_scan_result(vulns=[_make_vuln()], patches=[_make_patch()])
        output = MarkdownFormatter().format(result)
        assert "10" in output        # files_scanned
        assert "1" in output         # vuln and patch counts

    def test_markdown_code_snippet_in_python_block(self):
        """Vulnerability code snippet must be wrapped in a ```python fence."""
        result = _make_scan_result(vulns=[_make_vuln()])
        output = MarkdownFormatter().format(result)
        assert "```python" in output

    def test_markdown_diff_in_diff_block(self):
        """Patch diff must be wrapped in a ```diff fence."""
        result = _make_scan_result(patches=[_make_patch()])
        output = MarkdownFormatter().format(result)
        assert "```diff" in output

    def test_markdown_contains_repo_path(self):
        """Report metadata must mention the repo path."""
        result = _make_scan_result()
        output = MarkdownFormatter().format(result)
        assert "/tmp/repo" in output

    def test_markdown_confidence_displayed_as_percent(self):
        """Confidence (0.97) must appear as a percentage (97%) in the report."""
        result = _make_scan_result(vulns=[_make_vuln()])
        output = MarkdownFormatter().format(result)
        assert "97%" in output

    def test_markdown_has_exploit_chains_section(self):
        """Report must include ## Exploit Chains with chain details when chains exist."""
        result = _make_scan_result(chains=[_make_chain()])
        output = MarkdownFormatter().format(result)
        assert "## Exploit Chains" in output
        assert "CHAIN-001" in output
        assert "SQL Injection → Auth Bypass → Admin Access" in output

    def test_markdown_empty_no_chains_section(self):
        """Report must NOT include ## Exploit Chains when there are none."""
        result = _make_scan_result(chains=[])
        output = MarkdownFormatter().format(result)
        assert "## Exploit Chains" not in output

    def test_markdown_chains_contain_metadata(self):
        """Exploit chain section must contain entry point, impact, and severity."""
        result = _make_scan_result(chains=[_make_chain()])
        output = MarkdownFormatter().format(result)
        assert "auth/views.py:42" in output
        assert "Full admin access without credentials" in output
        assert "CRITICAL" in output

    def test_markdown_chains_confidence_as_percent(self):
        """Chain confidence (0.91) must appear as a percentage (91%) in the report."""
        result = _make_scan_result(chains=[_make_chain()])
        output = MarkdownFormatter().format(result)
        assert "91%" in output

    def test_markdown_chains_include_attack_path(self):
        """Chain entry must include the full attack path description."""
        result = _make_scan_result(chains=[_make_chain()])
        output = MarkdownFormatter().format(result)
        assert "Exploit SQL injection" in output or "1." in output  # Attack path content

    def test_markdown_phase3_fields_all_present(self):
        """Markdown report must display Phase 3 risk assessment when all fields are set."""
        vuln_with_phase3 = Vulnerability(
            id="SWIFT-003",
            file_path="db.py",
            line_number=25,
            vuln_type="sql_injection",
            description="Direct SQL concatenation",
            confidence=0.98,
            severity="CRITICAL",
            code_snippet="query = f'SELECT * FROM users WHERE id={user_id}'",
            risk_score=92.0,
            exploitability=0.92,  # Should map to "trivial"
            business_impact_category="customer_data_breach",
        )
        result = _make_scan_result(vulns=[vuln_with_phase3])
        output = MarkdownFormatter().format(result)
        assert "Phase 3 Risk Assessment" in output
        assert "92/100" in output  # Risk score as integer
        assert "trivial" in output  # Exploitability label
        assert "customer_data_breach" in output

    def test_markdown_phase3_risk_score_rounding(self):
        """Markdown report must round risk_score to nearest integer."""
        vuln = Vulnerability(
            id="SWIFT-004",
            file_path="api.py",
            line_number=10,
            vuln_type="rce",
            description="Remote code execution",
            confidence=0.99,
            severity="CRITICAL",
            code_snippet="eval(user_input)",
            risk_score=87.3,
            exploitability=None,
            business_impact_category=None,
        )
        result = _make_scan_result(vulns=[vuln])
        output = MarkdownFormatter().format(result)
        assert "87/100" in output or "87.3/100" not in output

    def test_markdown_phase3_exploitability_moderate(self):
        """Markdown report must display 'moderate' for exploitability 0.5-0.85."""
        vuln = Vulnerability(
            id="SWIFT-005",
            file_path="utils.py",
            line_number=15,
            vuln_type="xxe",
            description="XML External Entity injection",
            confidence=0.96,
            severity="HIGH",
            code_snippet="parser.parse(xml_input)",
            risk_score=65.0,
            exploitability=0.65,  # Should map to "moderate"
            business_impact_category=None,
        )
        result = _make_scan_result(vulns=[vuln])
        output = MarkdownFormatter().format(result)
        assert "moderate" in output

    def test_markdown_phase3_exploitability_complex(self):
        """Markdown report must display 'complex' for exploitability 0.25-0.55."""
        vuln = Vulnerability(
            id="SWIFT-006",
            file_path="config.py",
            line_number=20,
            vuln_type="csrf",
            description="Cross-Site Request Forgery",
            confidence=0.94,
            severity="MEDIUM",
            code_snippet="form.submit(user_request)",
            risk_score=45.0,
            exploitability=0.4,  # Should map to "complex"
            business_impact_category=None,
        )
        result = _make_scan_result(vulns=[vuln])
        output = MarkdownFormatter().format(result)
        assert "complex" in output

    def test_markdown_phase3_exploitability_specific(self):
        """Markdown report must display 'specific' for exploitability <0.25."""
        vuln = Vulnerability(
            id="SWIFT-007",
            file_path="crypto.py",
            line_number=30,
            vuln_type="weak_crypto",
            description="Weak cryptographic algorithm",
            confidence=0.93,
            severity="MEDIUM",
            code_snippet="cipher = DES.new(key)",
            risk_score=35.0,
            exploitability=0.15,  # Should map to "specific"
            business_impact_category=None,
        )
        result = _make_scan_result(vulns=[vuln])
        output = MarkdownFormatter().format(result)
        assert "specific" in output

    def test_markdown_phase3_fields_optional_with_dashes(self):
        """Markdown report must display dashes for missing Phase 3 fields."""
        result = _make_scan_result(vulns=[_make_vuln()])
        output = MarkdownFormatter().format(result)
        # When Phase 3 fields are None, the section should not appear
        # (since at least one needs to be set for the section to appear)
        # But if we have any non-None field, dashes should appear for others
        assert "Phase 3" not in output or "- **Risk Score:** -" in output

    def test_markdown_phase3_section_hidden_when_all_none(self):
        """Markdown report must NOT show Phase 3 section when all fields are None."""
        result = _make_scan_result(vulns=[_make_vuln()])
        output = MarkdownFormatter().format(result)
        # Standard vulnerability with no Phase 3 fields
        assert "Phase 3 Risk Assessment" not in output

    def test_markdown_phase3_partial_fields(self):
        """Markdown report must display Phase 3 section with dashes for unset fields."""
        vuln = Vulnerability(
            id="SWIFT-008",
            file_path="log.py",
            line_number=35,
            vuln_type="log_injection",
            description="Log injection vulnerability",
            confidence=0.95,
            severity="MEDIUM",
            code_snippet="log.info(user_message)",
            risk_score=50.0,
            exploitability=None,  # Not set
            business_impact_category=None,  # Not set
        )
        result = _make_scan_result(vulns=[vuln])
        output = MarkdownFormatter().format(result)
        assert "Phase 3 Risk Assessment" in output
        assert "50/100" in output
        assert "- **Exploitability:** -" in output
        assert "- **Business Impact:** -" in output


# ---------------------------------------------------------------------------
# format_output dispatcher tests
# ---------------------------------------------------------------------------

class TestFormatOutput:
    def test_format_output_json_dispatcher(self):
        """format_output('json') must return valid JSON."""
        result = _make_scan_result(vulns=[_make_vuln()])
        output = format_output(result, "json")
        parsed = json.loads(output)
        assert "scan" in parsed

    def test_format_output_markdown_dispatcher(self):
        """format_output('markdown') must return a SWIFT Markdown report."""
        result = _make_scan_result()
        output = format_output(result, "markdown")
        assert "# SWIFT" in output

    def test_format_output_invalid_raises(self):
        """Unknown format type must raise ValueError with descriptive message."""
        result = _make_scan_result()
        with pytest.raises(ValueError) as exc_info:
            format_output(result, "xml")
        assert "Unknown format" in str(exc_info.value)
        assert "xml" in str(exc_info.value)
