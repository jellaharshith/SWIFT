"""Unit tests for output formatters — pure data transformation, no API calls."""
import json

import pytest

from agent.models import Patch, ScanResult, Vulnerability
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


def _make_scan_result(vulns=None, patches=None) -> ScanResult:
    return ScanResult(
        scan_id="SCAN-001",
        repo_path="/tmp/repo",
        files_scanned=10,
        vulnerabilities=vulns if vulns is not None else [],
        patches=patches if patches is not None else [],
        duration_seconds=5.0,
        total_cost_usd=0.42,
        timestamp="2026-04-18T12:00:00Z",
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
