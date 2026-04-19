"""Integration tests for output formatters — no API calls needed."""
from __future__ import annotations

import json

import pytest

from output.formatters import JSONFormatter, MarkdownFormatter, format_output


class TestJSONFormatterIntegration:
    def test_valid_json_output(self, sample_scan_result):
        raw = JSONFormatter().format(sample_scan_result)
        data = json.loads(raw)  # raises if invalid
        assert data["scan"]["id"] == "scan-abc12345"

    def test_vuln_count_in_summary(self, sample_scan_result):
        data = json.loads(JSONFormatter().format(sample_scan_result))
        assert data["summary"]["vulnerabilities_found"] == 1

    def test_patch_count_in_summary(self, sample_scan_result):
        data = json.loads(JSONFormatter().format(sample_scan_result))
        assert data["summary"]["patches_generated"] == 1

    def test_severity_breakdown(self, sample_scan_result):
        data = json.loads(JSONFormatter().format(sample_scan_result))
        assert data["summary"]["by_severity"]["critical"] == 1

    def test_empty_result(self, empty_scan_result):
        data = json.loads(JSONFormatter().format(empty_scan_result))
        assert data["summary"]["vulnerabilities_found"] == 0

    def test_vuln_fields_present(self, sample_scan_result):
        data = json.loads(JSONFormatter().format(sample_scan_result))
        vuln = data["vulnerabilities"][0]
        assert vuln["id"] == "SWIFT-001"
        assert vuln["confidence"] == 0.97

    def test_patch_fields_present(self, sample_scan_result):
        data = json.loads(JSONFormatter().format(sample_scan_result))
        patch = data["patches"][0]
        assert patch["vuln_id"] == "SWIFT-001"
        assert "diff" in patch


class TestMarkdownFormatterIntegration:
    def test_has_title(self, sample_scan_result):
        md = MarkdownFormatter().format(sample_scan_result)
        assert "# SWIFT Vulnerability Report" in md

    def test_repo_path_present(self, sample_scan_result):
        md = MarkdownFormatter().format(sample_scan_result)
        assert "/tmp/test-repo" in md

    def test_vuln_section_present(self, sample_scan_result):
        md = MarkdownFormatter().format(sample_scan_result)
        assert "## Vulnerabilities" in md

    def test_patch_section_present(self, sample_scan_result):
        md = MarkdownFormatter().format(sample_scan_result)
        assert "## Patches" in md

    def test_empty_result_no_vuln_section(self, empty_scan_result):
        md = MarkdownFormatter().format(empty_scan_result)
        assert "## Vulnerabilities" not in md
        assert "No vulnerabilities found" in md

    def test_confidence_percentage(self, sample_scan_result):
        md = MarkdownFormatter().format(sample_scan_result)
        assert "97%" in md

    def test_code_block_present(self, sample_scan_result):
        md = MarkdownFormatter().format(sample_scan_result)
        assert "```python" in md


class TestFormatOutputDispatch:
    def test_json_dispatch(self, sample_scan_result):
        result = format_output(sample_scan_result, "json")
        json.loads(result)  # must be valid JSON

    def test_markdown_dispatch(self, sample_scan_result):
        result = format_output(sample_scan_result, "markdown")
        assert "# SWIFT" in result

    def test_unknown_format_raises(self, sample_scan_result):
        with pytest.raises(ValueError, match="Unknown format"):
            format_output(sample_scan_result, "xml")
