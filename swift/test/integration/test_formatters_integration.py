"""Integration tests for output formatters — no API calls needed."""
from __future__ import annotations

import json

import pytest

from agent.models import AttackStep, ExploitChain
from output.chains import ChainsFormatter
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


class TestJSONFormatterEvidenceFields:
    """Test that JSON formatter includes all 11 evidence bundle fields."""

    def test_json_formatter_includes_all_evidence_fields(self, sample_scan_result):
        """Verify all 11 evidence bundle fields are in JSON output."""
        data = json.loads(JSONFormatter().format(sample_scan_result))
        vuln = data["vulnerabilities"][0]

        # All 11 evidence bundle fields
        expected_fields = [
            "cwe_id",
            "cwe_url",
            "owasp_category",
            "exploit_description",
            "exploit_impact",
            "remediation",
            "remediation_code",
            "remediation_effort",
            "remediation_time_minutes",
            "affected_code",
            "references",
        ]

        for field in expected_fields:
            assert field in vuln, f"Missing evidence field: {field}"

    def test_json_formatter_evidence_fields_are_null_when_not_set(self, sample_scan_result):
        """Verify evidence fields are null when not populated in vulnerability."""
        data = json.loads(JSONFormatter().format(sample_scan_result))
        vuln = data["vulnerabilities"][0]

        # Sample vulnerability doesn't have evidence fields, so they should be null
        assert vuln["cwe_id"] is None
        assert vuln["cwe_url"] is None
        assert vuln["owasp_category"] is None
        assert vuln["exploit_description"] is None
        assert vuln["exploit_impact"] is None
        assert vuln["remediation"] is None
        assert vuln["remediation_code"] is None
        assert vuln["remediation_effort"] is None
        assert vuln["remediation_time_minutes"] is None
        assert vuln["affected_code"] is None
        assert vuln["references"] == []

    def test_json_formatter_preserves_evidence_when_populated(self, sample_scan_result):
        """Verify evidence fields are preserved when populated."""
        # Populate evidence fields in the vulnerability
        sample_scan_result.vulnerabilities[0].cwe_id = "CWE-89"
        sample_scan_result.vulnerabilities[0].cwe_url = "https://cwe.mitre.org/data/definitions/89.html"
        sample_scan_result.vulnerabilities[0].owasp_category = "A03:2021 – Injection"
        sample_scan_result.vulnerabilities[0].exploit_description = "Attacker can inject SQL code"
        sample_scan_result.vulnerabilities[0].exploit_impact = "Database compromise"
        sample_scan_result.vulnerabilities[0].remediation = "Use parameterized queries"
        sample_scan_result.vulnerabilities[0].remediation_code = "cursor.execute(query, (param,))"
        sample_scan_result.vulnerabilities[0].remediation_effort = "LOW"
        sample_scan_result.vulnerabilities[0].remediation_time_minutes = 5
        sample_scan_result.vulnerabilities[0].affected_code = {
            "before": "query = f'SELECT * FROM users WHERE id={id}'",
            "after": "cursor.execute('SELECT * FROM users WHERE id=?', (id,))",
        }
        sample_scan_result.vulnerabilities[0].references = ["https://owasp.org"]

        data = json.loads(JSONFormatter().format(sample_scan_result))
        vuln = data["vulnerabilities"][0]

        assert vuln["cwe_id"] == "CWE-89"
        assert vuln["cwe_url"] == "https://cwe.mitre.org/data/definitions/89.html"
        assert vuln["owasp_category"] == "A03:2021 – Injection"
        assert vuln["exploit_description"] == "Attacker can inject SQL code"
        assert vuln["exploit_impact"] == "Database compromise"
        assert vuln["remediation"] == "Use parameterized queries"
        assert vuln["remediation_code"] == "cursor.execute(query, (param,))"
        assert vuln["remediation_effort"] == "LOW"
        assert vuln["remediation_time_minutes"] == 5
        assert vuln["affected_code"]["before"] == "query = f'SELECT * FROM users WHERE id={id}'"
        assert vuln["references"] == ["https://owasp.org"]


class TestChainsFormatter:
    """Test the new ChainsFormatter for standalone exploit chain exports."""

    def test_chains_formatter_valid_json_output(self, sample_scan_result_with_chains):
        """Verify chains formatter produces valid JSON."""
        raw = ChainsFormatter().format(sample_scan_result_with_chains)
        data = json.loads(raw)  # raises if invalid JSON
        assert data["scan_id"] == "scan-abc12345"

    def test_chains_formatter_includes_export_timestamp(self, sample_scan_result_with_chains):
        """Verify export timestamp is included."""
        data = json.loads(ChainsFormatter().format(sample_scan_result_with_chains))
        assert "export_timestamp" in data
        assert "T" in data["export_timestamp"]  # ISO format includes T

    def test_chains_formatter_includes_scan_metadata(self, sample_scan_result_with_chains):
        """Verify scan metadata is included."""
        data = json.loads(ChainsFormatter().format(sample_scan_result_with_chains))
        assert data["scan_id"] == "scan-abc12345"
        assert data["scan_repo_path"] == "/tmp/test-repo"
        assert data["total_chains"] == 1

    def test_chains_formatter_exports_attack_steps_complete(self, sample_scan_result_with_chains):
        """Verify all attack steps are exported with complete details."""
        data = json.loads(ChainsFormatter().format(sample_scan_result_with_chains))
        chain = data["chains"][0]

        assert "attack_steps" in chain
        assert len(chain["attack_steps"]) == 2

        # Step 1
        step1 = chain["attack_steps"][0]
        assert step1["step"] == 1
        assert step1["vuln_id"] == "SWIFT-001"
        assert step1["entry_point"] == "auth/views.py:42"
        assert "Exploit SQL injection" in step1["description"]

        # Step 2
        step2 = chain["attack_steps"][1]
        assert step2["step"] == 2
        assert step2["vuln_id"] == "SWIFT-003"
        assert step2["entry_point"] == "admin/views.py:15"

    def test_chains_formatter_includes_chain_properties(self, sample_scan_result_with_chains):
        """Verify all chain properties are in output."""
        data = json.loads(ChainsFormatter().format(sample_scan_result_with_chains))
        chain = data["chains"][0]

        required_props = [
            "chain_id",
            "name",
            "vulnerability_ids",
            "estimated_impact",
            "attack_feasibility",
            "time_to_exploit",
            "entry_point",
            "confidence",
            "severity",
        ]

        for prop in required_props:
            assert prop in chain, f"Missing property: {prop}"

    def test_chains_formatter_feasibility_from_confidence(self, sample_scan_result_with_chains):
        """Verify attack feasibility is derived from confidence."""
        data = json.loads(ChainsFormatter().format(sample_scan_result_with_chains))
        chain = data["chains"][0]

        # Confidence 0.91 should map to HIGH
        assert chain["attack_feasibility"] == "HIGH"
        assert chain["time_to_exploit"] == "5-15 minutes"

    def test_chains_formatter_empty_chains(self, sample_scan_result):
        """Verify formatter handles no chains gracefully."""
        data = json.loads(ChainsFormatter().format(sample_scan_result))
        assert data["total_chains"] == 0
        assert data["chains"] == []

    def test_chains_formatter_multiple_chains(self, sample_scan_result_with_chains):
        """Verify formatter handles multiple chains."""
        # Add another chain
        chain2 = ExploitChain(
            chain_id="CHAIN-002",
            name="XSS → Session Hijacking",
            vulnerability_ids=["SWIFT-002"],
            attack_path="Inject XSS payload to steal session cookie",
            entry_point="views/page.py:88",
            impact="User session compromise",
            severity="HIGH",
            confidence=0.87,
            attack_steps=[
                AttackStep(
                    step=1,
                    description="Inject XSS payload",
                    vuln_id="SWIFT-002",
                    entry_point="views/page.py:88",
                ),
            ],
        )
        sample_scan_result_with_chains.exploit_chains.append(chain2)

        data = json.loads(ChainsFormatter().format(sample_scan_result_with_chains))
        assert data["total_chains"] == 2
        assert len(data["chains"]) == 2
        assert data["chains"][0]["chain_id"] == "CHAIN-001"
        assert data["chains"][1]["chain_id"] == "CHAIN-002"


class TestJSONAndChainsFormattersTogether:
    """Test JSON and Chains formatters working together in the pipeline."""

    def test_both_formatters_output_valid_json(self, sample_scan_result_with_chains):
        """Verify both formatters produce valid JSON."""
        json_output = JSONFormatter().format(sample_scan_result_with_chains)
        chains_output = ChainsFormatter().format(sample_scan_result_with_chains)

        json_data = json.loads(json_output)
        chains_data = json.loads(chains_output)

        assert json_data["scan"]["id"] == "scan-abc12345"
        assert chains_data["scan_id"] == "scan-abc12345"

    def test_json_includes_chains_in_output(self, sample_scan_result_with_chains):
        """Verify JSON formatter includes chains."""
        data = json.loads(JSONFormatter().format(sample_scan_result_with_chains))
        assert "exploit_chains" in data
        assert len(data["exploit_chains"]) == 1

    def test_json_chains_section_has_required_fields(self, sample_scan_result_with_chains):
        """Verify JSON chains section includes all required fields."""
        data = json.loads(JSONFormatter().format(sample_scan_result_with_chains))
        chain = data["exploit_chains"][0]

        required_fields = [
            "chain_id",
            "name",
            "vulnerability_ids",
            "attack_path",
            "entry_point",
            "impact",
            "severity",
            "confidence",
        ]

        for field in required_fields:
            assert field in chain, f"Missing field in JSON chains: {field}"

    def test_chains_formatter_standalone_has_attack_steps(self, sample_scan_result_with_chains):
        """Verify standalone chains export includes attack_steps (not in JSON formatter)."""
        chains_data = json.loads(ChainsFormatter().format(sample_scan_result_with_chains))
        chain = chains_data["chains"][0]

        # Standalone chains export includes attack_steps
        assert "attack_steps" in chain
        assert len(chain["attack_steps"]) == 2

    def test_both_formatters_with_evidence_fields(self, sample_scan_result_with_chains):
        """Verify JSON formatter includes evidence fields in vulnerability section."""
        sample_scan_result_with_chains.vulnerabilities[0].cwe_id = "CWE-89"
        sample_scan_result_with_chains.vulnerabilities[0].remediation = "Use parameterized queries"

        json_data = json.loads(JSONFormatter().format(sample_scan_result_with_chains))
        vuln = json_data["vulnerabilities"][0]

        assert vuln["cwe_id"] == "CWE-89"
        assert vuln["remediation"] == "Use parameterized queries"
