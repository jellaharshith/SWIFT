"""Unit tests for SARIF 2.1.0 formatter — GitHub Advanced Security integration."""
import json

import pytest

from agent.models import ScanResult, Vulnerability
from output.sarif import SARIFFormatter


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------

def _make_vuln(
    id="SWIFT-001",
    cwe_id="CWE-89",
    severity="CRITICAL",
    confidence=0.97,
    exploitability=0.9,
    business_impact_category="customer_data_breach",
    risk_score=87.3,
) -> Vulnerability:
    """Create a test vulnerability with all Phase 3 risk fields."""
    return Vulnerability(
        id=id,
        file_path="app.py",
        line_number=42,
        vuln_type="sql_injection",
        description="User input in SQL query",
        confidence=confidence,
        severity=severity,
        code_snippet='query = f"SELECT * FROM users WHERE id={user_id}"',
        cwe_id=cwe_id,
        cwe_url="https://cwe.mitre.org/data/definitions/89.html",
        remediation="Use parameterized queries",
        remediation_code="query = 'SELECT * FROM users WHERE id=?'",
        exploitability=exploitability,
        business_impact_category=business_impact_category,
        risk_score=risk_score,
    )


def _make_scan_result(vulns=None) -> ScanResult:
    """Create a test scan result."""
    return ScanResult(
        scan_id="SCAN-001",
        repo_path="/tmp/repo",
        files_scanned=10,
        vulnerabilities=vulns if vulns is not None else [],
        patches=[],
        duration_seconds=5.0,
        total_cost_usd=0.42,
        timestamp="2026-04-20T12:00:00Z",
    )


# ---------------------------------------------------------------------------
# SARIF Schema Compliance Tests
# ---------------------------------------------------------------------------

class TestSARIFSchemaCompliance:
    def test_sarif_formatter_produces_valid_json(self):
        """SARIF output must be valid, parseable JSON."""
        result = _make_scan_result(vulns=[_make_vuln()])
        output = SARIFFormatter().format(result)
        parsed = json.loads(output)  # raises if invalid
        assert isinstance(parsed, dict)

    def test_sarif_has_version(self):
        """SARIF must declare version 2.1.0."""
        result = _make_scan_result(vulns=[_make_vuln()])
        parsed = json.loads(SARIFFormatter().format(result))
        assert parsed["version"] == "2.1.0"

    def test_sarif_has_schema_uri(self):
        """SARIF must reference the official SARIF 2.1.0 schema."""
        result = _make_scan_result(vulns=[_make_vuln()])
        parsed = json.loads(SARIFFormatter().format(result))
        assert "$schema" in parsed
        assert "sarif-schema-2.1.0" in parsed["$schema"]

    def test_sarif_has_runs_array(self):
        """SARIF must have a 'runs' array with at least one run."""
        result = _make_scan_result(vulns=[_make_vuln()])
        parsed = json.loads(SARIFFormatter().format(result))
        assert "runs" in parsed
        assert isinstance(parsed["runs"], list)
        assert len(parsed["runs"]) >= 1

    def test_sarif_run_has_tool_driver(self):
        """Each SARIF run must have tool.driver with name and version."""
        result = _make_scan_result(vulns=[_make_vuln()])
        parsed = json.loads(SARIFFormatter().format(result))
        run = parsed["runs"][0]
        assert "tool" in run
        assert "driver" in run["tool"]
        assert run["tool"]["driver"]["name"] == "SWIFT"
        assert run["tool"]["driver"]["version"] == "0.1.0"

    def test_sarif_run_has_tool_uri(self):
        """SARIF tool driver must have informationUri."""
        result = _make_scan_result(vulns=[_make_vuln()])
        parsed = json.loads(SARIFFormatter().format(result))
        run = parsed["runs"][0]
        assert "informationUri" in run["tool"]["driver"]
        assert "github" in run["tool"]["driver"]["informationUri"]


# ---------------------------------------------------------------------------
# CWE to Rule Mapping Tests
# ---------------------------------------------------------------------------

class TestSARIFCWEMapping:
    def test_sarif_extracts_unique_cwe_ids(self):
        """SARIF must extract unique CWE IDs from vulnerabilities."""
        vuln1 = _make_vuln(id="SWIFT-001", cwe_id="CWE-89")
        vuln2 = _make_vuln(id="SWIFT-002", cwe_id="CWE-79")
        vuln3 = _make_vuln(id="SWIFT-003", cwe_id="CWE-89")  # Duplicate CWE
        result = _make_scan_result(vulns=[vuln1, vuln2, vuln3])
        parsed = json.loads(SARIFFormatter().format(result))
        rules = parsed["runs"][0]["tool"]["driver"]["rules"]
        # Should have 2 unique CWEs
        cwe_ids = [rule["id"] for rule in rules]
        assert len(set(cwe_ids)) == 2
        assert "CWE-89" in cwe_ids
        assert "CWE-79" in cwe_ids

    def test_sarif_rule_has_id_and_name(self):
        """Each SARIF rule must have id and human-readable name."""
        result = _make_scan_result(vulns=[_make_vuln(cwe_id="CWE-89")])
        parsed = json.loads(SARIFFormatter().format(result))
        rules = parsed["runs"][0]["tool"]["driver"]["rules"]
        rule = rules[0]
        assert rule["id"] == "CWE-89"
        assert rule["name"] == "SQL Injection"  # Must have human-readable name

    def test_sarif_rule_has_descriptions(self):
        """Each SARIF rule must have shortDescription and help."""
        result = _make_scan_result(vulns=[_make_vuln(cwe_id="CWE-89")])
        parsed = json.loads(SARIFFormatter().format(result))
        rules = parsed["runs"][0]["tool"]["driver"]["rules"]
        rule = rules[0]
        assert "shortDescription" in rule
        assert "text" in rule["shortDescription"]
        assert "help" in rule
        assert "text" in rule["help"]
        # Help should mention parameterized queries for SQL injection
        assert "parameterized" in rule["help"]["text"].lower()

    def test_sarif_rule_has_default_level(self):
        """Each SARIF rule must have defaultConfiguration.level."""
        result = _make_scan_result(vulns=[_make_vuln(cwe_id="CWE-89")])
        parsed = json.loads(SARIFFormatter().format(result))
        rules = parsed["runs"][0]["tool"]["driver"]["rules"]
        rule = rules[0]
        assert "defaultConfiguration" in rule
        assert "level" in rule["defaultConfiguration"]
        # CRITICAL CWE should default to error level
        assert rule["defaultConfiguration"]["level"] == "error"

    def test_sarif_rule_has_help_uri(self):
        """SARIF rule should have helpUri for vulnerability reference."""
        result = _make_scan_result(vulns=[_make_vuln(cwe_id="CWE-89")])
        parsed = json.loads(SARIFFormatter().format(result))
        rules = parsed["runs"][0]["tool"]["driver"]["rules"]
        rule = rules[0]
        # helpUri is optional but recommended
        if "helpUri" in rule:
            assert "cwe" in rule["helpUri"].lower() or "mitre" in rule["helpUri"].lower()


# ---------------------------------------------------------------------------
# SARIF Severity Mapping Tests
# ---------------------------------------------------------------------------

class TestSARIFSeverityMapping:
    def test_critical_maps_to_error(self):
        """CRITICAL severity must map to 'error' SARIF level."""
        vuln = _make_vuln(severity="CRITICAL")
        result = _make_scan_result(vulns=[vuln])
        parsed = json.loads(SARIFFormatter().format(result))
        results = parsed["runs"][0]["results"]
        assert results[0]["level"] == "error"

    def test_high_maps_to_error(self):
        """HIGH severity must map to 'error' SARIF level."""
        vuln = _make_vuln(severity="HIGH")
        result = _make_scan_result(vulns=[vuln])
        parsed = json.loads(SARIFFormatter().format(result))
        results = parsed["runs"][0]["results"]
        assert results[0]["level"] == "error"

    def test_medium_maps_to_warning(self):
        """MEDIUM severity must map to 'warning' SARIF level."""
        vuln = _make_vuln(severity="MEDIUM")
        result = _make_scan_result(vulns=[vuln])
        parsed = json.loads(SARIFFormatter().format(result))
        results = parsed["runs"][0]["results"]
        assert results[0]["level"] == "warning"

    def test_low_maps_to_note(self):
        """LOW severity must map to 'note' SARIF level."""
        vuln = _make_vuln(severity="LOW")
        result = _make_scan_result(vulns=[vuln])
        parsed = json.loads(SARIFFormatter().format(result))
        results = parsed["runs"][0]["results"]
        assert results[0]["level"] == "note"


# ---------------------------------------------------------------------------
# Custom Properties Tests
# ---------------------------------------------------------------------------

class TestSARIFCustomProperties:
    def test_sarif_result_has_swift_properties(self):
        """SARIF results must include SWIFT-specific custom properties."""
        vuln = _make_vuln(severity="CRITICAL", confidence=0.97)
        result = _make_scan_result(vulns=[vuln])
        parsed = json.loads(SARIFFormatter().format(result))
        results = parsed["runs"][0]["results"]
        props = results[0]["properties"]
        assert "swift-severity" in props
        assert props["swift-severity"] == "CRITICAL"
        assert "swift-confidence" in props
        assert props["swift-confidence"] == 0.97
        assert "swift-vuln-type" in props
        assert props["swift-vuln-type"] == "sql_injection"
        assert "swift-id" in props
        assert props["swift-id"] == "SWIFT-001"

    def test_sarif_result_includes_risk_score(self):
        """SARIF result properties must include risk-score when available."""
        vuln = _make_vuln(risk_score=87.3)
        result = _make_scan_result(vulns=[vuln])
        parsed = json.loads(SARIFFormatter().format(result))
        results = parsed["runs"][0]["results"]
        props = results[0]["properties"]
        assert "swift-risk-score" in props
        assert props["swift-risk-score"] == 87.3

    def test_sarif_result_includes_exploitability(self):
        """SARIF result properties must include exploitability when available."""
        vuln = _make_vuln(exploitability=0.85)
        result = _make_scan_result(vulns=[vuln])
        parsed = json.loads(SARIFFormatter().format(result))
        results = parsed["runs"][0]["results"]
        props = results[0]["properties"]
        assert "swift-exploitability" in props
        assert props["swift-exploitability"] == 0.85

    def test_sarif_result_includes_business_impact(self):
        """SARIF result properties must include business impact when available."""
        vuln = _make_vuln(business_impact_category="customer_data_breach")
        result = _make_scan_result(vulns=[vuln])
        parsed = json.loads(SARIFFormatter().format(result))
        results = parsed["runs"][0]["results"]
        props = results[0]["properties"]
        assert "swift-business-impact" in props
        assert props["swift-business-impact"] == "customer_data_breach"


# ---------------------------------------------------------------------------
# SARIF Location and Message Tests
# ---------------------------------------------------------------------------

class TestSARIFLocation:
    def test_sarif_result_has_location(self):
        """SARIF results must include locations with file and line number."""
        vuln = _make_vuln()
        result = _make_scan_result(vulns=[vuln])
        parsed = json.loads(SARIFFormatter().format(result))
        results = parsed["runs"][0]["results"]
        assert "locations" in results[0]
        assert len(results[0]["locations"]) > 0
        loc = results[0]["locations"][0]
        assert "physicalLocation" in loc
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == "app.py"
        assert loc["physicalLocation"]["region"]["startLine"] == 42

    def test_sarif_result_includes_code_snippet(self):
        """SARIF result should include code snippet when available."""
        vuln = _make_vuln()
        result = _make_scan_result(vulns=[vuln])
        parsed = json.loads(SARIFFormatter().format(result))
        results = parsed["runs"][0]["results"]
        loc = results[0]["locations"][0]
        assert "snippet" in loc["physicalLocation"]["region"]
        assert "SELECT * FROM users" in loc["physicalLocation"]["region"]["snippet"]["text"]

    def test_sarif_result_has_message(self):
        """SARIF results must have a message describing the finding."""
        vuln = _make_vuln()
        result = _make_scan_result(vulns=[vuln])
        parsed = json.loads(SARIFFormatter().format(result))
        results = parsed["runs"][0]["results"]
        assert "message" in results[0]
        assert "text" in results[0]["message"]
        assert results[0]["message"]["text"] == "User input in SQL query"


# ---------------------------------------------------------------------------
# Multiple Vulnerabilities Test
# ---------------------------------------------------------------------------

class TestSARIFMultipleVulnerabilities:
    def test_sarif_handles_multiple_vulns(self):
        """SARIF must correctly handle multiple vulnerabilities."""
        vuln1 = _make_vuln(id="SWIFT-001", cwe_id="CWE-89")
        vuln2 = _make_vuln(id="SWIFT-002", cwe_id="CWE-79", severity="HIGH")
        vuln3 = _make_vuln(id="SWIFT-003", cwe_id="CWE-434", severity="MEDIUM")
        result = _make_scan_result(vulns=[vuln1, vuln2, vuln3])
        parsed = json.loads(SARIFFormatter().format(result))
        results = parsed["runs"][0]["results"]
        assert len(results) == 3
        # Verify each result has correct properties
        ids = [r["properties"]["swift-id"] for r in results]
        assert "SWIFT-001" in ids
        assert "SWIFT-002" in ids
        assert "SWIFT-003" in ids

    def test_sarif_multiple_rules(self):
        """SARIF must create multiple rules for different CWE IDs."""
        vuln1 = _make_vuln(id="SWIFT-001", cwe_id="CWE-89")
        vuln2 = _make_vuln(id="SWIFT-002", cwe_id="CWE-79")
        result = _make_scan_result(vulns=[vuln1, vuln2])
        parsed = json.loads(SARIFFormatter().format(result))
        rules = parsed["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 2
        rule_ids = [r["id"] for r in rules]
        assert "CWE-89" in rule_ids
        assert "CWE-79" in rule_ids


# ---------------------------------------------------------------------------
# Remediation Test
# ---------------------------------------------------------------------------

class TestSARIFRemediation:
    def test_sarif_includes_remediation_when_available(self):
        """SARIF results should include fix guidance when remediation is available."""
        vuln = _make_vuln()
        result = _make_scan_result(vulns=[vuln])
        parsed = json.loads(SARIFFormatter().format(result))
        results = parsed["runs"][0]["results"]
        assert "fix" in results[0]
        # Fix should contain artifact changes
        assert "artifactChanges" in results[0]["fix"]

    def test_sarif_empty_vulnerabilities(self):
        """SARIF must handle empty vulnerability list gracefully."""
        result = _make_scan_result(vulns=[])
        parsed = json.loads(SARIFFormatter().format(result))
        results = parsed["runs"][0]["results"]
        assert results == []
        # But rules array should exist (though empty)
        rules = parsed["runs"][0]["tool"]["driver"]["rules"]
        assert isinstance(rules, list)


# ---------------------------------------------------------------------------
# GitHub Integration Tests
# ---------------------------------------------------------------------------

class TestSARIFGitHubIntegration:
    def test_sarif_valid_for_github_scanning(self):
        """SARIF output must be valid for GitHub code scanning integration."""
        vuln = _make_vuln()
        result = _make_scan_result(vulns=[vuln])
        output = SARIFFormatter().format(result)
        parsed = json.loads(output)

        # GitHub requirements:
        # 1. Valid JSON with version
        assert parsed["version"] == "2.1.0"

        # 2. Has runs with results
        assert len(parsed["runs"]) > 0
        run = parsed["runs"][0]
        assert "results" in run

        # 3. Tool has driver with rules
        assert "tool" in run
        assert "driver" in run["tool"]
        assert "rules" in run["tool"]["driver"]

        # 4. Results have proper location structure
        if run["results"]:
            result_item = run["results"][0]
            assert "locations" in result_item
            assert "ruleId" in result_item

    def test_sarif_run_properties_include_scan_metadata(self):
        """SARIF run should include scan metadata in properties."""
        result = _make_scan_result(vulns=[_make_vuln()])
        parsed = json.loads(SARIFFormatter().format(result))
        run = parsed["runs"][0]
        assert "properties" in run
        assert run["properties"]["scan_id"] == "SCAN-001"
        assert run["properties"]["repo_path"] == "/tmp/repo"
