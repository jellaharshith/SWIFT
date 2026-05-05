import os, tempfile
from unittest.mock import MagicMock
from output.bug_bounty_report import BugBountyFormatter
from agent.models import (
    UnifiedScanResult, MergedFinding, Vulnerability,
    EscalationPath
)
from feeds.live_cve import CVEMatch, CVEEntry


def _make_merged_finding(
    vuln_type="sql_injection",
    severity="HIGH",
    cve_id=None,
    actively_exploited=False,
) -> MergedFinding:
    mf = MagicMock(spec=MergedFinding)
    mf.id = "MERGED-abc123"
    mf.vuln_type = vuln_type
    mf.severity = severity
    mf.actively_exploited = actively_exploited
    mf.sources = ["code", "kali"]
    mf.mitre_techniques = [{"technique_id": "T1190", "technique": "Exploit Public-Facing App", "tactic": "Initial Access"}]

    cf = MagicMock(spec=Vulnerability)
    cf.file_path = "src/api/users.py"
    cf.line_number = 42
    cf.cwe_id = "CWE-89"
    cf.exploit_description = "Attacker sends malicious SQL payload"
    cf.exploit_impact = "Full database read access"
    cf.remediation = "Use parameterized queries"
    cf.confidence = 0.97
    mf.code_finding = cf

    if cve_id:
        entry = MagicMock(spec=CVEEntry)
        entry.cve_id = cve_id
        entry.cvss_score = 8.8
        entry.severity = severity
        cve_match = MagicMock(spec=CVEMatch)
        cve_match.cve = entry
        mf.cve_matches = [cve_match]
    else:
        mf.cve_matches = []

    mf.kali_finding = None
    return mf


def _make_result(findings=None, escalation_paths=None) -> tuple:
    result = MagicMock(spec=UnifiedScanResult)
    result.scan_id = "abc123"
    result.started_at = "2026-04-27T10:00:00Z"
    result.duration = 47.3
    result.merged_findings = findings or []
    result.code_only_findings = []
    result.kali_only_findings = []
    result.all_cve_matches = []
    result.exploit_chains = []
    result.repo_path = "/tmp/myapp"
    result.kali_target = "example.com"
    return result, escalation_paths or []


def test_format_contains_steps_to_reproduce():
    result, paths = _make_result([_make_merged_finding()])
    output = BugBountyFormatter().format_markdown(result, paths)
    assert "Steps to Reproduce" in output


def test_format_contains_impact():
    result, paths = _make_result([_make_merged_finding()])
    output = BugBountyFormatter().format_markdown(result, paths)
    assert "Impact" in output


def test_format_contains_severity_label():
    result, paths = _make_result([_make_merged_finding(severity="CRITICAL")])
    output = BugBountyFormatter().format_markdown(result, paths)
    assert "CRITICAL" in output


def test_format_contains_cve_when_present():
    result, paths = _make_result([_make_merged_finding(cve_id="CVE-2024-12345")])
    output = BugBountyFormatter().format_markdown(result, paths)
    assert "CVE-2024-12345" in output


def test_format_contains_escalation_chain():
    path = EscalationPath(
        from_vuln="sql_injection",
        steps=["DB credential leak"],
        to_impact="account_takeover",
        severity="HIGH",
        finding_ids=["MERGED-abc123"],
        ascii_chain="sql_injection ──► DB credential leak ──► account_takeover",
    )
    result, _ = _make_result([_make_merged_finding()])
    output = BugBountyFormatter().format_markdown(result, [path])
    assert "Privilege Escalation" in output
    assert "──►" in output


def test_save_creates_file():
    result, paths = _make_result([_make_merged_finding()])
    with tempfile.TemporaryDirectory() as d:
        path = BugBountyFormatter().save(result, paths, d)
        assert os.path.exists(path)
        assert "report-bounty-" in path
        content = open(path).read()
        assert "Steps to Reproduce" in content


def test_format_contains_actively_exploited_badge():
    result, paths = _make_result([_make_merged_finding(actively_exploited=True)])
    output = BugBountyFormatter().format_markdown(result, paths)
    assert "ACTIVELY EXPLOITED" in output
