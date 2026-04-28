from unittest.mock import MagicMock
from agent.models import EscalationPath, UnifiedScanResult, MergedFinding
from analysis.privesc import PrivilegeEscalationAnalyzer


def test_escalation_path_fields():
    path = EscalationPath(
        from_vuln="sql_injection",
        steps=["DB credential leak", "Admin panel access"],
        to_impact="account_takeover",
        severity="HIGH",
        finding_ids=["SIGNAL-abc123"],
        ascii_chain="SQLi ──► DB creds ──► Admin",
    )
    assert path.from_vuln == "sql_injection"
    assert path.severity == "HIGH"
    assert "DB credential leak" in path.steps
    assert "──►" in path.ascii_chain


def _make_result(vuln_types: list[str], actively_exploited: bool = False) -> UnifiedScanResult:
    """Build a minimal UnifiedScanResult with the given vuln_types."""
    merged = []
    for vt in vuln_types:
        mf = MagicMock(spec=MergedFinding)
        mf.vuln_type = vt
        mf.actively_exploited = actively_exploited
        mf.id = f"MERGED-{vt[:6]}"
        merged.append(mf)
    result = MagicMock(spec=UnifiedScanResult)
    result.merged_findings = merged
    result.code_only_findings = []
    result.kali_only_findings = []
    return result


def test_sqli_produces_escalation_path():
    result = _make_result(["sql_injection"])
    analyzer = PrivilegeEscalationAnalyzer()
    paths = analyzer.analyze(result)
    assert len(paths) == 1
    assert paths[0].from_vuln == "sql_injection"
    assert paths[0].to_impact == "account_takeover"
    assert paths[0].severity == "HIGH"
    assert "──►" in paths[0].ascii_chain


def test_command_injection_is_critical():
    result = _make_result(["command_injection"])
    paths = PrivilegeEscalationAnalyzer().analyze(result)
    assert paths[0].severity == "CRITICAL"


def test_actively_exploited_escalates_to_critical():
    result = _make_result(["sql_injection"], actively_exploited=True)
    paths = PrivilegeEscalationAnalyzer().analyze(result)
    assert paths[0].severity == "CRITICAL"


def test_unknown_vuln_type_produces_no_path():
    result = _make_result(["weird_unknown_type"])
    paths = PrivilegeEscalationAnalyzer().analyze(result)
    assert paths == []


def test_multiple_vulns_produce_multiple_paths():
    result = _make_result(["sql_injection", "ssrf"])
    paths = PrivilegeEscalationAnalyzer().analyze(result)
    assert len(paths) == 2
    types = {p.from_vuln for p in paths}
    assert "sql_injection" in types
    assert "ssrf" in types


def test_kali_finding_produces_escalation_path():
    result = MagicMock(spec=UnifiedScanResult)
    result.merged_findings = []
    result.code_only_findings = []
    result.kali_only_findings = [
        {"vuln_type": "command_injection", "id": "KALI-001"}
    ]
    paths = PrivilegeEscalationAnalyzer().analyze(result)
    assert len(paths) == 1
    assert paths[0].from_vuln == "command_injection"
    assert paths[0].severity == "CRITICAL"
