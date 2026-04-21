"""Unit tests for SeverityRanker."""
from agent.models import Vulnerability
from triage.severity_ranker import SeverityRanker


def _vuln(vuln_id: str, severity: str, confidence: float, exploitability: float) -> Vulnerability:
    return Vulnerability(
        id=vuln_id,
        file_path="app.py",
        line_number=1,
        vuln_type="sql_injection",
        description="test",
        confidence=confidence,
        severity=severity,
        code_snippet="SELECT *",
        exploitability=exploitability,
    )


def test_score_combines_base_and_chain_impact():
    ranker = SeverityRanker()
    vuln = _vuln("SWIFT-001", "CRITICAL", 1.0, 1.0)

    # base risk = 100; combined should be 60 when no chain impact.
    assert ranker.score_vulnerability(vuln, chain_impact=0.0) == 60.0
    assert ranker.score_vulnerability(vuln, chain_impact=100.0) == 100.0


def test_rank_findings_returns_top_10_sorted():
    ranker = SeverityRanker()
    vulns = [
        _vuln(f"SWIFT-{idx:03d}", "MEDIUM", 0.8, 0.6)
        for idx in range(1, 13)
    ]
    # Boost one finding via chain impact.
    chain_impact = {"SWIFT-005": 100.0}

    ranked = ranker.rank_findings(vulns, chain_impact_by_vuln_id=chain_impact, top_n=10)
    assert len(ranked) == 10
    assert ranked[0][0].id == "SWIFT-005"
    assert ranked[0][1] >= ranked[-1][1]
