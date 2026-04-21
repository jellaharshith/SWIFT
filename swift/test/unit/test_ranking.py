"""Unit tests for risk scoring and vulnerability ranking module."""
import pytest

from agent.models import Vulnerability
from triage.ranking import RiskScorer


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------

def _make_vuln(
    id="SWIFT-001",
    severity="CRITICAL",
    confidence=0.97,
    exploitability=None,
    business_impact_category=None,
) -> Vulnerability:
    """Create a test vulnerability for risk scoring."""
    return Vulnerability(
        id=id,
        file_path="app.py",
        line_number=42,
        vuln_type="sql_injection",
        description="User input in SQL query",
        confidence=confidence,
        severity=severity,
        code_snippet='query = f"SELECT * FROM users WHERE id={user_id}"',
        cwe_id="CWE-89",
        exploitability=exploitability,
        business_impact_category=business_impact_category,
    )


# ---------------------------------------------------------------------------
# Risk Score Formula Tests
# ---------------------------------------------------------------------------

class TestRiskScoreFormula:
    def test_risk_score_basic_calculation(self):
        """Risk score must follow formula: (severity × exploitability × confidence × impact) × 100."""
        # CRITICAL (1.0) × 0.9 × 0.97 × 0.6 × 100 = 52.38
        vuln = _make_vuln(
            severity="CRITICAL",
            confidence=0.97,
            exploitability=0.9,
            business_impact_category="data_exposure",
        )
        score = RiskScorer.calculate_risk_score(vuln)
        # Should be around 52.38
        assert 50.0 < score < 55.0

    def test_risk_score_with_customer_data_breach(self):
        """Risk score with customer_data_breach impact (1.0) should be highest."""
        # CRITICAL (1.0) × 0.9 × 0.97 × 1.0 × 100 = 87.3
        vuln = _make_vuln(
            severity="CRITICAL",
            confidence=0.97,
            exploitability=0.9,
            business_impact_category="customer_data_breach",
        )
        score = RiskScorer.calculate_risk_score(vuln)
        assert score > 85.0  # Should be around 87.3

    def test_risk_score_critical_severity(self):
        """CRITICAL severity should use 1.0 weight."""
        vuln = _make_vuln(
            severity="CRITICAL",
            confidence=1.0,
            exploitability=0.5,
            business_impact_category="no_impact",
        )
        score = RiskScorer.calculate_risk_score(vuln)
        # 1.0 × 0.5 × 1.0 × 0.0 × 100 = 0
        assert score == 0.0

    def test_risk_score_high_severity(self):
        """HIGH severity should use 0.75 weight."""
        vuln1 = _make_vuln(
            severity="HIGH",
            confidence=1.0,
            exploitability=0.6,
            business_impact_category="data_exposure",
        )
        vuln2 = _make_vuln(
            severity="CRITICAL",
            confidence=1.0,
            exploitability=0.6,
            business_impact_category="data_exposure",
        )
        score1 = RiskScorer.calculate_risk_score(vuln1)
        score2 = RiskScorer.calculate_risk_score(vuln2)
        # HIGH (0.75) should be less than CRITICAL (1.0)
        assert score1 < score2

    def test_risk_score_medium_severity(self):
        """MEDIUM severity should use 0.5 weight."""
        vuln = _make_vuln(
            severity="MEDIUM",
            confidence=1.0,
            exploitability=0.6,
            business_impact_category="data_exposure",
        )
        score = RiskScorer.calculate_risk_score(vuln)
        # 0.5 × 0.6 × 1.0 × 0.6 × 100 = 18.0
        assert 17.0 < score < 20.0

    def test_risk_score_low_severity(self):
        """LOW severity should use 0.25 weight."""
        vuln = _make_vuln(
            severity="LOW",
            confidence=1.0,
            exploitability=0.6,
            business_impact_category="data_exposure",
        )
        score = RiskScorer.calculate_risk_score(vuln)
        # 0.25 × 0.6 × 1.0 × 0.6 × 100 = 9.0
        assert 8.0 < score < 11.0


# ---------------------------------------------------------------------------
# Risk Score Range Tests
# ---------------------------------------------------------------------------

class TestRiskScoreRange:
    def test_risk_score_minimum_is_zero(self):
        """Minimum risk score should be 0.0."""
        vuln = _make_vuln(
            severity="LOW",
            confidence=0.0,
            business_impact_category="no_impact",
        )
        score = RiskScorer.calculate_risk_score(vuln)
        assert score >= 0.0

    def test_risk_score_maximum_is_one_hundred(self):
        """Maximum risk score should not exceed 100.0."""
        vuln = _make_vuln(
            severity="CRITICAL",
            confidence=1.0,
            exploitability=1.0,
            business_impact_category="customer_data_breach",
        )
        score = RiskScorer.calculate_risk_score(vuln)
        # (1.0 × 1.0 × 1.0 × 1.0) × 100 = 100
        assert score <= 100.0

    def test_risk_score_is_always_in_bounds(self):
        """Risk score should always be between 0 and 100."""
        test_cases = [
            ("CRITICAL", 1.0, "customer_data_breach"),
            ("CRITICAL", 0.0, "customer_data_breach"),
            ("LOW", 1.0, "no_impact"),
            ("LOW", 0.0, "no_impact"),
        ]
        for severity, confidence, impact in test_cases:
            vuln = _make_vuln(
                severity=severity,
                confidence=confidence,
                business_impact_category=impact,
            )
            score = RiskScorer.calculate_risk_score(vuln)
            assert 0.0 <= score <= 100.0


# ---------------------------------------------------------------------------
# Exploitability Impact Tests
# ---------------------------------------------------------------------------

class TestExploitabilityImpactOnRisk:
    def test_high_exploitability_increases_risk(self):
        """Higher exploitability should increase risk score."""
        vuln_easy = _make_vuln(
            severity="CRITICAL",
            confidence=0.97,
            exploitability=0.9,  # Easy to exploit
            business_impact_category="data_exposure",
        )
        vuln_hard = _make_vuln(
            severity="CRITICAL",
            confidence=0.97,
            exploitability=0.2,  # Hard to exploit
            business_impact_category="data_exposure",
        )
        score_easy = RiskScorer.calculate_risk_score(vuln_easy)
        score_hard = RiskScorer.calculate_risk_score(vuln_hard)
        assert score_easy > score_hard

    def test_exploitability_default_inference_critical(self):
        """CRITICAL severity without explicit exploitability should use 0.85."""
        vuln = _make_vuln(
            severity="CRITICAL",
            confidence=1.0,
            exploitability=None,  # Not set
            business_impact_category="data_exposure",
        )
        score = RiskScorer.calculate_risk_score(vuln)
        # 1.0 × 0.85 × 1.0 × 0.6 × 100 = 51.0
        assert 49.0 < score < 53.0

    def test_exploitability_default_inference_high(self):
        """HIGH severity without explicit exploitability should use 0.70."""
        vuln = _make_vuln(
            severity="HIGH",
            confidence=1.0,
            exploitability=None,  # Not set
            business_impact_category="data_exposure",
        )
        score = RiskScorer.calculate_risk_score(vuln)
        # 0.75 × 0.70 × 1.0 × 0.6 × 100 = 31.5
        assert 30.0 < score < 33.0

    def test_exploitability_default_inference_medium_and_low(self):
        """MEDIUM and LOW severity should default to 0.6 exploitability."""
        vuln = _make_vuln(
            severity="MEDIUM",
            confidence=1.0,
            exploitability=None,  # Not set
            business_impact_category="data_exposure",
        )
        score = RiskScorer.calculate_risk_score(vuln)
        # 0.5 × 0.6 × 1.0 × 0.6 × 100 = 18.0
        assert 17.0 < score < 20.0


# ---------------------------------------------------------------------------
# Impact Category Weight Tests
# ---------------------------------------------------------------------------

class TestImpactCategoryWeights:
    def test_customer_data_breach_highest_weight(self):
        """customer_data_breach should have highest weight (1.0)."""
        base_vuln = _make_vuln(
            severity="CRITICAL",
            confidence=1.0,
            exploitability=0.5,
        )
        vuln_breach = _make_vuln(
            severity="CRITICAL",
            confidence=1.0,
            exploitability=0.5,
            business_impact_category="customer_data_breach",
        )
        score_base = RiskScorer.calculate_risk_score(base_vuln)
        score_breach = RiskScorer.calculate_risk_score(vuln_breach)
        assert score_breach > score_base

    def test_compliance_violation_weight(self):
        """compliance_violation should have 0.9 weight."""
        vuln = _make_vuln(
            severity="CRITICAL",
            confidence=1.0,
            exploitability=0.5,
            business_impact_category="compliance_violation",
        )
        score = RiskScorer.calculate_risk_score(vuln)
        # 1.0 × 0.5 × 1.0 × 0.9 × 100 = 45.0
        assert 44.0 < score < 46.0

    def test_financial_loss_weight(self):
        """financial_loss should have 0.8 weight."""
        vuln = _make_vuln(
            severity="CRITICAL",
            confidence=1.0,
            exploitability=0.5,
            business_impact_category="financial_loss",
        )
        score = RiskScorer.calculate_risk_score(vuln)
        # 1.0 × 0.5 × 1.0 × 0.8 × 100 = 40.0
        assert 39.0 < score < 41.0

    def test_service_disruption_weight(self):
        """service_disruption should have 0.7 weight."""
        vuln = _make_vuln(
            severity="CRITICAL",
            confidence=1.0,
            exploitability=0.5,
            business_impact_category="service_disruption",
        )
        score = RiskScorer.calculate_risk_score(vuln)
        # 1.0 × 0.5 × 1.0 × 0.7 × 100 = 35.0
        assert 34.0 < score < 36.0

    def test_data_exposure_weight(self):
        """data_exposure should have 0.6 weight."""
        vuln = _make_vuln(
            severity="CRITICAL",
            confidence=1.0,
            exploitability=0.5,
            business_impact_category="data_exposure",
        )
        score = RiskScorer.calculate_risk_score(vuln)
        # 1.0 × 0.5 × 1.0 × 0.6 × 100 = 30.0
        assert 29.0 < score < 31.0

    def test_no_impact_weight(self):
        """no_impact should have 0.0 weight (zero risk)."""
        vuln = _make_vuln(
            severity="CRITICAL",
            confidence=1.0,
            exploitability=0.9,
            business_impact_category="no_impact",
        )
        score = RiskScorer.calculate_risk_score(vuln)
        assert score == 0.0

    def test_default_impact_is_data_exposure(self):
        """When impact_category not set, should default to data_exposure (0.6)."""
        vuln = _make_vuln(
            severity="CRITICAL",
            confidence=1.0,
            exploitability=0.5,
            business_impact_category=None,  # Not set
        )
        score = RiskScorer.calculate_risk_score(vuln)
        # 1.0 × 0.5 × 1.0 × 0.6 × 100 = 30.0
        assert 29.0 < score < 31.0


# ---------------------------------------------------------------------------
# Vulnerability Ranking Tests
# ---------------------------------------------------------------------------

class TestRankVulnerabilities:
    def test_rank_vulnerabilities_by_risk_descending(self):
        """rank_vulnerabilities must return list sorted by risk score descending."""
        vuln1 = _make_vuln(
            id="SWIFT-001",
            severity="LOW",
            confidence=0.5,
            business_impact_category="no_impact",
        )  # Low risk
        vuln2 = _make_vuln(
            id="SWIFT-002",
            severity="CRITICAL",
            confidence=0.95,
            business_impact_category="customer_data_breach",
        )  # High risk
        vuln3 = _make_vuln(
            id="SWIFT-003",
            severity="MEDIUM",
            confidence=0.8,
            business_impact_category="data_exposure",
        )  # Medium risk

        ranked = RiskScorer.rank_vulnerabilities([vuln1, vuln2, vuln3])

        # Should return tuples of (vulnerability, score)
        assert len(ranked) == 3
        assert all(isinstance(item, tuple) for item in ranked)

        # First should be highest risk (SWIFT-002)
        assert ranked[0][0].id == "SWIFT-002"
        # Last should be lowest risk (SWIFT-001)
        assert ranked[2][0].id == "SWIFT-001"

    def test_rank_vulnerabilities_scores_are_descending(self):
        """Risk scores in ranked list must be in descending order."""
        vuln1 = _make_vuln(
            id="SWIFT-001", severity="CRITICAL", confidence=0.9
        )
        vuln2 = _make_vuln(
            id="SWIFT-002", severity="MEDIUM", confidence=0.9
        )
        vuln3 = _make_vuln(
            id="SWIFT-003", severity="LOW", confidence=0.9
        )

        ranked = RiskScorer.rank_vulnerabilities([vuln1, vuln2, vuln3])
        scores = [score for _, score in ranked]

        # Each score should be >= next score
        for i in range(len(scores) - 1):
            assert scores[i] >= scores[i + 1]

    def test_rank_empty_list(self):
        """rank_vulnerabilities must handle empty list."""
        ranked = RiskScorer.rank_vulnerabilities([])
        assert ranked == []

    def test_rank_single_vulnerability(self):
        """rank_vulnerabilities must handle single vulnerability."""
        vuln = _make_vuln(id="SWIFT-001")
        ranked = RiskScorer.rank_vulnerabilities([vuln])
        assert len(ranked) == 1
        assert ranked[0][0].id == "SWIFT-001"


# ---------------------------------------------------------------------------
# Impact Category Inference Tests
# ---------------------------------------------------------------------------

class TestImpactCategoryInference:
    def test_get_impact_category_returns_set_value(self):
        """If business_impact_category is set, should return it."""
        vuln = _make_vuln(
            business_impact_category="customer_data_breach"
        )
        impact = RiskScorer.get_impact_category(vuln)
        assert impact == "customer_data_breach"

    def test_infer_customer_data_breach_from_auth_bypass(self):
        """SQL injection and auth bypass should infer customer_data_breach."""
        vuln = Vulnerability(
            id="SWIFT-001",
            file_path="auth.py",
            line_number=42,
            vuln_type="sql_injection",
            description="Password field vulnerable to injection",
            confidence=0.97,
            severity="CRITICAL",
            code_snippet="",
        )
        impact = RiskScorer.get_impact_category(vuln)
        assert impact == "customer_data_breach"

    def test_infer_compliance_violation_from_privilege_escalation(self):
        """Privilege escalation should infer compliance_violation."""
        vuln = Vulnerability(
            id="SWIFT-001",
            file_path="admin.py",
            line_number=42,
            vuln_type="privilege_escalation",
            description="Admin access without proper checks",
            confidence=0.97,
            severity="CRITICAL",
            code_snippet="",
        )
        impact = RiskScorer.get_impact_category(vuln)
        assert impact == "compliance_violation"

    def test_infer_data_exposure_from_xxe(self):
        """XXE vulnerability should infer data_exposure."""
        vuln = Vulnerability(
            id="SWIFT-001",
            file_path="parser.py",
            line_number=42,
            vuln_type="xxe",
            description="XML parser processes external entities",
            confidence=0.97,
            severity="HIGH",
            code_snippet="",
        )
        impact = RiskScorer.get_impact_category(vuln)
        assert impact == "data_exposure"

    def test_infer_service_disruption_from_dos(self):
        """DoS vulnerability should infer service_disruption."""
        vuln = Vulnerability(
            id="SWIFT-001",
            file_path="api.py",
            line_number=42,
            vuln_type="dos",
            description="Unbounded resource allocation",
            confidence=0.97,
            severity="HIGH",
            code_snippet="",
        )
        impact = RiskScorer.get_impact_category(vuln)
        assert impact == "service_disruption"


# ---------------------------------------------------------------------------
# Exploitability Inference Tests
# ---------------------------------------------------------------------------

class TestExploitabilityInference:
    def test_get_exploitability_returns_set_value(self):
        """If exploitability is set, should return it."""
        vuln = _make_vuln(exploitability=0.75)
        score = RiskScorer.get_exploitability_score(vuln)
        assert score == 0.75

    def test_xss_trivial_exploitability(self):
        """XSS should have trivial exploitability (0.9)."""
        vuln = Vulnerability(
            id="SWIFT-001",
            file_path="template.html",
            line_number=10,
            vuln_type="xss",
            description="Unescaped user input in template",
            confidence=0.97,
            severity="HIGH",
            code_snippet="",
        )
        score = RiskScorer.get_exploitability_score(vuln)
        assert score == 0.9

    def test_sql_injection_moderate_exploitability(self):
        """SQL injection should have moderate exploitability (0.6)."""
        vuln = Vulnerability(
            id="SWIFT-001",
            file_path="app.py",
            line_number=42,
            vuln_type="sql_injection",
            description="User input in query",
            confidence=0.97,
            severity="CRITICAL",
            code_snippet="",
        )
        score = RiskScorer.get_exploitability_score(vuln)
        assert score == 0.6

    def test_privilege_escalation_specific_exploitability(self):
        """Privilege escalation should have specific exploitability (0.4)."""
        vuln = Vulnerability(
            id="SWIFT-001",
            file_path="auth.py",
            line_number=42,
            vuln_type="privilege_escalation",
            description="Can escalate to admin",
            confidence=0.97,
            severity="CRITICAL",
            code_snippet="",
        )
        score = RiskScorer.get_exploitability_score(vuln)
        assert score == 0.4

    def test_race_condition_complex_exploitability(self):
        """Race condition should have complex exploitability (0.2)."""
        vuln = Vulnerability(
            id="SWIFT-001",
            file_path="transaction.py",
            line_number=42,
            vuln_type="race_condition",
            description="TOCTOU vulnerability",
            confidence=0.97,
            severity="HIGH",
            code_snippet="",
        )
        score = RiskScorer.get_exploitability_score(vuln)
        assert score == 0.2

    def test_unknown_type_defaults_to_moderate(self):
        """Unknown vulnerability type should default to moderate (0.6)."""
        vuln = Vulnerability(
            id="SWIFT-001",
            file_path="unknown.py",
            line_number=42,
            vuln_type="unknown_type",
            description="Some unknown finding",
            confidence=0.97,
            severity="MEDIUM",
            code_snippet="",
        )
        score = RiskScorer.get_exploitability_score(vuln)
        assert score == 0.6
