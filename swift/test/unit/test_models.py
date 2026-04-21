import dataclasses
import pytest
from agent.models import Vulnerability, Patch, ScanResult, TestResult


def test_vulnerability_creation():
    v = Vulnerability(
        id="SWIFT-001",
        file_path="app.py",
        line_number=10,
        vuln_type="sql_injection",
        description="SQL injection via f-string",
        confidence=0.97,
        severity="CRITICAL",
        code_snippet="query = f'SELECT * FROM users WHERE id={user_id}'",
    )
    assert v.id == "SWIFT-001"
    assert v.line_number == 10


def test_vulnerability_serializable():
    v = Vulnerability(
        id="SWIFT-001",
        file_path="app.py",
        line_number=10,
        vuln_type="sql_injection",
        description="SQL injection",
        confidence=0.97,
        severity="CRITICAL",
        code_snippet="query = f'SELECT * FROM users'",
    )
    d = dataclasses.asdict(v)
    assert d["id"] == "SWIFT-001"
    assert isinstance(d, dict)


def test_patch_creation():
    p = Patch(
        id="PATCH-001",
        vuln_id="SWIFT-001",
        file_path="app.py",
        original_code="query = f'SELECT * FROM users WHERE id={user_id}'",
        patched_code="query = 'SELECT * FROM users WHERE id=?'",
        diff="--- a/app.py\n+++ b/app.py",
        confidence=0.95,
    )
    assert p.id == "PATCH-001"
    assert p.vuln_id == "SWIFT-001"


def test_scan_result_creation():
    sr = ScanResult(
        scan_id="SCAN-abc123",
        repo_path="/tmp/repo",
        files_scanned=5,
        vulnerabilities=[],
        patches=[],
        duration_seconds=1.5,
        total_cost_usd=0.05,
        timestamp="2026-04-18T00:00:00",
    )
    assert sr.scan_id == "SCAN-abc123"
    assert sr.files_scanned == 5


def test_confidence_stored_as_float():
    v = Vulnerability(
        id="SWIFT-001",
        file_path="app.py",
        line_number=10,
        vuln_type="sql_injection",
        description="SQL injection",
        confidence=0.97,
        severity="CRITICAL",
        code_snippet="...",
    )
    assert isinstance(v.confidence, float)
    assert v.confidence == 0.97  # NOT 97


def test_test_result_summary_passed():
    tr = TestResult(patch_id="PATCH-001", passed=True, output="All tests passed", exit_code=0)
    assert tr.summary == "PASSED"


def test_test_result_summary_failed():
    tr = TestResult(patch_id="PATCH-001", passed=False, output="AssertionError", exit_code=1)
    assert tr.summary == "FAILED"


def test_vulnerability_with_evidence_fields():
    """Test Vulnerability with all evidence bundle fields."""
    v = Vulnerability(
        id="SWIFT-001",
        file_path="app.py",
        line_number=42,
        vuln_type="sql_injection",
        description="SQL injection via f-string",
        confidence=0.97,
        severity="CRITICAL",
        code_snippet="query = f'SELECT * FROM users WHERE id={user_id}'",
        cwe_id="CWE-89",
        cwe_url="https://cwe.mitre.org/data/definitions/89.html",
        owasp_category="A03:2021 – Injection",
        exploit_description="Attacker injects malicious SQL code via user_id parameter",
        exploit_impact="Full database compromise and unauthorized data access",
        remediation="Use parameterized queries or prepared statements",
        remediation_code="query = 'SELECT * FROM users WHERE id=?' # Use parameterized query",
        remediation_effort="LOW",
        remediation_time_minutes=15,
        affected_code={
            "before": "query = f'SELECT * FROM users WHERE id={user_id}'",
            "after": "query = 'SELECT * FROM users WHERE id=?'"
        },
        references=[
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        ]
    )

    # Verify all core fields
    assert v.id == "SWIFT-001"
    assert v.file_path == "app.py"
    assert v.line_number == 42
    assert v.vuln_type == "sql_injection"
    assert v.description == "SQL injection via f-string"
    assert v.confidence == 0.97
    assert v.severity == "CRITICAL"
    assert v.code_snippet == "query = f'SELECT * FROM users WHERE id={user_id}'"

    # Verify all evidence bundle fields
    assert v.cwe_id == "CWE-89"
    assert v.cwe_url == "https://cwe.mitre.org/data/definitions/89.html"
    assert v.owasp_category == "A03:2021 – Injection"
    assert v.exploit_description == "Attacker injects malicious SQL code via user_id parameter"
    assert v.exploit_impact == "Full database compromise and unauthorized data access"
    assert v.remediation == "Use parameterized queries or prepared statements"
    assert v.remediation_code == "query = 'SELECT * FROM users WHERE id=?' # Use parameterized query"
    assert v.remediation_effort == "LOW"
    assert v.remediation_time_minutes == 15
    assert v.affected_code == {
        "before": "query = f'SELECT * FROM users WHERE id={user_id}'",
        "after": "query = 'SELECT * FROM users WHERE id=?'"
    }
    assert len(v.references) == 2
    assert "https://owasp.org/www-community/attacks/SQL_Injection" in v.references


def test_vulnerability_evidence_fields_optional():
    """Test that evidence bundle fields are optional and default to None."""
    v = Vulnerability(
        id="SWIFT-002",
        file_path="utils.py",
        line_number=5,
        vuln_type="hardcoded_secret",
        description="Hardcoded API key",
        confidence=0.95,
        severity="HIGH",
        code_snippet="api_key = 'sk_live_12345678'"
    )

    # Core fields must be present
    assert v.id == "SWIFT-002"
    assert v.vuln_type == "hardcoded_secret"

    # Evidence fields should be None or empty
    assert v.cwe_id is None
    assert v.cwe_url is None
    assert v.owasp_category is None
    assert v.exploit_description is None
    assert v.exploit_impact is None
    assert v.remediation is None
    assert v.remediation_code is None
    assert v.remediation_effort is None
    assert v.remediation_time_minutes is None
    assert v.affected_code is None
    assert v.references == []


def test_vulnerability_affected_code_dict():
    """Test affected_code dict with before/after keys."""
    v = Vulnerability(
        id="SWIFT-003",
        file_path="handler.py",
        line_number=20,
        vuln_type="command_injection",
        description="Command injection in subprocess call",
        confidence=0.92,
        severity="HIGH",
        code_snippet="subprocess.run(f'echo {user_input}', shell=True)",
        affected_code={
            "before": "subprocess.run(f'echo {user_input}', shell=True)",
            "after": "subprocess.run(['echo', user_input])"
        }
    )

    assert isinstance(v.affected_code, dict)
    assert "before" in v.affected_code
    assert "after" in v.affected_code
    assert v.affected_code["before"] == "subprocess.run(f'echo {user_input}', shell=True)"
    assert v.affected_code["after"] == "subprocess.run(['echo', user_input])"


def test_vulnerability_remediation_effort_levels():
    """Test remediation_effort with valid levels."""
    effort_levels = ["LOW", "MEDIUM", "HIGH"]

    for effort in effort_levels:
        v = Vulnerability(
            id=f"SWIFT-EFF-{effort}",
            file_path="test.py",
            line_number=1,
            vuln_type="test",
            description="test",
            confidence=0.9,
            severity="MEDIUM",
            code_snippet="test",
            remediation_effort=effort
        )
        assert v.remediation_effort == effort


def test_vulnerability_references_list():
    """Test references list with multiple URLs."""
    refs = [
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        "https://cwe.mitre.org/data/definitions/89.html"
    ]

    v = Vulnerability(
        id="SWIFT-005",
        file_path="db.py",
        line_number=100,
        vuln_type="sql_injection",
        description="SQL injection in query builder",
        confidence=0.98,
        severity="CRITICAL",
        code_snippet="...",
        references=refs
    )

    assert len(v.references) == 3
    assert v.references == refs
    for ref in refs:
        assert ref in v.references


def test_vulnerability_with_evidence_serializable():
    """Test that Vulnerability with evidence fields can be serialized."""
    v = Vulnerability(
        id="SWIFT-006",
        file_path="api.py",
        line_number=50,
        vuln_type="path_traversal",
        description="Path traversal vulnerability",
        confidence=0.91,
        severity="HIGH",
        code_snippet="open(f'/var/www/{user_path}')",
        cwe_id="CWE-22",
        cwe_url="https://cwe.mitre.org/data/definitions/22.html",
        owasp_category="A01:2021 – Broken Access Control",
        exploit_description="Attacker uses ../ to access sensitive files",
        exploit_impact="Unauthorized file access and disclosure",
        remediation="Validate and sanitize file paths",
        remediation_code="os.path.abspath(user_path).startswith(base_dir)",
        remediation_effort="MEDIUM",
        remediation_time_minutes=30,
        affected_code={"before": "open(f'/var/www/{user_path}')", "after": "validated_path = sanitize(user_path)"},
        references=["https://owasp.org/www-community/attacks/Path_Traversal"]
    )

    d = dataclasses.asdict(v)
    assert isinstance(d, dict)
    assert d["id"] == "SWIFT-006"
    assert d["cwe_id"] == "CWE-22"
    assert d["owasp_category"] == "A01:2021 – Broken Access Control"
    assert d["remediation_effort"] == "MEDIUM"
    assert d["remediation_time_minutes"] == 30
    assert isinstance(d["affected_code"], dict)
    assert isinstance(d["references"], list)
