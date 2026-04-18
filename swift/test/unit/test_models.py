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
