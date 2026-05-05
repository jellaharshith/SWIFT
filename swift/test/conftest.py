"""Shared pytest fixtures for all SWIFT test layers."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

import config.settings as _settings
from agent.models import AttackStep, ExploitChain, ScanResult, TestResult, Vulnerability


# ---------------------------------------------------------------------------
# Config isolation
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_config_cache():
    """Reset module-level config cache before/after every test."""
    _settings._config = None
    yield
    _settings._config = None


# ---------------------------------------------------------------------------
# Model fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_vulnerability() -> Vulnerability:
    return Vulnerability(
        id="SWIFT-001",
        file_path="app.py",
        line_number=12,
        vuln_type="sql_injection",
        description="User input concatenated directly into SQL query",
        confidence=0.97,
        severity="CRITICAL",
        code_snippet='query = f"SELECT * FROM users WHERE id={user_id}"',
    )


@pytest.fixture()
def low_confidence_vulnerability() -> Vulnerability:
    return Vulnerability(
        id="SWIFT-999",
        file_path="app.py",
        line_number=5,
        vuln_type="sql_injection",
        description="Possible SQL injection",
        confidence=0.80,
        severity="HIGH",
        code_snippet='query = "SELECT * FROM users WHERE id=" + str(user_id)',
    )


@pytest.fixture()
def sample_scan_result(
    sample_vulnerability: Vulnerability,
) -> ScanResult:
    return ScanResult(
        scan_id="scan-abc12345",
        repo_path="/tmp/test-repo",
        files_scanned=3,
        vulnerabilities=[sample_vulnerability],
        duration_seconds=1.5,
        total_cost_usd=0.12,
        timestamp="2026-04-19T10:00:00+00:00",
    )


@pytest.fixture()
def empty_scan_result() -> ScanResult:
    return ScanResult(
        scan_id="scan-empty",
        repo_path="/tmp/empty-repo",
        files_scanned=0,
        vulnerabilities=[],
        duration_seconds=0.1,
        total_cost_usd=0.0,
        timestamp="2026-04-19T10:00:00+00:00",
    )


@pytest.fixture()
def sample_exploit_chain() -> ExploitChain:
    return ExploitChain(
        chain_id="CHAIN-001",
        name="SQL Injection → Auth Bypass → Admin Access",
        vulnerability_ids=["SWIFT-001", "SWIFT-003"],
        attack_path="1. Exploit SQL injection in login query\n2. Bypass authentication\n3. Gain admin access",
        entry_point="auth/views.py:42",
        impact="Complete system compromise",
        severity="CRITICAL",
        confidence=0.91,
        attack_steps=[
            AttackStep(
                step=1,
                description="Exploit SQL injection in login query",
                vuln_id="SWIFT-001",
                entry_point="auth/views.py:42",
            ),
            AttackStep(
                step=2,
                description="Bypass authentication and access admin panel",
                vuln_id="SWIFT-003",
                entry_point="admin/views.py:15",
            ),
        ],
    )


@pytest.fixture()
def sample_scan_result_with_chains(
    sample_vulnerability: Vulnerability,
    sample_exploit_chain: ExploitChain,
) -> ScanResult:
    return ScanResult(
        scan_id="scan-abc12345",
        repo_path="/tmp/test-repo",
        files_scanned=3,
        vulnerabilities=[sample_vulnerability],
        duration_seconds=1.5,
        total_cost_usd=0.12,
        timestamp="2026-04-19T10:00:00+00:00",
        exploit_chains=[sample_exploit_chain],
    )


# ---------------------------------------------------------------------------
# Mock Anthropic client
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_anthropic_client() -> MagicMock:
    """Anthropic client that never hits the real API."""
    client = MagicMock()
    msg = MagicMock()
    msg.content = [MagicMock(text="")]
    client.messages.create.return_value = msg
    return client


@pytest.fixture()
def mock_haiku_response(mock_anthropic_client: MagicMock) -> MagicMock:
    """Haiku client returning line 12 as suspicious."""
    mock_anthropic_client.messages.create.return_value.content[0].text = "12"
    return mock_anthropic_client


@pytest.fixture()
def mock_sonnet_vuln_response(mock_anthropic_client: MagicMock) -> MagicMock:
    """Sonnet client returning a high-confidence SQL injection finding."""
    import json

    mock_anthropic_client.messages.create.return_value.content[0].text = json.dumps(
        {
            "confidence": 0.97,
            "vuln_type": "sql_injection",
            "description": "User input concatenated into SQL query",
            "severity": "critical",
            "code_snippet": 'query = f"SELECT * FROM users WHERE id={user_id}"',
        }
    )
    return mock_anthropic_client


