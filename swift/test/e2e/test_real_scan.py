"""E2E tests — require real Anthropic API key and SWIFT_RUN_E2E=1.

Run with:
    SWIFT_RUN_E2E=1 pytest test/e2e/ -v
"""
from __future__ import annotations

import json
import os

import pytest

E2E_REPO = os.path.join(os.path.dirname(__file__), "test_repo")

pytestmark = pytest.mark.skipif(
    os.environ.get("SWIFT_RUN_E2E") != "1",
    reason="Set SWIFT_RUN_E2E=1 to run end-to-end tests (requires real API key)",
)


@pytest.fixture(scope="module")
def scan_result():
    """Run real scan once and share result across E2E tests."""
    from agent.orchestrator import scan_codebase
    return scan_codebase(E2E_REPO)


def test_e2e_scan_returns_result(scan_result):
    """Scan must complete and return a ScanResult."""
    from agent.models import ScanResult
    assert isinstance(scan_result, ScanResult)


def test_e2e_finds_vulnerabilities(scan_result):
    """SWIFT must find at least 1 vulnerability in the intentionally vulnerable repo."""
    assert len(scan_result.vulnerabilities) >= 1, (
        f"Expected >=1 vulns, got {len(scan_result.vulnerabilities)}"
    )


def test_e2e_all_confidence_above_95(scan_result):
    """ALL reported vulnerabilities must have confidence >= 0.95 (95% gate)."""
    for vuln in scan_result.vulnerabilities:
        assert vuln.confidence >= 0.95, (
            f"Vuln {vuln.id} has confidence {vuln.confidence} < 0.95"
        )


def test_e2e_scan_id_format(scan_result):
    """scan_id must start with 'SCAN-'."""
    assert scan_result.scan_id.startswith("SCAN-")


def test_e2e_json_output_valid(scan_result):
    """JSON formatter must produce valid JSON from real scan result."""
    from output.formatters import format_output
    raw = format_output(scan_result, "json")
    data = json.loads(raw)  # raises if invalid
    assert data["summary"]["vulnerabilities_found"] == len(scan_result.vulnerabilities)


def test_e2e_markdown_output_has_header(scan_result):
    """Markdown output must include the standard SWIFT header."""
    from output.formatters import format_output
    md = format_output(scan_result, "markdown")
    assert "# SWIFT Vulnerability Report" in md


def test_e2e_redteam_stub(scan_result):
    """Redteam pipeline E2E requires live target + ROE — run manually."""
    pytest.skip("Redteam E2E requires authorized target and roe.yaml")
