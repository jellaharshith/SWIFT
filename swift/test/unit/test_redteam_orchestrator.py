"""Unit tests for red-team orchestration helpers."""
from __future__ import annotations

from argparse import Namespace

import pytest

from agent.redteam_orchestrator import (
    browser_findings_to_vulnerabilities,
    browser_kind_to_vuln_type,
    effective_phases,
    kali_rows_to_vulnerabilities,
    parse_phases,
    phases_need_network_target,
)


def test_parse_phases() -> None:
    assert parse_phases("osint, active ,chain") == {"osint", "active", "chain"}


def test_phases_need_network_target() -> None:
    assert phases_need_network_target({"osint"}) is True
    assert phases_need_network_target({"chain", "code"}) is False


def test_effective_phases_injects_code_when_chain_and_repo() -> None:
    args = Namespace(phases="chain", repo="/tmp/repo")
    assert "code" in effective_phases(args)
    args2 = Namespace(phases="code,chain", repo="/tmp/repo")
    assert effective_phases(args2) == {"code", "chain"}


@pytest.mark.parametrize(
    "kind,expected",
    [
        ("xss_reflected", "xss"),
        ("sql_error", "sql_injection"),
        ("idor_enum", "insecure_direct_object"),
        ("ssrf_probe", "ssrf"),
        ("unknown_signal", "information_disclosure"),
    ],
)
def test_browser_kind_to_vuln_type(kind: str, expected: str) -> None:
    assert browser_kind_to_vuln_type(kind) == expected


def test_kali_rows_to_vulnerabilities() -> None:
    rows = [
        {"tool": "sqlmap", "target": "http://x/", "output": "sqlmap found injection"},
        {"tool": "nmap", "target": "http://x/", "output": "80/tcp open"},
    ]
    vulns = kali_rows_to_vulnerabilities(rows)
    assert len(vulns) == 2
    assert vulns[0].vuln_type == "sql_injection"
    assert vulns[0].id.startswith("KALI-SQLMAP-")


def test_browser_findings_to_vulnerabilities() -> None:
    from browser.playwright_runner import BrowserFinding

    findings = [
        BrowserFinding(
            kind="xss_reflected",
            severity="high",
            url="https://example.com/?q=1",
            evidence="reflected",
            payload="<script>",
        ),
    ]
    vulns = browser_findings_to_vulnerabilities(findings, "https://example.com/")
    assert len(vulns) == 1
    assert vulns[0].vuln_type == "xss"
    assert vulns[0].id == "WEB-001"
