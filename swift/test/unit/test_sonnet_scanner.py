"""Tests for SonnetAnalysisScanner — semgrep-backed, no Claude API."""
import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from scanners.sonnet_scanner import SonnetAnalysisScanner
from agent.models import Vulnerability


def _semgrep_result(line: int, rule_id: str = "python.lang.security.sql-injection",
                    severity: str = "ERROR", cwe: str = "CWE-89") -> str:
    return json.dumps({
        "results": [{
            "check_id": rule_id,
            "path": "app.py",
            "start": {"line": line, "col": 1},
            "end": {"line": line, "col": 20},
            "extra": {
                "severity": severity,
                "message": "SQL injection detected",
                "metadata": {
                    "cwe": [cwe],
                    "owasp": "A03:2021 – Injection",
                    "references": ["https://owasp.org/Top10/A03_2021-Injection/"],
                },
            },
        }],
        "errors": [],
    })


def _mock_run(stdout: str, returncode: int = 1):
    m = MagicMock()
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = ""
    return m


# ------------------------------------------------------------------

def test_analyze_line_returns_vulnerability_from_semgrep():
    scanner = SonnetAnalysisScanner()
    with patch("subprocess.run", return_value=_mock_run(_semgrep_result(5))):
        vuln = scanner.analyze_line("app.py", 5, "x = query(uid)\n")
    assert vuln is not None
    assert isinstance(vuln, Vulnerability)
    assert vuln.file_path == "app.py"
    assert vuln.line_number == 5


def test_analyze_line_sets_owasp_category():
    scanner = SonnetAnalysisScanner()
    with patch("subprocess.run", return_value=_mock_run(_semgrep_result(3))):
        vuln = scanner.analyze_line("app.py", 3, "code\n")
    assert vuln.owasp_category == "A03:2021 – Injection"


def test_analyze_line_maps_cwe():
    scanner = SonnetAnalysisScanner()
    with patch("subprocess.run", return_value=_mock_run(_semgrep_result(1))):
        vuln = scanner.analyze_line("app.py", 1, "code\n")
    assert vuln.cwe_id == "CWE-89"
    assert "89" in (vuln.cwe_url or "")


def test_analyze_line_severity_mapping():
    scanner = SonnetAnalysisScanner()
    with patch("subprocess.run", return_value=_mock_run(_semgrep_result(1, severity="ERROR"))):
        vuln = scanner.analyze_line("app.py", 1, "code\n")
    assert vuln.severity == "HIGH"


def test_analyze_line_no_semgrep_returns_signal():
    scanner = SonnetAnalysisScanner()
    with patch("subprocess.run", side_effect=FileNotFoundError):
        vuln = scanner.analyze_line("app.py", 7, "code\n")
    assert vuln is not None
    assert vuln.status == "REVIEW_REQUIRED"
    assert vuln.vuln_type == "signal_requires_review"


def test_analyze_line_unmatched_line_returns_signal():
    scanner = SonnetAnalysisScanner()
    with patch("subprocess.run", return_value=_mock_run(_semgrep_result(10))):
        vuln = scanner.analyze_line("app.py", 99, "code\n")
    assert vuln.vuln_type == "signal_requires_review"


def test_results_cached_per_file():
    scanner = SonnetAnalysisScanner()
    mock_run = MagicMock(return_value=_mock_run(_semgrep_result(1)))
    with patch("subprocess.run", mock_run):
        scanner.analyze_line("app.py", 1, "code\n")
        scanner.analyze_line("app.py", 1, "code\n")
    assert mock_run.call_count == 1


def test_client_kwarg_ignored():
    fake_client = MagicMock()
    scanner = SonnetAnalysisScanner(client=fake_client)
    with patch("subprocess.run", return_value=_mock_run(_semgrep_result(1))):
        scanner.analyze_line("app.py", 1, "code\n")
    fake_client.messages.create.assert_not_called()
