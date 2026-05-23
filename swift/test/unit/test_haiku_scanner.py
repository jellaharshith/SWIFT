"""Tests for SemgrepTriageScanner (replaces Claude Haiku)."""
import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from scanners.haiku_scanner import HaikuTriageScanner


def _make_semgrep_output(lines: list[int]) -> str:
    results = [
        {
            "check_id": "python.lang.security.audit.test",
            "path": "app.py",
            "start": {"line": ln, "col": 1},
            "end": {"line": ln, "col": 10},
            "extra": {"severity": "WARNING", "message": "test finding"},
        }
        for ln in lines
    ]
    return json.dumps({"results": results, "errors": []})


def _mock_run(stdout: str, returncode: int = 1):
    mock = MagicMock()
    mock.returncode = returncode
    mock.stdout = stdout
    mock.stderr = ""
    return mock


# Semgrep finds lines → those lines returned (unioned with flagged)
def test_semgrep_lines_returned():
    scanner = HaikuTriageScanner()
    with patch("subprocess.run", return_value=_mock_run(_make_semgrep_output([5, 10]))):
        result = scanner.scan_lines("app.py", "code", {5, 10})
    assert 5 in result
    assert 10 in result


# Semgrep finds nothing → regex-flagged lines kept as fallback
def test_empty_semgrep_falls_back_to_flagged():
    scanner = HaikuTriageScanner()
    with patch("subprocess.run", return_value=_mock_run(_make_semgrep_output([]))):
        result = scanner.scan_lines("app.py", "code", {3, 7})
    assert 3 in result
    assert 7 in result


# semgrep finds extra lines → union with flagged
def test_semgrep_union_with_flagged():
    scanner = HaikuTriageScanner()
    with patch("subprocess.run", return_value=_mock_run(_make_semgrep_output([99]))):
        result = scanner.scan_lines("app.py", "code", {1})
    assert 1 in result
    assert 99 in result


# semgrep not installed → fallback to flagged lines gracefully
def test_semgrep_not_installed_fallback():
    scanner = HaikuTriageScanner()
    with patch("subprocess.run", side_effect=FileNotFoundError("semgrep not found")):
        result = scanner.scan_lines("app.py", "code", {42})
    assert 42 in result


# semgrep timeout → fallback to flagged lines
def test_semgrep_timeout_fallback():
    scanner = HaikuTriageScanner()
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("semgrep", 30)):
        result = scanner.scan_lines("app.py", "code", {7})
    assert 7 in result


# Results are cached per file_path
def test_results_cached():
    scanner = HaikuTriageScanner()
    mock_run = MagicMock(return_value=_mock_run(_make_semgrep_output([3])))
    with patch("subprocess.run", mock_run):
        scanner.scan_lines("app.py", "code", set())
        scanner.scan_lines("app.py", "code", set())
    assert mock_run.call_count == 1


# Client kwarg ignored (backward compat)
def test_client_kwarg_ignored():
    fake_client = MagicMock()
    scanner = HaikuTriageScanner(client=fake_client)
    with patch("subprocess.run", return_value=_mock_run(_make_semgrep_output([1]))):
        result = scanner.scan_lines("app.py", "code", set())
    fake_client.messages.create.assert_not_called()
    assert 1 in result
