"""Unit tests for the agent orchestrator — all external calls mocked."""
from __future__ import annotations

import json
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from agent.models import ScanResult, Vulnerability


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_vuln(confidence: float = 0.97) -> Vulnerability:
    return Vulnerability(
        id="SWIFT-001",
        file_path="/tmp/repo/app.py",
        line_number=10,
        vuln_type="sql_injection",
        description="SQL injection",
        confidence=confidence,
        severity="CRITICAL",
        code_snippet="query = f'SELECT * FROM users WHERE id={uid}'",
    )


def _mock_triage(flagged: dict):
    """Return a patch target for triage_codebase."""
    return patch("agent.orchestrator.triage_codebase", return_value=flagged)


def _mock_haiku(lines: set):
    scanner = MagicMock()
    scanner.scan_lines.return_value = lines
    return patch("agent.orchestrator.HaikuTriageScanner", return_value=scanner), scanner


def _mock_sonnet(vuln=None):
    scanner = MagicMock()
    scanner.analyze_line.return_value = vuln
    return patch("agent.orchestrator.SonnetAnalysisScanner", return_value=scanner), scanner


# ---------------------------------------------------------------------------
# Tests — no ANTHROPIC_API_KEY required
# ---------------------------------------------------------------------------

class TestScanCodebase:
    def test_scan_returns_scan_result(self, tmp_path):
        with _mock_triage({}):
            from agent.orchestrator import scan_codebase
            result = scan_codebase(str(tmp_path))
        assert isinstance(result, ScanResult)

    def test_scan_calls_triage(self, tmp_path):
        with patch("agent.orchestrator.triage_codebase", return_value={}) as mock_triage:
            from agent.orchestrator import scan_codebase
            scan_codebase(str(tmp_path))
        mock_triage.assert_called_once_with(str(tmp_path))

    def test_scan_files_scanned_count(self, tmp_path):
        flagged = {
            str(tmp_path / "a.py"): [1],
            str(tmp_path / "b.py"): [2],
        }
        with _mock_triage(flagged):
            haiku_patch, haiku_mock = _mock_haiku(set())
            with haiku_patch:
                from agent.orchestrator import scan_codebase
                result = scan_codebase(str(tmp_path))
        assert result.files_scanned == 2

    def test_scan_empty_repo_returns_empty(self, tmp_path):
        with _mock_triage({}):
            from agent.orchestrator import scan_codebase
            result = scan_codebase(str(tmp_path))
        assert result.vulnerabilities == []

    def test_scan_duration_tracked(self, tmp_path):
        with _mock_triage({}):
            from agent.orchestrator import scan_codebase
            result = scan_codebase(str(tmp_path))
        assert result.duration_seconds >= 0.0

    def test_scan_no_haiku_signals_gives_empty_result(self, tmp_path):
        file_path = str(tmp_path / "app.py")
        with open(file_path, "w") as f:
            f.write("query = f'SELECT * FROM users WHERE id={uid}'\n")

        flagged = {file_path: [1]}
        with _mock_triage(flagged):
            haiku_patch, haiku_mock = _mock_haiku(set())
            with haiku_patch:
                from agent.orchestrator import scan_codebase
                result = scan_codebase(str(tmp_path))
        assert len(result.vulnerabilities) == 0

    def test_scan_calls_haiku_on_flagged_files(self, tmp_path):
        file_path = str(tmp_path / "app.py")
        with open(file_path, "w") as f:
            f.write("os.system(cmd)\n")

        flagged = {file_path: [1]}
        with _mock_triage(flagged):
            haiku_patch, haiku_mock = _mock_haiku(set())
            with haiku_patch:
                from agent.orchestrator import scan_codebase
                scan_codebase(str(tmp_path))
        haiku_mock.scan_lines.assert_called()

    def test_scan_haiku_signals_create_findings(self, tmp_path):
        """Semgrep/triage signals → SIGNAL-* REVIEW_REQUIRED findings."""
        file_path = str(tmp_path / "app.py")
        with open(file_path, "w") as f:
            f.write("os.system(cmd)\n")

        flagged = {file_path: [1]}
        with _mock_triage(flagged):
            haiku_patch, haiku_mock = _mock_haiku({1})
            with haiku_patch:
                from agent.orchestrator import scan_codebase
                result = scan_codebase(str(tmp_path))
        assert len(result.vulnerabilities) == 1
        vuln = result.vulnerabilities[0]
        assert vuln.id.startswith("SIGNAL-")
        assert vuln.status == "REVIEW_REQUIRED"
        assert vuln.confidence == 0.7

    def test_scan_timestamp_is_iso(self, tmp_path):
        with _mock_triage({}):
            from agent.orchestrator import scan_codebase
            result = scan_codebase(str(tmp_path))
        datetime.fromisoformat(result.timestamp.replace("Z", "+00:00"))

    def test_scan_id_format(self, tmp_path):
        with _mock_triage({}):
            from agent.orchestrator import scan_codebase
            result = scan_codebase(str(tmp_path))
        assert result.scan_id.startswith("SCAN-")
