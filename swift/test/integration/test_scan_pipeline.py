"""Integration tests: full pipeline wired end-to-end with mocked Anthropic API."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from agent.models import ScanResult, Vulnerability


def _make_vuln(confidence: float = 0.97) -> Vulnerability:
    return Vulnerability(
        id="SWIFT-001", file_path="/tmp/repo/app.py", line_number=1,
        vuln_type="sql_injection", description="SQL injection",
        confidence=confidence, severity="CRITICAL",
        code_snippet='query = f"SELECT * FROM users WHERE id={uid}"',
    )


class TestFullPipelineWithMockApi:
    """Wire triage → haiku → sonnet together using mocks, no real API calls."""

    def test_full_pipeline_with_mock_api(self, tmp_path, monkeypatch):
        """Full pipeline must return a ScanResult with 1 SIGNAL-* REVIEW_REQUIRED finding.

        In MVP mode the orchestrator converts Haiku signals directly to findings
        without calling Sonnet deep-analysis. One Haiku-flagged line → one SIGNAL-*
        vulnerability with confidence 0.7 and status REVIEW_REQUIRED.
        """
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")

        app_py = tmp_path / "app.py"
        app_py.write_text('query = f"SELECT * FROM users WHERE id={uid}"\n')

        haiku_mock = MagicMock()
        haiku_mock.scan_lines.return_value = {1}

        with patch("agent.orchestrator.triage_codebase", return_value={str(app_py): [1]}):
            with patch("agent.orchestrator.HaikuTriageScanner", return_value=haiku_mock):
                with patch("agent.orchestrator.anthropic.Anthropic"):
                    from agent.orchestrator import scan_codebase
                    result = scan_codebase(str(tmp_path))

        assert isinstance(result, ScanResult)
        assert len(result.vulnerabilities) == 1
        vuln = result.vulnerabilities[0]
        assert vuln.id.startswith("SIGNAL-")
        assert vuln.status == "REVIEW_REQUIRED"
        assert vuln.confidence == 0.7

    def test_no_haiku_signals_gives_empty_result(self, tmp_path, monkeypatch):
        """When Haiku finds no suspicious lines the result must have 0 vulnerabilities.

        In MVP mode the pipeline is: triage → Haiku → SIGNAL-* findings.
        Sonnet deep-analysis is disabled. Zero Haiku signals → zero findings.
        """
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")

        app_py = tmp_path / "app.py"
        app_py.write_text('query = f"SELECT * FROM users WHERE id={uid}"\n')

        haiku_mock = MagicMock()
        haiku_mock.scan_lines.return_value = set()  # Haiku finds nothing

        with patch("agent.orchestrator.triage_codebase", return_value={str(app_py): [1]}):
            with patch("agent.orchestrator.HaikuTriageScanner", return_value=haiku_mock):
                with patch("agent.orchestrator.anthropic.Anthropic"):
                    from agent.orchestrator import scan_codebase
                    result = scan_codebase(str(tmp_path))

        assert result.vulnerabilities == []

