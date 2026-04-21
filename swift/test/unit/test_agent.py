"""Unit tests for the agent orchestrator — all external calls mocked."""
from __future__ import annotations

import json
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
# Tests
# ---------------------------------------------------------------------------

class TestScanCodebase:
    def test_scan_returns_scan_result(self, tmp_path, monkeypatch):
        """scan_codebase must always return a ScanResult."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        with _mock_triage({}):
            with patch("agent.orchestrator.anthropic.Anthropic"):
                from agent.orchestrator import scan_codebase
                result = scan_codebase(str(tmp_path))
        assert isinstance(result, ScanResult)

    def test_scan_calls_triage(self, tmp_path, monkeypatch):
        """scan_codebase must call triage_codebase with the repo path."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        with patch("agent.orchestrator.triage_codebase", return_value={}) as mock_triage:
            with patch("agent.orchestrator.anthropic.Anthropic"):
                from agent.orchestrator import scan_codebase
                scan_codebase(str(tmp_path))
        mock_triage.assert_called_once_with(str(tmp_path))

    def test_scan_files_scanned_count(self, tmp_path, monkeypatch):
        """files_scanned must equal number of files returned by triage."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        flagged = {
            str(tmp_path / "a.py"): [1],
            str(tmp_path / "b.py"): [2],
        }
        with _mock_triage(flagged):
            haiku_patch, haiku_mock = _mock_haiku(set())
            with haiku_patch:
                with patch("agent.orchestrator.anthropic.Anthropic"):
                    from agent.orchestrator import scan_codebase
                    result = scan_codebase(str(tmp_path))
        assert result.files_scanned == 2

    def test_scan_empty_repo_returns_empty(self, tmp_path, monkeypatch):
        """Empty repo must yield 0 vulnerabilities and 0 patches."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        with _mock_triage({}):
            with patch("agent.orchestrator.anthropic.Anthropic"):
                from agent.orchestrator import scan_codebase
                result = scan_codebase(str(tmp_path))
        assert result.vulnerabilities == []
        assert result.patches == []

    def test_scan_duration_tracked(self, tmp_path, monkeypatch):
        """duration_seconds must be a positive float."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        with _mock_triage({}):
            with patch("agent.orchestrator.anthropic.Anthropic"):
                from agent.orchestrator import scan_codebase
                result = scan_codebase(str(tmp_path))
        assert result.duration_seconds >= 0.0

    def test_scan_no_haiku_signals_gives_empty_result(self, tmp_path, monkeypatch):
        """When Haiku finds no suspicious lines, the result must have 0 vulnerabilities.

        The orchestrator converts Haiku signals directly to SIGNAL-* REVIEW_REQUIRED
        findings (Sonnet deep-analysis is disabled for MVP stability). With no signals
        there are no findings.
        """
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        file_path = str(tmp_path / "app.py")
        with open(file_path, "w") as f:
            f.write("query = f'SELECT * FROM users WHERE id={uid}'\n")

        flagged = {file_path: [1]}
        with _mock_triage(flagged):
            haiku_patch, haiku_mock = _mock_haiku(set())  # Haiku finds nothing
            with haiku_patch:
                with patch("agent.orchestrator.anthropic.Anthropic"):
                    from agent.orchestrator import scan_codebase
                    result = scan_codebase(str(tmp_path))
        assert len(result.vulnerabilities) == 0

    def test_scan_calls_haiku_on_flagged_files(self, tmp_path, monkeypatch):
        """Haiku scanner must be called for each file flagged by regex triage."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        file_path = str(tmp_path / "app.py")
        with open(file_path, "w") as f:
            f.write("os.system(cmd)\n")

        flagged = {file_path: [1]}
        with _mock_triage(flagged):
            haiku_patch, haiku_mock = _mock_haiku(set())
            with haiku_patch:
                with patch("agent.orchestrator.anthropic.Anthropic"):
                    from agent.orchestrator import scan_codebase
                    scan_codebase(str(tmp_path))
        haiku_mock.scan_lines.assert_called()

    def test_scan_haiku_signals_create_findings(self, tmp_path, monkeypatch):
        """Haiku signals are converted to SIGNAL-* REVIEW_REQUIRED findings.

        The orchestrator (MVP mode) bypasses Sonnet deep-analysis and converts
        each Haiku-flagged line directly into a SIGNAL-* vulnerability with
        REVIEW_REQUIRED status and confidence ~0.7.
        """
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        file_path = str(tmp_path / "app.py")
        with open(file_path, "w") as f:
            f.write("os.system(cmd)\n")

        flagged = {file_path: [1]}
        with _mock_triage(flagged):
            haiku_patch, haiku_mock = _mock_haiku({1})  # Haiku flags line 1
            with haiku_patch:
                with patch("agent.orchestrator.anthropic.Anthropic"):
                    from agent.orchestrator import scan_codebase
                    result = scan_codebase(str(tmp_path))
        assert len(result.vulnerabilities) == 1
        vuln = result.vulnerabilities[0]
        assert vuln.id.startswith("SIGNAL-")
        assert vuln.status == "REVIEW_REQUIRED"
        assert vuln.confidence == 0.7

    def test_scan_timestamp_is_iso(self, tmp_path, monkeypatch):
        """ScanResult.timestamp must be a valid ISO 8601 string."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        from datetime import datetime
        with _mock_triage({}):
            with patch("agent.orchestrator.anthropic.Anthropic"):
                from agent.orchestrator import scan_codebase
                result = scan_codebase(str(tmp_path))
        # Raises ValueError if not ISO format
        datetime.fromisoformat(result.timestamp.replace("Z", "+00:00"))

    def test_scan_id_format(self, tmp_path, monkeypatch):
        """scan_id must start with 'SCAN-'."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        with _mock_triage({}):
            with patch("agent.orchestrator.anthropic.Anthropic"):
                from agent.orchestrator import scan_codebase
                result = scan_codebase(str(tmp_path))
        assert result.scan_id.startswith("SCAN-")

    def test_scan_no_patches_by_default(self, tmp_path, monkeypatch):
        """Patches must be empty when generate_patches_flag=False (default)."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        vuln = _make_vuln()
        file_path = str(tmp_path / "app.py")
        with open(file_path, "w") as f:
            f.write("query = f'SELECT * FROM users WHERE id={uid}'\n")

        flagged = {file_path: [1]}
        with _mock_triage(flagged):
            haiku_patch, _ = _mock_haiku({1})
            sonnet_patch, _ = _mock_sonnet(vuln)
            with haiku_patch, sonnet_patch:
                with patch("agent.orchestrator.anthropic.Anthropic"):
                    from agent.orchestrator import scan_codebase
                    result = scan_codebase(str(tmp_path), generate_patches_flag=False)
        assert result.patches == []


class TestGeneratePatches:
    def test_generate_patches_calls_patch_generator(self, tmp_path, monkeypatch):
        """generate_patches must invoke PatchGenerator for each vulnerability."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        from agent.models import ScanResult
        scan = ScanResult(
            scan_id="SCAN-abc",
            repo_path=str(tmp_path),
            files_scanned=1,
            vulnerabilities=[_make_vuln()],
            patches=[],
            duration_seconds=1.0,
            total_cost_usd=0.0,
            timestamp="2026-04-19T00:00:00+00:00",
        )
        mock_gen = MagicMock()
        mock_gen.generate_patch.return_value = None
        mock_sandbox = MagicMock()
        with patch("agent.orchestrator.PatchGenerator", return_value=mock_gen):
            with patch("agent.orchestrator.DockerSandbox", return_value=mock_sandbox):
                with patch("agent.orchestrator.anthropic.Anthropic"):
                    from agent.orchestrator import generate_patches
                    generate_patches(scan)
        mock_gen.generate_patch.assert_called_once()

    def test_generate_patches_calls_sandbox(self, tmp_path, monkeypatch):
        """generate_patches must call sandbox.test_patch when a patch is produced."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        from agent.models import Patch, ScanResult, TestResult

        patch_obj = Patch(
            id="PATCH-001", vuln_id="SWIFT-001", file_path="app.py",
            original_code="old", patched_code="new", diff="", confidence=0.97,
        )
        scan = ScanResult(
            scan_id="SCAN-abc", repo_path=str(tmp_path), files_scanned=1,
            vulnerabilities=[_make_vuln()], patches=[], duration_seconds=1.0,
            total_cost_usd=0.0, timestamp="2026-04-19T00:00:00+00:00",
        )
        mock_gen = MagicMock()
        mock_gen.generate_patch.return_value = patch_obj
        mock_sandbox = MagicMock()
        mock_sandbox.test_patch.return_value = TestResult(patch_id="PATCH-001", passed=True, output="OK", exit_code=0)

        with patch("agent.orchestrator.PatchGenerator", return_value=mock_gen):
            with patch("agent.orchestrator.DockerSandbox", return_value=mock_sandbox):
                with patch("agent.orchestrator.anthropic.Anthropic"):
                    from agent.orchestrator import generate_patches
                    result = generate_patches(scan)
        mock_sandbox.test_patch.assert_called_once_with(patch_obj)
        assert len(result.patches) == 1
