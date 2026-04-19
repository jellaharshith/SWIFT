"""Unit tests for CLI commands — uses click.testing.CliRunner, all scanning mocked."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from agent.models import Patch, ScanResult, Vulnerability
from cli.commands import cli


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_vuln() -> Vulnerability:
    return Vulnerability(
        id="SWIFT-001", file_path="app.py", line_number=10,
        vuln_type="sql_injection", description="SQL injection",
        confidence=0.97, severity="CRITICAL",
        code_snippet='query = f"SELECT * FROM users WHERE id={uid}"',
    )


def _make_patch() -> Patch:
    return Patch(
        id="PATCH-001", vuln_id="SWIFT-001", file_path="app.py",
        original_code="old", patched_code="new", diff="--- a\n+++ b\n",
        confidence=0.97,
    )


def _make_scan_result(vulns=None, patches=None) -> ScanResult:
    return ScanResult(
        scan_id="SCAN-abc12345", repo_path="/tmp/repo", files_scanned=5,
        vulnerabilities=vulns or [], patches=patches or [],
        duration_seconds=1.2, total_cost_usd=0.05,
        timestamp="2026-04-19T00:00:00+00:00",
    )


# ---------------------------------------------------------------------------
# scan command tests
# ---------------------------------------------------------------------------

class TestScanCommand:
    def test_scan_exits_0(self, tmp_path):
        """scan command must exit 0 on success."""
        runner = CliRunner()
        with patch("cli.commands.scan_codebase", return_value=_make_scan_result()):
            result = runner.invoke(cli, ["scan", "--repo", str(tmp_path)])
        assert result.exit_code == 0

    def test_scan_outputs_valid_json(self, tmp_path):
        """scan --output json must produce valid JSON somewhere in output."""
        runner = CliRunner()
        with patch("cli.commands.scan_codebase", return_value=_make_scan_result([_make_vuln()])):
            result = runner.invoke(cli, ["scan", "--repo", str(tmp_path), "--output", "json"])
        assert result.exit_code == 0
        # Find the JSON block (starts at first '{')
        json_start = result.output.find("{")
        assert json_start != -1, f"No JSON found in output: {result.output!r}"
        data = json.loads(result.output[json_start:])
        assert "scan" in data

    def test_scan_outputs_markdown(self, tmp_path):
        """scan --output markdown must produce Markdown with SWIFT header."""
        runner = CliRunner()
        with patch("cli.commands.scan_codebase", return_value=_make_scan_result()):
            result = runner.invoke(cli, ["scan", "--repo", str(tmp_path), "--output", "markdown"])
        assert result.exit_code == 0
        assert "# SWIFT Vulnerability Report" in result.output

    def test_scan_missing_repo_exits_2(self):
        """scan without --repo must exit 2 (Click missing required option)."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan"])
        assert result.exit_code == 2

    def test_scan_error_exits_1(self, tmp_path):
        """scan must exit 1 when scan_codebase raises an exception."""
        runner = CliRunner()
        with patch("cli.commands.scan_codebase", side_effect=RuntimeError("API error")):
            result = runner.invoke(cli, ["scan", "--repo", str(tmp_path)])
        assert result.exit_code == 1

    def test_scan_no_api_key_exits_1(self, tmp_path, monkeypatch):
        """scan must exit 1 when API key is missing (ValueError from config)."""
        runner = CliRunner()
        with patch("cli.commands.scan_codebase", side_effect=ValueError("ANTHROPIC_API_KEY not set")):
            result = runner.invoke(cli, ["scan", "--repo", str(tmp_path)])
        assert result.exit_code == 1

    def test_scan_with_patches_flag(self, tmp_path):
        """scan --patches must call scan_codebase with generate_patches_flag=True."""
        runner = CliRunner()
        with patch("cli.commands.scan_codebase", return_value=_make_scan_result()) as mock_scan:
            result = runner.invoke(cli, ["scan", "--repo", str(tmp_path), "--patches"])
        assert result.exit_code == 0
        mock_scan.assert_called_once_with(str(tmp_path), generate_patches_flag=True)

    def test_scan_writes_to_out_file(self, tmp_path):
        """scan --out-file must write output to the specified file."""
        runner = CliRunner()
        out_file = str(tmp_path / "report.json")
        with patch("cli.commands.scan_codebase", return_value=_make_scan_result()):
            result = runner.invoke(cli, ["scan", "--repo", str(tmp_path), "--out-file", out_file])
        assert result.exit_code == 0
        import os
        assert os.path.exists(out_file)


# ---------------------------------------------------------------------------
# patch command tests
# ---------------------------------------------------------------------------

class TestPatchCommand:
    def test_patch_missing_repo_exits_2(self):
        """patch without --repo must exit 2."""
        runner = CliRunner()
        result = runner.invoke(cli, ["patch"])
        assert result.exit_code == 2

    def test_patch_exits_0_on_success(self, tmp_path):
        """patch command must exit 0 on success."""
        runner = CliRunner()
        with patch("cli.commands.scan_codebase", return_value=_make_scan_result()):
            result = runner.invoke(cli, ["patch", "--repo", str(tmp_path)])
        assert result.exit_code == 0

    def test_patch_calls_scan_with_patches_flag(self, tmp_path):
        """patch command must always pass generate_patches_flag=True."""
        runner = CliRunner()
        with patch("cli.commands.scan_codebase", return_value=_make_scan_result()) as mock_scan:
            runner.invoke(cli, ["patch", "--repo", str(tmp_path)])
        mock_scan.assert_called_once_with(str(tmp_path), generate_patches_flag=True)


# ---------------------------------------------------------------------------
# validate command tests
# ---------------------------------------------------------------------------

class TestValidateCommand:
    def test_validate_exits_0(self):
        """validate --patch-id must exit 0 (informational stub)."""
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", "--patch-id", "PATCH-001"])
        assert result.exit_code == 0

    def test_validate_missing_patch_id_exits_2(self):
        """validate without --patch-id must exit 2."""
        runner = CliRunner()
        result = runner.invoke(cli, ["validate"])
        assert result.exit_code == 2
