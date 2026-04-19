"""Integration tests for GitHub URL support in CLI scan and patch commands."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from agent.models import ScanResult
from cli.commands import cli


def _make_scan_result(repo_path: str = "/tmp/swift_clone_abc") -> ScanResult:
    return ScanResult(
        scan_id="SCAN-abc12345",
        repo_path=repo_path,
        files_scanned=3,
        vulnerabilities=[],
        patches=[],
        duration_seconds=1.0,
        total_cost_usd=0.01,
        timestamp="2026-04-19T00:00:00+00:00",
    )


class TestScanWithGitHubUrl:
    def test_scan_https_url_exits_0(self):
        runner = CliRunner()
        cleanup_mock = MagicMock()
        with patch("cli.commands.is_github_url", return_value=True):
            with patch("cli.commands.clone_repo", return_value=("/tmp/swift_clone_abc", cleanup_mock)):
                with patch("cli.commands.scan_codebase", return_value=_make_scan_result()):
                    result = runner.invoke(
                        cli, ["scan", "--repo", "https://github.com/owner/repo"]
                    )
        assert result.exit_code == 0

    def test_scan_calls_clone_repo_with_url(self):
        runner = CliRunner()
        cleanup_mock = MagicMock()
        with patch("cli.commands.is_github_url", return_value=True):
            with patch("cli.commands.clone_repo", return_value=("/tmp/swift_clone_abc", cleanup_mock)) as mock_clone:
                with patch("cli.commands.scan_codebase", return_value=_make_scan_result()):
                    runner.invoke(cli, ["scan", "--repo", "https://github.com/owner/repo"])
        mock_clone.assert_called_once_with("https://github.com/owner/repo")

    def test_scan_passes_cloned_path_to_scan_codebase(self):
        runner = CliRunner()
        cleanup_mock = MagicMock()
        with patch("cli.commands.is_github_url", return_value=True):
            with patch("cli.commands.clone_repo", return_value=("/tmp/swift_clone_abc", cleanup_mock)):
                with patch("cli.commands.scan_codebase", return_value=_make_scan_result()) as mock_scan:
                    runner.invoke(cli, ["scan", "--repo", "https://github.com/owner/repo"])
        mock_scan.assert_called_once_with("/tmp/swift_clone_abc", generate_patches_flag=False)

    def test_scan_cleanup_called_after_success(self):
        runner = CliRunner()
        cleanup_mock = MagicMock()
        with patch("cli.commands.is_github_url", return_value=True):
            with patch("cli.commands.clone_repo", return_value=("/tmp/swift_clone_abc", cleanup_mock)):
                with patch("cli.commands.scan_codebase", return_value=_make_scan_result()):
                    runner.invoke(cli, ["scan", "--repo", "https://github.com/owner/repo"])
        cleanup_mock.assert_called_once()

    def test_scan_cleanup_called_when_scan_raises(self):
        """Cleanup must run even when scan_codebase raises an exception."""
        runner = CliRunner()
        cleanup_mock = MagicMock()
        with patch("cli.commands.is_github_url", return_value=True):
            with patch("cli.commands.clone_repo", return_value=("/tmp/swift_clone_abc", cleanup_mock)):
                with patch("cli.commands.scan_codebase", side_effect=RuntimeError("API error")):
                    result = runner.invoke(cli, ["scan", "--repo", "https://github.com/owner/repo"])
        assert result.exit_code == 1
        cleanup_mock.assert_called_once()

    def test_scan_clone_failure_exits_1(self):
        runner = CliRunner()
        with patch("cli.commands.is_github_url", return_value=True):
            with patch("cli.commands.clone_repo", side_effect=RuntimeError("git clone failed (exit 128)")):
                result = runner.invoke(cli, ["scan", "--repo", "https://github.com/owner/repo"])
        assert result.exit_code == 1

    def test_scan_invalid_url_exits_1(self):
        runner = CliRunner()
        with patch("cli.commands.is_github_url", return_value=True):
            with patch("cli.commands.clone_repo", side_effect=ValueError("Invalid GitHub URL")):
                result = runner.invoke(cli, ["scan", "--repo", "https://github.com/bad"])
        assert result.exit_code == 1

    def test_local_path_skips_clone(self, tmp_path):
        """Local paths must never call clone_repo."""
        runner = CliRunner()
        with patch("cli.commands.is_github_url", return_value=False):
            with patch("cli.commands.clone_repo") as mock_clone:
                with patch("cli.commands.scan_codebase", return_value=_make_scan_result()):
                    runner.invoke(cli, ["scan", "--repo", str(tmp_path)])
        mock_clone.assert_not_called()

    def test_scan_github_url_output_contains_json(self):
        runner = CliRunner()
        cleanup_mock = MagicMock()
        with patch("cli.commands.is_github_url", return_value=True):
            with patch("cli.commands.clone_repo", return_value=("/tmp/swift_clone_abc", cleanup_mock)):
                with patch("cli.commands.scan_codebase", return_value=_make_scan_result()):
                    result = runner.invoke(
                        cli,
                        ["scan", "--repo", "https://github.com/owner/repo", "--output", "json"],
                    )
        assert result.exit_code == 0
        json_start = result.output.find("{")
        assert json_start != -1
        data = json.loads(result.output[json_start:])
        assert "scan" in data


class TestPatchCommandWithGitHubUrl:
    def test_patch_github_url_exits_0(self):
        runner = CliRunner()
        cleanup_mock = MagicMock()
        with patch("cli.commands.is_github_url", return_value=True):
            with patch("cli.commands.clone_repo", return_value=("/tmp/swift_clone_abc", cleanup_mock)):
                with patch("cli.commands.scan_codebase", return_value=_make_scan_result()):
                    result = runner.invoke(cli, ["patch", "--repo", "https://github.com/owner/repo"])
        assert result.exit_code == 0

    def test_patch_cleanup_called_on_success(self):
        runner = CliRunner()
        cleanup_mock = MagicMock()
        with patch("cli.commands.is_github_url", return_value=True):
            with patch("cli.commands.clone_repo", return_value=("/tmp/swift_clone_abc", cleanup_mock)):
                with patch("cli.commands.scan_codebase", return_value=_make_scan_result()):
                    runner.invoke(cli, ["patch", "--repo", "https://github.com/owner/repo"])
        cleanup_mock.assert_called_once()

    def test_patch_cleanup_called_on_failure(self):
        runner = CliRunner()
        cleanup_mock = MagicMock()
        with patch("cli.commands.is_github_url", return_value=True):
            with patch("cli.commands.clone_repo", return_value=("/tmp/swift_clone_abc", cleanup_mock)):
                with patch("cli.commands.scan_codebase", side_effect=Exception("boom")):
                    result = runner.invoke(cli, ["patch", "--repo", "https://github.com/owner/repo"])
        assert result.exit_code == 1
        cleanup_mock.assert_called_once()

    def test_patch_passes_generate_patches_flag_true(self):
        runner = CliRunner()
        cleanup_mock = MagicMock()
        with patch("cli.commands.is_github_url", return_value=True):
            with patch("cli.commands.clone_repo", return_value=("/tmp/swift_clone_abc", cleanup_mock)):
                with patch("cli.commands.scan_codebase", return_value=_make_scan_result()) as mock_scan:
                    runner.invoke(cli, ["patch", "--repo", "https://github.com/owner/repo"])
        mock_scan.assert_called_once_with("/tmp/swift_clone_abc", generate_patches_flag=True)
