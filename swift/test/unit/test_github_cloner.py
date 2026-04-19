"""Unit tests for agent.github_cloner — subprocess fully mocked."""
from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from agent.github_cloner import clone_repo, is_github_url, validate_github_url


class TestIsGithubUrl:
    def test_https_url_detected(self):
        assert is_github_url("https://github.com/owner/repo") is True

    def test_ssh_url_detected(self):
        assert is_github_url("git@github.com:owner/repo.git") is True

    def test_local_path_not_detected(self):
        assert is_github_url("/home/user/myrepo") is False

    def test_http_not_https_not_detected(self):
        assert is_github_url("http://github.com/owner/repo") is False

    def test_gitlab_not_detected(self):
        assert is_github_url("https://gitlab.com/owner/repo") is False

    def test_empty_string_not_detected(self):
        assert is_github_url("") is False

    def test_relative_path_not_detected(self):
        assert is_github_url("./myrepo") is False


class TestValidateGithubUrl:
    def test_valid_https_passes(self):
        validate_github_url("https://github.com/owner/repo")  # no raise

    def test_valid_https_with_git_suffix_passes(self):
        validate_github_url("https://github.com/owner/repo.git")

    def test_valid_https_with_trailing_slash_passes(self):
        validate_github_url("https://github.com/owner/repo/")

    def test_valid_ssh_passes(self):
        validate_github_url("git@github.com:owner/repo.git")

    def test_valid_ssh_no_suffix_passes(self):
        validate_github_url("git@github.com:owner/repo")

    def test_missing_repo_raises_value_error(self):
        with pytest.raises(ValueError, match="Invalid GitHub URL"):
            validate_github_url("https://github.com/owner")

    def test_missing_owner_raises_value_error(self):
        with pytest.raises(ValueError, match="Invalid GitHub URL"):
            validate_github_url("https://github.com/")

    def test_local_path_raises_value_error(self):
        with pytest.raises(ValueError, match="Invalid GitHub URL"):
            validate_github_url("/tmp/myrepo")

    def test_http_not_https_raises(self):
        with pytest.raises(ValueError):
            validate_github_url("http://github.com/owner/repo")

    def test_gitlab_raises(self):
        with pytest.raises(ValueError):
            validate_github_url("https://gitlab.com/owner/repo")


class TestCloneRepo:
    def test_clone_returns_path_and_callable(self):
        mock_result = MagicMock(returncode=0)
        with patch("agent.github_cloner.subprocess.run", return_value=mock_result):
            with patch("agent.github_cloner.tempfile.mkdtemp", return_value="/tmp/swift_clone_abc"):
                path, cleanup = clone_repo("https://github.com/owner/repo")
        assert path == "/tmp/swift_clone_abc"
        assert callable(cleanup)

    def test_clone_calls_git_with_depth_1(self):
        mock_result = MagicMock(returncode=0)
        with patch("agent.github_cloner.subprocess.run", return_value=mock_result) as mock_run:
            with patch("agent.github_cloner.tempfile.mkdtemp", return_value="/tmp/swift_clone_abc"):
                clone_repo("https://github.com/owner/repo")
        mock_run.assert_called_once_with(
            ["git", "clone", "--depth", "1", "https://github.com/owner/repo", "/tmp/swift_clone_abc"],
            capture_output=True,
            timeout=120,
        )

    def test_cleanup_callable_removes_tmpdir(self):
        mock_result = MagicMock(returncode=0)
        with patch("agent.github_cloner.subprocess.run", return_value=mock_result):
            with patch("agent.github_cloner.tempfile.mkdtemp", return_value="/tmp/swift_clone_abc"):
                with patch("agent.github_cloner.shutil.rmtree") as mock_rmtree:
                    _, cleanup = clone_repo("https://github.com/owner/repo")
                    cleanup()
        mock_rmtree.assert_called_with("/tmp/swift_clone_abc", ignore_errors=True)

    def test_nonzero_exit_raises_runtime_error(self):
        mock_result = MagicMock(returncode=128, stderr=b"repository not found")
        with patch("agent.github_cloner.subprocess.run", return_value=mock_result):
            with patch("agent.github_cloner.tempfile.mkdtemp", return_value="/tmp/swift_clone_abc"):
                with patch("agent.github_cloner.shutil.rmtree"):
                    with pytest.raises(RuntimeError, match="git clone failed"):
                        clone_repo("https://github.com/owner/repo")

    def test_auth_failure_raises_runtime_error_with_message(self):
        mock_result = MagicMock(returncode=128, stderr=b"Authentication failed")
        with patch("agent.github_cloner.subprocess.run", return_value=mock_result):
            with patch("agent.github_cloner.tempfile.mkdtemp", return_value="/tmp/swift_clone_abc"):
                with patch("agent.github_cloner.shutil.rmtree"):
                    with pytest.raises(RuntimeError, match="Authentication failed"):
                        clone_repo("https://github.com/private/repo")

    def test_git_not_installed_raises_file_not_found(self):
        with patch("agent.github_cloner.subprocess.run", side_effect=FileNotFoundError):
            with patch("agent.github_cloner.tempfile.mkdtemp", return_value="/tmp/swift_clone_abc"):
                with patch("agent.github_cloner.shutil.rmtree"):
                    with pytest.raises(FileNotFoundError, match="git is not installed"):
                        clone_repo("https://github.com/owner/repo")

    def test_timeout_raises_runtime_error(self):
        with patch(
            "agent.github_cloner.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="git", timeout=120),
        ):
            with patch("agent.github_cloner.tempfile.mkdtemp", return_value="/tmp/swift_clone_abc"):
                with patch("agent.github_cloner.shutil.rmtree"):
                    with pytest.raises(RuntimeError, match="timed out"):
                        clone_repo("https://github.com/owner/repo")

    def test_invalid_url_raises_value_error_before_subprocess(self):
        """validate_github_url fires before subprocess.run is ever called."""
        with patch("agent.github_cloner.subprocess.run") as mock_run:
            with pytest.raises(ValueError):
                clone_repo("not-a-github-url")
        mock_run.assert_not_called()

    def test_cleanup_called_on_nonzero_exit(self):
        """Temporary directory is removed even when clone fails."""
        mock_result = MagicMock(returncode=1, stderr=b"some error")
        with patch("agent.github_cloner.subprocess.run", return_value=mock_result):
            with patch("agent.github_cloner.tempfile.mkdtemp", return_value="/tmp/swift_clone_abc"):
                with patch("agent.github_cloner.shutil.rmtree") as mock_rmtree:
                    with pytest.raises(RuntimeError):
                        clone_repo("https://github.com/owner/repo")
        mock_rmtree.assert_called_once_with("/tmp/swift_clone_abc", ignore_errors=True)

    def test_ssh_url_cloned_correctly(self):
        mock_result = MagicMock(returncode=0)
        with patch("agent.github_cloner.subprocess.run", return_value=mock_result) as mock_run:
            with patch("agent.github_cloner.tempfile.mkdtemp", return_value="/tmp/swift_clone_ssh"):
                path, _ = clone_repo("git@github.com:owner/repo.git")
        assert path == "/tmp/swift_clone_ssh"
        args = mock_run.call_args[0][0]
        assert "git@github.com:owner/repo.git" in args
