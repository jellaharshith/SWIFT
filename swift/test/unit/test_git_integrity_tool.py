"""Tests for git integrity MCP tool."""
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from security.permissions import Permission, PermissionDenied, PermissionLayer
from tools.git_integrity_tool import (
    GitIntegrityInput,
    GitIntegrityOutput,
    GitIntegrityTool,
)


class TestGitIntegrityInputValidation:
    """Test input schema validation."""

    def test_valid_input_creates_schema(self):
        """Valid input should create schema."""
        with tempfile.TemporaryDirectory() as tmpdir:
            schema = GitIntegrityInput(repo_path=tmpdir)
            assert schema.repo_path == tmpdir

    def test_nonexistent_repo_path_raises(self):
        """Nonexistent repo path should raise."""
        with pytest.raises(ValueError, match="does not exist"):
            GitIntegrityInput(repo_path="/nonexistent/path")


class TestGitIntegrityOutputSchema:
    """Test output schema."""

    def test_output_schema_creates_successfully(self):
        """Output schema should create with valid data."""
        output = GitIntegrityOutput(
            repo_path="/tmp/repo",
            is_git_repo=True,
            branch="main",
            head_commit="abc123",
            working_tree_clean=True,
            untracked_files=[],
            modified_files=[],
            suspicious_history_signals=[],
        )
        assert output.is_git_repo is True
        assert output.working_tree_clean is True


class TestGitIntegrityToolPermissions:
    """Test permission enforcement."""

    def test_permission_check_on_verify(self):
        """Verify should check permission."""
        perm_layer = PermissionLayer()
        perm_layer.set_permission(Permission.READ_FILE, False)
        tool = GitIntegrityTool(permission_layer=perm_layer)

        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(PermissionDenied):
                tool.verify(tmpdir)

    def test_permission_granted_allows_verify(self):
        """Verify with permission granted should not raise permission error."""
        perm_layer = PermissionLayer()
        tool = GitIntegrityTool(permission_layer=perm_layer)

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(tool, "_is_git_repo", return_value=False):
                # Should not raise PermissionDenied
                result = tool.verify(tmpdir)
                assert isinstance(result, GitIntegrityOutput)


class TestGitIntegrityToolIsGitRepo:
    """Test git repo detection."""

    def test_is_git_repo_returns_false_for_non_repo(self):
        """Non-git directory should return False."""
        perm_layer = PermissionLayer()
        tool = GitIntegrityTool(permission_layer=perm_layer)

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=1)
                is_repo = tool._is_git_repo(tmpdir)
                assert is_repo is False

    def test_is_git_repo_returns_true_for_repo(self):
        """Git directory should return True."""
        perm_layer = PermissionLayer()
        tool = GitIntegrityTool(permission_layer=perm_layer)

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0)
                is_repo = tool._is_git_repo(tmpdir)
                assert is_repo is True


class TestGitIntegrityToolGetCurrentBranch:
    """Test branch detection."""

    def test_get_current_branch_returns_branch_name(self):
        """Valid branch should return branch name."""
        perm_layer = PermissionLayer()
        tool = GitIntegrityTool(permission_layer=perm_layer)

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout="main\n",
                )
                branch = tool._get_current_branch(tmpdir)
                assert branch == "main"

    def test_get_current_branch_detects_detached_head(self):
        """Detached HEAD should return None."""
        perm_layer = PermissionLayer()
        tool = GitIntegrityTool(permission_layer=perm_layer)

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout="HEAD\n",
                )
                branch = tool._get_current_branch(tmpdir)
                assert branch is None

    def test_get_current_branch_error_returns_none(self):
        """Git error should return None."""
        perm_layer = PermissionLayer()
        tool = GitIntegrityTool(permission_layer=perm_layer)

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=1)
                branch = tool._get_current_branch(tmpdir)
                assert branch is None


class TestGitIntegrityToolGetHeadCommit:
    """Test HEAD commit detection."""

    def test_get_head_commit_returns_hash(self):
        """Valid HEAD should return commit hash."""
        perm_layer = PermissionLayer()
        tool = GitIntegrityTool(permission_layer=perm_layer)

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout="abc123def456\n",
                )
                commit = tool._get_head_commit(tmpdir)
                assert commit == "abc123def456"

    def test_get_head_commit_error_returns_none(self):
        """Git error should return None."""
        perm_layer = PermissionLayer()
        tool = GitIntegrityTool(permission_layer=perm_layer)

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=1)
                commit = tool._get_head_commit(tmpdir)
                assert commit is None


class TestGitIntegrityToolGetWorkingTreeStatus:
    """Test working tree status detection."""

    def test_clean_working_tree(self):
        """Clean working tree should return empty lists."""
        perm_layer = PermissionLayer()
        tool = GitIntegrityTool(permission_layer=perm_layer)

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("subprocess.run") as mock_run:
                # Return empty output for both untracked and modified
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout="",
                )
                untracked, modified = tool._get_working_tree_status(tmpdir)
                assert untracked == []
                assert modified == []

    def test_untracked_files_detected(self):
        """Untracked files should be detected."""
        perm_layer = PermissionLayer()
        tool = GitIntegrityTool(permission_layer=perm_layer)

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("subprocess.run") as mock_run:
                # First call returns untracked files, second returns modified
                mock_run.side_effect = [
                    MagicMock(returncode=0, stdout="file1.txt\nfile2.txt\n"),
                    MagicMock(returncode=0, stdout=""),
                ]
                untracked, modified = tool._get_working_tree_status(tmpdir)
                assert "file1.txt" in untracked
                assert "file2.txt" in untracked
                assert modified == []

    def test_modified_files_detected(self):
        """Modified files should be detected."""
        perm_layer = PermissionLayer()
        tool = GitIntegrityTool(permission_layer=perm_layer)

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("subprocess.run") as mock_run:
                # First call returns untracked, second returns modified
                mock_run.side_effect = [
                    MagicMock(returncode=0, stdout=""),
                    MagicMock(returncode=0, stdout="main.py\nutils.py\n"),
                ]
                untracked, modified = tool._get_working_tree_status(tmpdir)
                assert untracked == []
                assert "main.py" in modified
                assert "utils.py" in modified


class TestGitIntegrityToolDetectSuspiciousPatterns:
    """Test suspicious pattern detection."""

    def test_detached_head_detected(self):
        """Detached HEAD should be detected."""
        perm_layer = PermissionLayer()
        tool = GitIntegrityTool(permission_layer=perm_layer)

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("subprocess.run") as mock_run:
                # Return HEAD for detached state
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout="HEAD\n",
                )
                suspicious = tool._detect_suspicious_patterns(tmpdir)
                assert any("Detached HEAD" in s for s in suspicious)

    def test_force_push_detected(self):
        """Force push in reflog should be detected."""
        perm_layer = PermissionLayer()
        tool = GitIntegrityTool(permission_layer=perm_layer)

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("subprocess.run") as mock_run:
                # Return branch name (not detached) then force push in reflog
                mock_run.side_effect = [
                    MagicMock(returncode=0, stdout="main\n"),
                    MagicMock(returncode=0, stdout="force push detected\n"),
                    MagicMock(returncode=0, stdout=""),
                ]
                suspicious = tool._detect_suspicious_patterns(tmpdir)
                assert any("Force push" in s or "force" in s for s in suspicious)

    def test_large_files_detected(self):
        """Large files should be detected."""
        perm_layer = PermissionLayer()
        tool = GitIntegrityTool(permission_layer=perm_layer)

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("subprocess.run") as mock_run:
                # Return branch name, reflog with no force push, and file list with large file
                mock_run.side_effect = [
                    MagicMock(returncode=0, stdout="main\n"),
                    MagicMock(returncode=0, stdout=""),
                    MagicMock(returncode=0, stdout="large.bin\0"),
                ]
                # Mock Path.exists and stat for the large file
                with patch("pathlib.Path.exists", return_value=True):
                    with patch("pathlib.Path.stat") as mock_stat:
                        mock_stat.return_value.st_size = 11 * 1024 * 1024  # 11MB
                        suspicious = tool._detect_suspicious_patterns(tmpdir)
                        # Should detect large files
                        assert any("Large files" in s for s in suspicious)


class TestGitIntegrityToolVerify:
    """Test full verification."""

    def test_verify_non_git_repo(self):
        """Verify on non-git directory should return not a repo."""
        perm_layer = PermissionLayer()
        tool = GitIntegrityTool(permission_layer=perm_layer)

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(tool, "_is_git_repo", return_value=False):
                result = tool.verify(tmpdir)
                assert result.is_git_repo is False
                assert result.branch is None

    def test_verify_clean_git_repo(self):
        """Verify on clean git repo should show success."""
        perm_layer = PermissionLayer()
        tool = GitIntegrityTool(permission_layer=perm_layer)

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(tool, "_is_git_repo", return_value=True):
                with patch.object(tool, "_get_current_branch", return_value="main"):
                    with patch.object(tool, "_get_head_commit", return_value="abc123"):
                        with patch.object(
                            tool, "_get_working_tree_status", return_value=([], [])
                        ):
                            with patch.object(
                                tool, "_detect_suspicious_patterns", return_value=[]
                            ):
                                result = tool.verify(tmpdir)
                                assert result.is_git_repo is True
                                assert result.working_tree_clean is True
                                assert result.branch == "main"


class TestGitIntegrityToolForensicLogging:
    """Test forensic logging."""

    def test_successful_verify_logged(self):
        """Successful verify should be logged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = str(Path(tmpdir) / "audit.json")
            perm_layer = PermissionLayer()
            tool = GitIntegrityTool(permission_layer=perm_layer, audit_log_path=log_path)

            repo_dir = Path(tmpdir) / "repo"
            repo_dir.mkdir()

            with patch.object(tool, "_is_git_repo", return_value=False):
                tool.verify(str(repo_dir))

                # Verify log entry created
                import json as json_module
                with open(log_path, "r") as f:
                    entries = json_module.load(f)
                assert len(entries) > 0
                assert entries[0]["tool_name"] == "git_integrity"
                assert entries[0]["status"] == "success"

    def test_permission_denied_logged(self):
        """Permission denied should be logged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = str(Path(tmpdir) / "audit.json")
            perm_layer = PermissionLayer()
            perm_layer.set_permission(Permission.READ_FILE, False)
            tool = GitIntegrityTool(permission_layer=perm_layer, audit_log_path=log_path)

            repo_dir = Path(tmpdir) / "repo"
            repo_dir.mkdir()

            try:
                tool.verify(str(repo_dir))
            except PermissionDenied:
                pass

            # Verify log entry created with denied status
            import json as json_module
            with open(log_path, "r") as f:
                entries = json_module.load(f)
            assert len(entries) > 0
            assert entries[0]["status"] == "denied"
