"""Safe MCP tool wrapper for git repository integrity verification.

Detects suspicious history patterns and uncommitted changes.
Uses subprocess with shell=False for all git commands.
Permission-checked and forensically logged.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

from log.logger import get_logger
from security.logging import ForensicLogger
from security.permissions import Permission, PermissionDenied, PermissionLayer

logger = get_logger(__name__)


class GitIntegrityInput(BaseModel):
    """Input schema for git integrity tool."""

    repo_path: str = Field(
        ...,
        description="Path to git repository",
    )

    @field_validator("repo_path")
    @classmethod
    def validate_repo_path(cls, v: str) -> str:
        """Validate repository path exists."""
        if not Path(v).exists():
            raise ValueError(f"Repository path does not exist: {v}")
        return v


class GitIntegrityOutput(BaseModel):
    """Output schema for git integrity tool."""

    repo_path: str = Field(
        ...,
        description="Repository path that was checked",
    )
    is_git_repo: bool = Field(
        ...,
        description="Whether path is a valid git repository",
    )
    branch: Optional[str] = Field(
        default=None,
        description="Current branch name",
    )
    head_commit: Optional[str] = Field(
        default=None,
        description="Current HEAD commit hash",
    )
    working_tree_clean: bool = Field(
        ...,
        description="Whether working tree has no uncommitted changes",
    )
    untracked_files: List[str] = Field(
        ...,
        description="List of untracked files",
    )
    modified_files: List[str] = Field(
        ...,
        description="List of modified files",
    )
    suspicious_history_signals: List[str] = Field(
        ...,
        description="List of suspicious patterns detected in history",
    )


class GitIntegrityTool:
    """Safe wrapper for git repository integrity verification.

    - Detects detached HEAD
    - Detects missing .git directory
    - Detects uncommitted modifications
    - Detects untracked files
    - Detects suspicious history patterns (large file churn, force pushes)
    - Permission-checked and forensically logged
    - Uses subprocess with shell=False for all git commands
    """

    def __init__(
        self,
        permission_layer: Optional[PermissionLayer] = None,
        audit_log_path: str = "log/audit_mcp_tools.json",
    ) -> None:
        """Initialize git integrity tool.

        Args:
            permission_layer: Permission enforcement layer (creates new if None).
            audit_log_path: Path to forensic audit log.
        """
        self._permissions = permission_layer or PermissionLayer()
        self._forensic = ForensicLogger(audit_log_path)

    def verify(self, repo_path: str) -> GitIntegrityOutput:
        """Verify git repository integrity.

        Args:
            repo_path: Path to git repository.

        Returns:
            GitIntegrityOutput with integrity status and suspicious signals.

        Raises:
            PermissionDenied: If tool use not permitted.
            ValueError: If inputs invalid.
        """
        # Validate inputs
        try:
            input_schema = GitIntegrityInput(repo_path=repo_path)
        except ValueError as e:
            logger.error("Input validation failed: %s", e)
            self._forensic.log_action(
                tool_name="git_integrity",
                action="verify",
                inputs={"repo_path": repo_path},
                outputs={},
                status="failure",
                error_message=f"Input validation: {e}",
            )
            raise

        # Check permission (READ_FILE covers repo access)
        try:
            self._permissions.check_permission(Permission.READ_FILE)
        except PermissionDenied as e:
            logger.warning("Git integrity check denied: %s", e)
            self._forensic.log_action(
                tool_name="git_integrity",
                action="verify",
                inputs=input_schema.model_dump(),
                outputs={},
                status="denied",
                error_message=str(e),
            )
            raise

        logger.info("Starting git integrity check: %s", repo_path)

        try:
            # Check if it's a git repo
            is_git_repo = self._is_git_repo(repo_path)

            if not is_git_repo:
                output = GitIntegrityOutput(
                    repo_path=repo_path,
                    is_git_repo=False,
                    branch=None,
                    head_commit=None,
                    working_tree_clean=True,
                    untracked_files=[],
                    modified_files=[],
                    suspicious_history_signals=["Not a git repository"],
                )

                self._forensic.log_action(
                    tool_name="git_integrity",
                    action="verify",
                    inputs=input_schema.model_dump(),
                    outputs={"is_git_repo": False},
                    status="success",
                )

                logger.warning("Not a git repository: %s", repo_path)
                return output

            # Get branch and HEAD
            branch = self._get_current_branch(repo_path)
            head_commit = self._get_head_commit(repo_path)

            # Get working tree status
            untracked, modified = self._get_working_tree_status(repo_path)
            working_tree_clean = len(untracked) == 0 and len(modified) == 0

            # Detect suspicious patterns
            suspicious = self._detect_suspicious_patterns(repo_path)

            output = GitIntegrityOutput(
                repo_path=repo_path,
                is_git_repo=True,
                branch=branch,
                head_commit=head_commit,
                working_tree_clean=working_tree_clean,
                untracked_files=untracked,
                modified_files=modified,
                suspicious_history_signals=suspicious,
            )

            # Log success
            self._forensic.log_action(
                tool_name="git_integrity",
                action="verify",
                inputs=input_schema.model_dump(),
                outputs={
                    "is_git_repo": True,
                    "branch": branch,
                    "working_tree_clean": working_tree_clean,
                    "suspicious_signals_count": len(suspicious),
                },
                status="success",
            )

            logger.info(
                "Git integrity check complete: repo=%s, branch=%s, clean=%s",
                repo_path,
                branch,
                working_tree_clean,
            )
            return output

        except Exception as e:
            logger.error("Git integrity check failed: %s", e)
            self._forensic.log_action(
                tool_name="git_integrity",
                action="verify",
                inputs=input_schema.model_dump(),
                outputs={},
                status="failure",
                error_message=str(e),
            )
            raise

    def _is_git_repo(self, repo_path: str) -> bool:
        """Check if path is a valid git repository.

        Args:
            repo_path: Path to check.

        Returns:
            True if valid git repo, False otherwise.
        """
        try:
            result = subprocess.run(
                ["git", "-C", repo_path, "rev-parse", "--git-dir"],
                shell=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception as e:
            logger.debug("Failed to check if git repo: %s", e)
            return False

    def _get_current_branch(self, repo_path: str) -> Optional[str]:
        """Get current branch name.

        Args:
            repo_path: Repository path.

        Returns:
            Branch name or None if detached HEAD.
        """
        try:
            result = subprocess.run(
                ["git", "-C", repo_path, "rev-parse", "--abbrev-ref", "HEAD"],
                shell=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                branch = result.stdout.strip()
                # "HEAD" means detached HEAD
                if branch == "HEAD":
                    return None
                return branch
            return None
        except Exception as e:
            logger.debug("Failed to get current branch: %s", e)
            return None

    def _get_head_commit(self, repo_path: str) -> Optional[str]:
        """Get current HEAD commit hash.

        Args:
            repo_path: Repository path.

        Returns:
            Commit hash or None on error.
        """
        try:
            result = subprocess.run(
                ["git", "-C", repo_path, "rev-parse", "HEAD"],
                shell=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return result.stdout.strip()
            return None
        except Exception as e:
            logger.debug("Failed to get HEAD commit: %s", e)
            return None

    def _get_working_tree_status(self, repo_path: str) -> tuple[List[str], List[str]]:
        """Get untracked and modified files.

        Args:
            repo_path: Repository path.

        Returns:
            Tuple of (untracked_files, modified_files).
        """
        untracked = []
        modified = []

        try:
            # Get untracked files
            result = subprocess.run(
                ["git", "-C", repo_path, "ls-files", "--others", "--exclude-standard"],
                shell=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                untracked = [line.strip() for line in result.stdout.split("\n") if line.strip()]

            # Get modified files
            result = subprocess.run(
                ["git", "-C", repo_path, "diff", "--name-only"],
                shell=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                modified = [line.strip() for line in result.stdout.split("\n") if line.strip()]

        except Exception as e:
            logger.debug("Failed to get working tree status: %s", e)

        return untracked, modified

    def _detect_suspicious_patterns(self, repo_path: str) -> List[str]:
        """Detect suspicious history patterns.

        Args:
            repo_path: Repository path.

        Returns:
            List of detected suspicious signals.
        """
        suspicious = []

        try:
            # Check for detached HEAD
            result = subprocess.run(
                ["git", "-C", repo_path, "rev-parse", "--abbrev-ref", "HEAD"],
                shell=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip() == "HEAD":
                suspicious.append("Detached HEAD detected")

            # Check reflog for force pushes (git reflog show -a)
            result = subprocess.run(
                ["git", "-C", repo_path, "reflog", "show", "-a"],
                shell=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                reflog = result.stdout.lower()
                if "force" in reflog or "reset" in reflog:
                    suspicious.append("Force push or reset detected in reflog")

            # Check for large files (>10MB)
            result = subprocess.run(
                ["git", "-C", repo_path, "ls-files", "-z"],
                shell=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                file_list = result.stdout.split("\0")
                large_files = []
                for file in file_list:
                    if not file:
                        continue
                    try:
                        file_path = Path(repo_path) / file
                        if file_path.exists() and file_path.stat().st_size > 10 * 1024 * 1024:
                            large_files.append(file)
                    except Exception:
                        pass

                if large_files:
                    suspicious.append(f"Large files detected: {len(large_files)} files >10MB")

        except Exception as e:
            logger.debug("Error detecting suspicious patterns: %s", e)

        return suspicious
