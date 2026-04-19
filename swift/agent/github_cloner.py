"""GitHub repository cloner for SWIFT.

Provides utilities to detect GitHub URLs, validate their format, and clone
them into a temporary directory with automatic cleanup support.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from typing import Callable, Tuple

# Matches https://github.com/owner/repo  (optional .git suffix, optional trailing slash)
_HTTPS_PATTERN = re.compile(
    r"^https://github\.com/[\w.\-]+/[\w.\-]+(\.git)?/?$"
)
# Matches git@github.com:owner/repo  (optional .git suffix)
_SSH_PATTERN = re.compile(
    r"^git@github\.com:[\w.\-]+/[\w.\-]+(\.git)?$"
)


def is_github_url(s: str) -> bool:
    """Return True if *s* looks like a GitHub HTTPS or SSH URL.

    Args:
        s: The string to test.

    Returns:
        True when *s* starts with ``https://github.com/`` or
        ``git@github.com:``, False otherwise.
    """
    return s.startswith("https://github.com/") or s.startswith("git@github.com:")


def validate_github_url(s: str) -> None:
    """Raise ValueError if *s* is not a well-formed GitHub repository URL.

    Accepts HTTPS (``https://github.com/owner/repo``) and SSH
    (``git@github.com:owner/repo``) forms. The ``.git`` suffix and a
    trailing slash are both optional for HTTPS.

    Args:
        s: The URL string to validate.

    Raises:
        ValueError: If *s* does not match the expected GitHub URL format.
    """
    if not (_HTTPS_PATTERN.match(s) or _SSH_PATTERN.match(s)):
        raise ValueError(
            f"Invalid GitHub URL: {s!r}. "
            "Expected format: https://github.com/owner/repo  or  "
            "git@github.com:owner/repo"
        )


def clone_repo(url: str) -> Tuple[str, Callable[[], None]]:
    """Shallow-clone a GitHub repository into a temporary directory.

    Runs ``git clone --depth 1 <url> <tmpdir>`` via subprocess. The caller
    is responsible for invoking the returned cleanup callable, ideally in a
    ``finally`` block, to remove the temporary directory.

    Args:
        url: A valid GitHub repository URL (HTTPS or SSH).

    Returns:
        A ``(local_path, cleanup)`` tuple where *local_path* is the
        absolute path to the cloned directory and *cleanup* is a zero-
        argument callable that deletes it.

    Raises:
        ValueError: If *url* fails format validation.
        FileNotFoundError: If ``git`` is not installed or not on PATH.
        RuntimeError: For network errors, authentication failures, timeouts,
            or any non-zero git exit code.
    """
    validate_github_url(url)

    tmpdir = tempfile.mkdtemp(prefix="swift_clone_")

    def cleanup() -> None:
        """Remove the cloned temporary directory."""
        shutil.rmtree(tmpdir, ignore_errors=True)

    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", url, tmpdir],
            capture_output=True,
            timeout=120,
        )
    except FileNotFoundError:
        cleanup()
        raise FileNotFoundError(
            "git is not installed or not found on PATH. "
            "Install git and retry."
        )
    except subprocess.TimeoutExpired:
        cleanup()
        raise RuntimeError(
            f"git clone timed out after 120s cloning {url!r}."
        )

    if result.returncode != 0:
        stderr = result.stderr.decode(errors="replace").strip()
        cleanup()
        if "Authentication failed" in stderr or "could not read Username" in stderr:
            raise RuntimeError(
                f"Authentication failed cloning {url!r}. "
                "For private repos set up SSH keys or a GitHub token. "
                f"git stderr: {stderr}"
            )
        raise RuntimeError(
            f"git clone failed (exit {result.returncode}) for {url!r}. "
            f"git stderr: {stderr}"
        )

    return tmpdir, cleanup
