"""Patch application helper with safety checks."""
from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path


def patch_sha256(unified_diff: str) -> str:
    """Return SHA256 for immutable audit correlation."""
    return hashlib.sha256(unified_diff.encode("utf-8")).hexdigest()


def apply_unified_diff(workspace: Path, unified_diff: str) -> tuple[bool, str]:
    """Apply a unified diff in *workspace* using git apply --check first."""
    if not unified_diff.strip():
        return False, "Patch is empty."
    if not workspace.exists() or not workspace.is_dir():
        return False, f"Workspace does not exist: {workspace}"

    patch_file = workspace / ".swift_patch.diff"
    patch_file.write_text(unified_diff, encoding="utf-8")

    try:
        check = subprocess.run(
            ["git", "apply", "--check", str(patch_file)],
            cwd=str(workspace),
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"Patch pre-check failed: {exc}"

    if check.returncode != 0:
        return False, check.stderr.strip() or check.stdout.strip() or "git apply --check failed."

    try:
        apply_cmd = subprocess.run(
            ["git", "apply", str(patch_file)],
            cwd=str(workspace),
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"Patch apply failed: {exc}"

    if apply_cmd.returncode != 0:
        return False, apply_cmd.stderr.strip() or apply_cmd.stdout.strip() or "git apply failed."
    return True, "Patch applied successfully."
