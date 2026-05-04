"""Isolated patch validator for local repositories."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from patch_apply import apply_unified_diff, patch_sha256
from validation_schema import ValidationResult


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def append_audit_log(log_file: Path, payload: dict) -> None:
    """Write append-only JSONL audit entries."""
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")


def infer_validation_commands(workspace: Path) -> list[str]:
    """Infer deterministic defaults for Python, Node, or generic repos."""
    if (workspace / "pyproject.toml").exists() or (workspace / "setup.py").exists():
        return ["find . -name '*.py' | xargs python -m py_compile", "pytest -q"]
    if (workspace / "package.json").exists():
        return ["npm test --silent"]
    return ["sh -c 'echo no-op validation for unknown stack'"]


def run_validation_commands(
    workspace: Path,
    commands: list[str],
    artifact_dir: Path,
    audit_log: Path,
) -> tuple[bool, bool, list[str], list[str], list[str]]:
    """Run commands inside Docker sandbox (zero-trust) and split outcomes."""
    from sandbox_runner import run_in_sandbox

    syntax_ok = True
    tests_ok = True
    artifacts: list[str] = []
    errors: list[str] = []

    for index, cmd in enumerate(commands, start=1):
        result = run_in_sandbox(
            repo_path=str(workspace),
            command=cmd,
            artifacts_root=str(artifact_dir),
        )
        artifacts.extend(result.get("artifacts", []))
        append_audit_log(
            audit_log,
            {
                "timestamp": _utc_now(),
                "action": "run_command",
                "repo_path": str(workspace),
                "command_executed": cmd,
                "exit_code": result.get("container_exit_code"),
            },
        )
        if not result.get("success"):
            if "pytest" in cmd or " test" in cmd:
                tests_ok = False
            else:
                syntax_ok = False
            errors.extend(result.get("errors", [f"Command failed [{cmd}]"]))
    success = syntax_ok and tests_ok and not errors
    return success, syntax_ok, tests_ok, artifacts, errors


def validate_patch(
    original_repo_path: str,
    target_file_path: str,
    unified_diff_patch: str,
    commands: list[str] | None = None,
    artifacts_root: str = ".swift-artifacts",
) -> dict:
    """Validate patch in isolated temp workspace without touching original repo."""
    original_repo = Path(original_repo_path).resolve()
    result = ValidationResult(
        success=False,
        patch_applied=False,
        syntax_ok=False,
        tests_ok=False,
        summary="Validation did not run.",
    )
    if not original_repo.exists() or not original_repo.is_dir():
        result.errors.append(f"Repo path not found: {original_repo}")
        return result.to_json_dict()

    patch_hash = patch_sha256(unified_diff_patch)
    artifacts_base = Path(artifacts_root).resolve()
    artifacts_base.mkdir(parents=True, exist_ok=True)
    audit_log = artifacts_base / "audit.log.jsonl"

    with tempfile.TemporaryDirectory(prefix="swift_validate_") as tmp:
        workspace = Path(tmp) / original_repo.name
        result.workspace = str(workspace)
        artifact_dir = artifacts_base / patch_hash[:12]
        artifact_dir.mkdir(parents=True, exist_ok=True)
        append_audit_log(
            audit_log,
            {
                "timestamp": _utc_now(),
                "action": "start_patch_validation",
                "repo_path": str(original_repo),
                "file_path": target_file_path,
                "patch_hash": patch_hash,
                "workspace": str(workspace),
            },
        )
        try:
            shutil.copytree(original_repo, workspace, symlinks=True)
        except OSError as exc:
            result.errors.append(f"Failed to copy repo to isolated workspace: {exc}")
            return result.to_json_dict()

        ok, msg = apply_unified_diff(workspace, unified_diff_patch)
        result.patch_applied = ok
        if not ok:
            result.errors.append(msg)
            result.summary = "Patch could not be applied."
            append_audit_log(
                audit_log,
                {
                    "timestamp": _utc_now(),
                    "action": "patch_apply_failed",
                    "repo_path": str(original_repo),
                    "file_path": target_file_path,
                    "patch_hash": patch_hash,
                    "result_summary": msg,
                },
            )
            return result.to_json_dict()

        selected_commands = commands or infer_validation_commands(workspace)
        result.commands_run = selected_commands
        success, syntax_ok, tests_ok, artifacts, errors = run_validation_commands(
            workspace,
            selected_commands,
            artifact_dir,
            audit_log,
        )
        result.syntax_ok = syntax_ok
        result.tests_ok = tests_ok
        result.success = success
        result.artifacts = artifacts
        result.errors.extend(errors)
        result.summary = "Patch validated successfully." if success else "Validation failed."
        append_audit_log(
            audit_log,
            {
                "timestamp": _utc_now(),
                "action": "finish_patch_validation",
                "repo_path": str(original_repo),
                "file_path": target_file_path,
                "patch_hash": patch_hash,
                "exit_code": 0 if success else 1,
                "result_summary": result.summary,
            },
        )
    return result.to_json_dict()
