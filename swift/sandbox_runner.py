"""Docker sandbox runner for isolated patch validation."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class SandboxConfig:
    timeout_seconds: int = 300
    cpus: str = "2"
    memory: str = "2g"
    disable_network: bool = True
    user: str = "65534:65534"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def append_audit(log_file: Path, payload: dict) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")


def infer_image_and_command(repo_path: Path) -> tuple[str, str]:
    if (repo_path / "pyproject.toml").exists() or (repo_path / "requirements.txt").exists():
        return "python:3.12-slim", "find . -name '*.py' | PYTHONDONTWRITEBYTECODE=1 xargs python -m py_compile"
    if (repo_path / "package.json").exists():
        return "node:20-alpine", "npm ci --ignore-scripts && npm test --silent"
    return "alpine:3.20", "sh -c 'echo generic validation completed'"


def build_docker_run_command(
    image: str,
    repo_mount: Path,
    writable_tmp: Path,
    command: str,
    config: SandboxConfig,
    container_name: str,
) -> list[str]:
    run_cmd = [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name,
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=512m",
        "--mount",
        f"type=bind,src={repo_mount},dst=/workspace",
        "--mount",
        f"type=bind,src={writable_tmp},dst=/artifacts",
        "--workdir",
        "/workspace",
        "--cpus",
        config.cpus,
        "--memory",
        config.memory,
        "--pids-limit",
        "256",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        config.user,
    ]
    if config.disable_network:
        run_cmd.extend(["--network", "none"])
    run_cmd.extend([image, "sh", "-lc", command])
    return run_cmd


def run_in_sandbox(
    repo_path: str,
    command: str | None = None,
    artifacts_root: str = ".swift-artifacts/sandbox",
    config: SandboxConfig | None = None,
) -> dict:
    cfg = config or SandboxConfig()
    source_repo = Path(repo_path).resolve()
    artifacts_dir = Path(artifacts_root).resolve()
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    audit_log = artifacts_dir / "audit.log.jsonl"

    if not source_repo.exists():
        return {
            "success": False,
            "container_exit_code": 127,
            "container_id": None,
            "commands_run": [],
            "artifacts": [],
            "errors": [f"Repo path does not exist: {source_repo}"],
            "summary": "Sandbox run failed before startup.",
        }

    image, default_command = infer_image_and_command(source_repo)
    final_command = command or default_command
    container_name = f"swift-sandbox-{uuid.uuid4().hex[:12]}"

    with tempfile.TemporaryDirectory(prefix="swift_sandbox_") as tmp:
        tmp_path = Path(tmp)
        workspace_copy = tmp_path / "workspace"
        writable_artifacts = tmp_path / "artifacts"
        writable_artifacts.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source_repo, workspace_copy)
        # Make workspace + artifacts writable by the container's non-root UID.
        uid = int(cfg.user.split(":")[0])
        subprocess.run(
            ["docker", "run", "--rm",
             f"--volume={workspace_copy}:/ws",
             f"--volume={writable_artifacts}:/art",
             "busybox", "sh", "-c", f"chown -R {uid}:{uid} /ws /art"],
            capture_output=True,
        )

        docker_cmd = build_docker_run_command(
            image=image,
            repo_mount=workspace_copy,
            writable_tmp=writable_artifacts,
            command=final_command,
            config=cfg,
            container_name=container_name,
        )
        append_audit(
            audit_log,
            {
                "timestamp": _utc_now(),
                "action": "sandbox_start",
                "repo_path": str(source_repo),
                "command_executed": " ".join(docker_cmd),
                "container_id": container_name,
                "result_summary": "Sandbox run requested.",
            },
        )
        try:
            proc = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=cfg.timeout_seconds,
            )
            stdout_file = artifacts_dir / f"{container_name}.stdout.log"
            stderr_file = artifacts_dir / f"{container_name}.stderr.log"
            stdout_file.write_text(proc.stdout or "", encoding="utf-8")
            stderr_file.write_text(proc.stderr or "", encoding="utf-8")
            copied_artifacts: list[str] = [str(stdout_file), str(stderr_file)]

            for generated in writable_artifacts.iterdir():
                destination = artifacts_dir / f"{container_name}-{generated.name}"
                if generated.is_dir():
                    shutil.copytree(generated, destination, dirs_exist_ok=True)
                else:
                    shutil.copy2(generated, destination)
                copied_artifacts.append(str(destination))

            success = proc.returncode == 0
            summary = "Sandbox validation completed." if success else "Sandbox validation failed."
            append_audit(
                audit_log,
                {
                    "timestamp": _utc_now(),
                    "action": "sandbox_finish",
                    "repo_path": str(source_repo),
                    "command_executed": final_command,
                    "container_id": container_name,
                    "exit_code": proc.returncode,
                    "result_summary": summary,
                },
            )
            return {
                "success": success,
                "container_exit_code": proc.returncode,
                "container_id": container_name,
                "commands_run": [final_command],
                "artifacts": copied_artifacts,
                "errors": [] if success else ["Container command failed."],
                "summary": summary,
            }
        except subprocess.TimeoutExpired as exc:
            subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
            append_audit(
                audit_log,
                {
                    "timestamp": _utc_now(),
                    "action": "sandbox_timeout",
                    "repo_path": str(source_repo),
                    "command_executed": final_command,
                    "container_id": container_name,
                    "exit_code": 124,
                    "result_summary": f"Timeout after {cfg.timeout_seconds}s.",
                },
            )
            return {
                "success": False,
                "container_exit_code": 124,
                "container_id": container_name,
                "commands_run": [final_command],
                "artifacts": [],
                "errors": [f"Sandbox timed out: {exc}"],
                "summary": "Sandbox execution timed out.",
            }
        except OSError as exc:
            return {
                "success": False,
                "container_exit_code": 126,
                "container_id": container_name,
                "commands_run": [final_command],
                "artifacts": [],
                "errors": [f"Failed to run docker command: {exc}"],
                "summary": "Sandbox execution could not start.",
            }
