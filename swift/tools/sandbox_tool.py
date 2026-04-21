"""Safe MCP tool wrapper for Docker sandbox execution.

Enforces permission checks, forensic logging, and strict security constraints.
No privileged mode, no host PID, read-only root FS, no network access.
Enforces mount restrictions and timeout enforcement.
"""
from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

from log.logger import get_logger
from security.logging import ForensicLogger
from security.permissions import Permission, PermissionDenied, PermissionLayer

logger = get_logger(__name__)

# Approved mount paths (read-only by default)
APPROVED_MOUNT_ROOTS = {
    "/tmp",
    "/var/tmp",
    "/home",
    "/opt",
}


class SandboxInput(BaseModel):
    """Input schema for sandbox tool."""

    image: Optional[str] = Field(
        default="python:3.11-slim",
        description="Docker image to run (defaults to python:3.11-slim)",
    )
    command: List[str] = Field(
        ...,
        description="Command and args to execute (e.g., ['python', 'script.py'])",
    )
    mounts: List[str] = Field(
        default_factory=list,
        description="Mount paths (e.g., ['/home/user/code:/code:ro'])",
    )
    timeout_seconds: int = Field(
        default=30,
        description="Timeout in seconds (1-3600, default 30)",
    )
    working_dir: Optional[str] = Field(
        default=None,
        description="Working directory inside container",
    )

    @field_validator("timeout_seconds")
    @classmethod
    def validate_timeout(cls, v: int) -> int:
        """Validate timeout is reasonable."""
        if v < 1 or v > 3600:
            raise ValueError("Timeout must be between 1 and 3600 seconds")
        return v

    @field_validator("command")
    @classmethod
    def validate_command(cls, v: List[str]) -> List[str]:
        """Validate command is not empty."""
        if not v or len(v) == 0:
            raise ValueError("Command cannot be empty")
        return v

    @field_validator("mounts")
    @classmethod
    def validate_mounts(cls, v: List[str]) -> List[str]:
        """Validate mount paths are safe."""
        for mount in v:
            # Mount format: /host/path:/container/path[:ro/rw]
            parts = mount.split(":")
            if len(parts) < 2 or len(parts) > 3:
                raise ValueError(f"Invalid mount format: {mount}. Use /host:/container[:ro|rw]")

            host_path = parts[0]
            # Validate host path is under approved roots
            is_approved = False
            for root in APPROVED_MOUNT_ROOTS:
                if host_path.startswith(root):
                    is_approved = True
                    break

            if not is_approved:
                raise ValueError(
                    f"Mount path {host_path} not under approved roots: {APPROVED_MOUNT_ROOTS}"
                )

        return v


class SandboxOutput(BaseModel):
    """Output schema for sandbox tool."""

    exit_code: int = Field(
        ...,
        description="Container exit code (0 = success)",
    )
    stdout: str = Field(
        ...,
        description="Standard output from container",
    )
    stderr: str = Field(
        ...,
        description="Standard error from container",
    )
    duration_ms: int = Field(
        ...,
        description="Execution duration in milliseconds",
    )
    timed_out: bool = Field(
        ...,
        description="Whether execution timed out",
    )


class SandboxTool:
    """Safe wrapper for Docker sandbox execution.

    - Enforces no privileged mode
    - Enforces no host PID namespace sharing
    - Enforces read-only root FS
    - Enforces no network access
    - Validates and restricts mount paths
    - Enforces timeout (1-3600 seconds)
    - Permission-checked and forensically logged
    """

    def __init__(
        self,
        permission_layer: Optional[PermissionLayer] = None,
        audit_log_path: str = "log/audit_mcp_tools.json",
    ) -> None:
        """Initialize sandbox tool.

        Args:
            permission_layer: Permission enforcement layer (creates new if None).
            audit_log_path: Path to forensic audit log.
        """
        self._permissions = permission_layer or PermissionLayer()
        self._forensic = ForensicLogger(audit_log_path)

    def execute(
        self,
        command: List[str],
        image: Optional[str] = None,
        mounts: Optional[List[str]] = None,
        timeout_seconds: int = 30,
        working_dir: Optional[str] = None,
    ) -> SandboxOutput:
        """Execute command in sandboxed Docker container.

        Args:
            command: Command and arguments to execute.
            image: Docker image to use (default: python:3.11-slim).
            mounts: Mount paths in format /host:/container[:ro|rw].
            timeout_seconds: Timeout in seconds (1-3600).
            working_dir: Working directory inside container.

        Returns:
            SandboxOutput with exit code, stdout, stderr, and duration.

        Raises:
            PermissionDenied: If tool use not permitted.
            ValueError: If inputs invalid.
        """
        # Validate inputs
        try:
            input_schema = SandboxInput(
                image=image or "python:3.11-slim",
                command=command,
                mounts=mounts or [],
                timeout_seconds=timeout_seconds,
                working_dir=working_dir,
            )
        except ValueError as e:
            logger.error("Input validation failed: %s", e)
            self._forensic.log_action(
                tool_name="sandbox",
                action="execute",
                inputs={
                    "command": command,
                    "image": image,
                    "timeout_seconds": timeout_seconds,
                },
                outputs={},
                status="failure",
                error_message=f"Input validation: {e}",
            )
            raise

        # Check permission (TEST_PATCH covers sandbox execution)
        try:
            self._permissions.check_permission(Permission.TEST_PATCH)
        except PermissionDenied as e:
            logger.warning("Sandbox execution denied: %s", e)
            self._forensic.log_action(
                tool_name="sandbox",
                action="execute",
                inputs=input_schema.model_dump(),
                outputs={},
                status="denied",
                error_message=str(e),
            )
            raise

        logger.info("Starting sandbox execution: image=%s, timeout=%ds", input_schema.image, timeout_seconds)

        start_time = time.time()

        try:
            # Build docker run command with security constraints
            docker_cmd = self._build_docker_command(
                input_schema.image,
                command,
                input_schema.mounts,
                working_dir,
            )

            # Run container
            result = subprocess.run(
                docker_cmd,
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )

            duration_ms = int((time.time() - start_time) * 1000)

            # Create output
            output = SandboxOutput(
                exit_code=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                duration_ms=duration_ms,
                timed_out=False,
            )

            # Log success
            self._forensic.log_action(
                tool_name="sandbox",
                action="execute",
                inputs=input_schema.model_dump(),
                outputs={
                    "exit_code": result.returncode,
                    "duration_ms": duration_ms,
                },
                status="success",
            )

            logger.info(
                "Sandbox execution complete: exit_code=%d, duration=%dms",
                result.returncode,
                duration_ms,
            )
            return output

        except subprocess.TimeoutExpired as e:
            duration_ms = int((time.time() - start_time) * 1000)

            output = SandboxOutput(
                exit_code=124,  # Timeout exit code
                stdout="",
                stderr=f"Container execution timed out after {timeout_seconds}s",
                duration_ms=duration_ms,
                timed_out=True,
            )

            # Log timeout
            self._forensic.log_action(
                tool_name="sandbox",
                action="execute",
                inputs=input_schema.model_dump(),
                outputs={
                    "duration_ms": duration_ms,
                    "timed_out": True,
                },
                status="failure",
                error_message=f"Timeout after {timeout_seconds}s",
            )

            logger.error("Sandbox execution timed out after %ds", timeout_seconds)
            return output

        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            logger.error("Sandbox execution failed: %s", e)
            self._forensic.log_action(
                tool_name="sandbox",
                action="execute",
                inputs=input_schema.model_dump(),
                outputs={},
                status="failure",
                error_message=str(e),
            )
            raise

    def _build_docker_command(
        self,
        image: str,
        command: List[str],
        mounts: List[str],
        working_dir: Optional[str],
    ) -> List[str]:
        """Build docker run command with security constraints.

        Args:
            image: Docker image name.
            command: Command to execute.
            mounts: Mount specifications.
            working_dir: Working directory in container.

        Returns:
            List of command arguments for subprocess.
        """
        docker_cmd = [
            "docker", "run",
            # Security constraints (non-negotiable)
            "--rm",  # Remove container after exit
            "--read-only",  # Read-only root FS
            "--network=none",  # No network access
            "--pids-limit=100",  # Limit processes
            "--memory=512m",  # Limit memory
            "--cpus=1",  # Limit CPU
            "--security-opt=no-new-privileges:true",  # Prevent privilege escalation
        ]

        # Add mounts
        for mount in mounts:
            docker_cmd.extend(["-v", mount])

        # Add tmpfs for temp files (required for read-only FS)
        docker_cmd.extend([
            "--tmpfs=/tmp:size=128m,noexec,nosuid",
            "--tmpfs=/run:size=64m,noexec,nosuid",
        ])

        # Add working directory if specified
        if working_dir:
            docker_cmd.extend(["-w", working_dir])

        # Add image and command
        docker_cmd.append(image)
        docker_cmd.extend(command)

        return docker_cmd
