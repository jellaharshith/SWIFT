"""Safe MCP tool wrapper for semgrep vulnerability scanning.

Enforces permission checks, forensic logging, and ruleset validation.
Integrates with SWIFT's two-stage scanning pipeline (Haiku triage → Sonnet analysis).
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

from log.logger import get_logger
from security.logging import ForensicLogger
from security.permissions import Permission, PermissionDenied, PermissionLayer

logger = get_logger(__name__)


# Approved rulesets when READ_ONLY_MODE is enforced
APPROVED_RULESETS = {
    "auto",
    "p/c",
    "p/cpp",
    "p/security-audit",
    "p/owasp-top-ten",
}


class SemgrepInput(BaseModel):
    """Input schema for semgrep tool."""

    repo_path: str = Field(
        ...,
        description="Path to repository or file to scan",
    )
    ruleset: str = Field(
        default="auto",
        description="Semgrep ruleset (auto, p/c, p/cpp, p/security-audit, p/owasp-top-ten)",
    )
    timeout_seconds: Optional[int] = Field(
        default=None,
        description="Timeout for scan in seconds (None = no timeout)",
    )

    @field_validator("ruleset")
    @classmethod
    def validate_ruleset(cls, v: str) -> str:
        """Validate ruleset is on allowlist."""
        if v not in APPROVED_RULESETS:
            raise ValueError(
                f"Ruleset '{v}' not approved. Allowed: {', '.join(sorted(APPROVED_RULESETS))}"
            )
        return v

    @field_validator("repo_path")
    @classmethod
    def validate_path_exists(cls, v: str) -> str:
        """Validate repository path exists."""
        if not Path(v).exists():
            raise ValueError(f"Repository path does not exist: {v}")
        return v


class SemgrepOutput(BaseModel):
    """Output schema for semgrep tool."""

    findings: List[Dict[str, Any]] = Field(
        ...,
        description="List of findings (rules matched)",
    )
    finding_count: int = Field(
        ...,
        description="Total number of findings",
    )
    ruleset_used: str = Field(
        ...,
        description="Ruleset that was used for scan",
    )


class SemgrepTool:
    """Safe wrapper for semgrep vulnerability scanner.

    - Validates repo path and ruleset before execution
    - Enforces permission checks via PermissionLayer
    - Logs all actions to forensic audit trail
    - Parses JSON output safely
    - Returns structured findings with metadata
    """

    def __init__(
        self,
        permission_layer: Optional[PermissionLayer] = None,
        audit_log_path: str = "log/audit_mcp_tools.json",
    ) -> None:
        """Initialize semgrep tool.

        Args:
            permission_layer: Permission enforcement layer (creates new if None).
            audit_log_path: Path to forensic audit log.
        """
        self._permissions = permission_layer or PermissionLayer()
        self._forensic = ForensicLogger(audit_log_path)

    def scan(self, repo_path: str, ruleset: str = "auto", timeout_seconds: Optional[int] = None) -> SemgrepOutput:
        """Scan repository for vulnerabilities using semgrep.

        Args:
            repo_path: Path to repository or file to scan.
            ruleset: Semgrep ruleset to use (must be approved).
            timeout_seconds: Timeout for scan in seconds.

        Returns:
            SemgrepOutput with findings and metadata.

        Raises:
            PermissionDenied: If tool use not permitted.
            ValueError: If inputs invalid.
        """
        # Validate inputs
        try:
            input_schema = SemgrepInput(
                repo_path=repo_path,
                ruleset=ruleset,
                timeout_seconds=timeout_seconds,
            )
        except ValueError as e:
            logger.error("Input validation failed: %s", e)
            self._forensic.log_action(
                tool_name="semgrep",
                action="scan",
                inputs={
                    "repo_path": repo_path,
                    "ruleset": ruleset,
                    "timeout_seconds": timeout_seconds,
                },
                outputs={},
                status="failure",
                error_message=f"Input validation: {e}",
            )
            raise

        # Check permission
        try:
            self._permissions.check_permission(Permission.SCAN_REPO)
        except PermissionDenied as e:
            logger.warning("Semgrep scan denied: %s", e)
            self._forensic.log_action(
                tool_name="semgrep",
                action="scan",
                inputs=input_schema.model_dump(),
                outputs={},
                status="denied",
                error_message=str(e),
            )
            raise

        logger.info("Starting semgrep scan: %s (ruleset=%s)", repo_path, ruleset)

        try:
            # Build semgrep command
            cmd = ["semgrep", "--json", "--config", ruleset, input_schema.repo_path]

            # Run semgrep
            result = subprocess.run(
                cmd,
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )

            # Parse JSON output
            try:
                output_data = json.loads(result.stdout)
            except json.JSONDecodeError as e:
                logger.error("Failed to parse semgrep JSON output: %s", e)
                self._forensic.log_action(
                    tool_name="semgrep",
                    action="scan",
                    inputs=input_schema.model_dump(),
                    outputs={},
                    status="failure",
                    error_message=f"JSON parse error: {e}",
                )
                raise ValueError(f"Semgrep output not valid JSON: {e}") from e

            # Extract findings
            findings = output_data.get("results", [])
            finding_count = len(findings)

            # Create output
            output = SemgrepOutput(
                findings=findings,
                finding_count=finding_count,
                ruleset_used=ruleset,
            )

            # Log success
            self._forensic.log_action(
                tool_name="semgrep",
                action="scan",
                inputs=input_schema.model_dump(),
                outputs={
                    "finding_count": finding_count,
                    "ruleset_used": ruleset,
                },
                status="success",
            )

            logger.info("Semgrep scan complete: %d findings", finding_count)
            return output

        except subprocess.TimeoutExpired as e:
            logger.error("Semgrep scan timeout: %s", e)
            self._forensic.log_action(
                tool_name="semgrep",
                action="scan",
                inputs=input_schema.model_dump(),
                outputs={},
                status="failure",
                error_message=f"Timeout after {timeout_seconds}s",
            )
            raise TimeoutError(f"Semgrep scan timed out after {timeout_seconds}s") from e

        except Exception as e:
            logger.error("Semgrep scan failed: %s", e)
            self._forensic.log_action(
                tool_name="semgrep",
                action="scan",
                inputs=input_schema.model_dump(),
                outputs={},
                status="failure",
                error_message=str(e),
            )
            raise
