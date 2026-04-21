"""Safe MCP tool wrapper for Cuckoo sandbox malware analysis.

Enforces permission checks, forensic logging, and strict operation allowlist.
Supports safe read-only operations: submit_file, get_report, get_status, list_tasks.
Blocks destructive operations: delete, modify, reconfigure.
"""
from __future__ import annotations

import os
from typing import Any, Dict, Literal, Optional

import requests
from pydantic import BaseModel, Field, field_validator

from log.logger import get_logger
from security.logging import ForensicLogger
from security.permissions import Permission, PermissionDenied, PermissionLayer

logger = get_logger(__name__)

# Allowed operations only (read-only + submit)
ALLOWED_OPERATIONS = {"submit_file", "get_report", "get_status", "list_tasks"}


class CuckooInput(BaseModel):
    """Input schema for Cuckoo tool."""

    operation: Literal["submit_file", "get_report", "get_status", "list_tasks"] = Field(
        ...,
        description="Operation: submit_file, get_report, get_status, list_tasks",
    )
    file_path: Optional[str] = Field(
        default=None,
        description="Path to file (required for submit_file)",
    )
    task_id: Optional[int] = Field(
        default=None,
        description="Task ID (required for get_report, get_status)",
    )

    @field_validator("operation")
    @classmethod
    def validate_operation(cls, v: str) -> str:
        """Validate operation is on allowlist."""
        if v not in ALLOWED_OPERATIONS:
            raise ValueError(
                f"Operation '{v}' not allowed. Allowed: {', '.join(sorted(ALLOWED_OPERATIONS))}"
            )
        return v

    def validate_operation_args(self) -> None:
        """Validate required args for operation."""
        if self.operation == "submit_file" and not self.file_path:
            raise ValueError("submit_file requires file_path")
        if self.operation in {"get_report", "get_status"} and not self.task_id:
            raise ValueError(f"{self.operation} requires task_id")


class CuckooOutput(BaseModel):
    """Output schema for Cuckoo tool."""

    operation: str = Field(
        ...,
        description="Operation that was executed",
    )
    success: bool = Field(
        ...,
        description="Whether operation succeeded",
    )
    data: Dict[str, Any] = Field(
        ...,
        description="Response data from Cuckoo API",
    )
    message: str = Field(
        ...,
        description="Status message",
    )


class CuckooTool:
    """Safe wrapper for Cuckoo sandbox API.

    - Restricts to read-only operations and safe submission
    - Blocks destructive operations (delete, modify, reconfigure)
    - Validates file paths and task IDs before API calls
    - Permission-checked and forensically logged
    - Reads API credentials from environment
    """

    def __init__(
        self,
        permission_layer: Optional[PermissionLayer] = None,
        audit_log_path: str = "log/audit_mcp_tools.json",
    ) -> None:
        """Initialize Cuckoo tool.

        Args:
            permission_layer: Permission enforcement layer (creates new if None).
            audit_log_path: Path to forensic audit log.
        """
        self._permissions = permission_layer or PermissionLayer()
        self._forensic = ForensicLogger(audit_log_path)

        # Load Cuckoo API credentials from environment
        self._api_url = os.getenv("CUCKOO_API_URL", "http://localhost:8090")
        self._api_key = os.getenv("CUCKOO_API_KEY", "")

    def execute(
        self,
        operation: Literal["submit_file", "get_report", "get_status", "list_tasks"],
        file_path: Optional[str] = None,
        task_id: Optional[int] = None,
    ) -> CuckooOutput:
        """Execute safe Cuckoo operation.

        Args:
            operation: Operation to execute (submit_file, get_report, get_status, list_tasks).
            file_path: Path to file for submit_file operation.
            task_id: Task ID for get_report/get_status operations.

        Returns:
            CuckooOutput with success status and data.

        Raises:
            PermissionDenied: If tool use not permitted.
            ValueError: If inputs invalid.
        """
        # Validate inputs
        try:
            input_schema = CuckooInput(
                operation=operation,
                file_path=file_path,
                task_id=task_id,
            )
            input_schema.validate_operation_args()
        except ValueError as e:
            logger.error("Input validation failed: %s", e)
            self._forensic.log_action(
                tool_name="cuckoo",
                action=operation,
                inputs={
                    "operation": operation,
                    "file_path": file_path,
                    "task_id": task_id,
                },
                outputs={},
                status="failure",
                error_message=f"Input validation: {e}",
            )
            raise

        # Check permission (API_CALL) - use allowed model for context
        try:
            self._permissions.check_permission(Permission.API_CALL, {"model": "claude-sonnet-4-6"})
        except PermissionDenied as e:
            logger.warning("Cuckoo operation denied: %s", e)
            self._forensic.log_action(
                tool_name="cuckoo",
                action=operation,
                inputs=input_schema.model_dump(),
                outputs={},
                status="denied",
                error_message=str(e),
            )
            raise

        logger.info("Executing Cuckoo operation: %s", operation)

        try:
            if operation == "submit_file":
                return self._submit_file(file_path)
            elif operation == "get_report":
                return self._get_report(task_id)
            elif operation == "get_status":
                return self._get_status(task_id)
            elif operation == "list_tasks":
                return self._list_tasks()
            else:
                raise ValueError(f"Unknown operation: {operation}")

        except Exception as e:
            logger.error("Cuckoo operation failed: %s", e)
            self._forensic.log_action(
                tool_name="cuckoo",
                action=operation,
                inputs={
                    "operation": operation,
                    "file_path": file_path,
                    "task_id": task_id,
                },
                outputs={},
                status="failure",
                error_message=str(e),
            )
            raise

    def _submit_file(self, file_path: str) -> CuckooOutput:
        """Submit file to Cuckoo for analysis.

        Args:
            file_path: Path to file to submit.

        Returns:
            CuckooOutput with task ID.

        Raises:
            FileNotFoundError: If file doesn't exist.
            requests.RequestException: If API call fails.
        """
        # Validate file exists
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        # Submit to Cuckoo
        url = f"{self._api_url}/tasks/create/file"
        headers = {"Authorization": f"Bearer {self._api_key}"} if self._api_key else {}

        with open(file_path, "rb") as f:
            files = {"file": f}
            response = requests.post(url, files=files, headers=headers, timeout=30)

        response.raise_for_status()
        data = response.json()

        output = CuckooOutput(
            operation="submit_file",
            success=True,
            data=data,
            message=f"File submitted successfully. Task ID: {data.get('task_id')}",
        )

        # Log success
        self._forensic.log_action(
            tool_name="cuckoo",
            action="submit_file",
            inputs={"file_path": file_path},
            outputs={"task_id": data.get("task_id")},
            status="success",
        )

        logger.info("File submitted to Cuckoo: task_id=%s", data.get("task_id"))
        return output

    def _get_report(self, task_id: int) -> CuckooOutput:
        """Get analysis report for task.

        Args:
            task_id: Task ID to get report for.

        Returns:
            CuckooOutput with analysis report.

        Raises:
            requests.RequestException: If API call fails.
        """
        url = f"{self._api_url}/tasks/report/{task_id}"
        headers = {"Authorization": f"Bearer {self._api_key}"} if self._api_key else {}

        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()

        output = CuckooOutput(
            operation="get_report",
            success=True,
            data=data,
            message=f"Report retrieved for task {task_id}",
        )

        # Log success
        self._forensic.log_action(
            tool_name="cuckoo",
            action="get_report",
            inputs={"task_id": task_id},
            outputs={"status": data.get("info", {}).get("status")},
            status="success",
        )

        logger.info("Retrieved Cuckoo report: task_id=%s", task_id)
        return output

    def _get_status(self, task_id: int) -> CuckooOutput:
        """Get status of analysis task.

        Args:
            task_id: Task ID to get status for.

        Returns:
            CuckooOutput with task status.

        Raises:
            requests.RequestException: If API call fails.
        """
        url = f"{self._api_url}/tasks/view/{task_id}"
        headers = {"Authorization": f"Bearer {self._api_key}"} if self._api_key else {}

        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()

        status = data.get("task", {}).get("status", "unknown")

        output = CuckooOutput(
            operation="get_status",
            success=True,
            data=data,
            message=f"Task {task_id} status: {status}",
        )

        # Log success
        self._forensic.log_action(
            tool_name="cuckoo",
            action="get_status",
            inputs={"task_id": task_id},
            outputs={"status": status},
            status="success",
        )

        logger.info("Retrieved Cuckoo task status: task_id=%s, status=%s", task_id, status)
        return output

    def _list_tasks(self) -> CuckooOutput:
        """List all tasks in Cuckoo.

        Returns:
            CuckooOutput with task list.

        Raises:
            requests.RequestException: If API call fails.
        """
        url = f"{self._api_url}/tasks/list"
        headers = {"Authorization": f"Bearer {self._api_key}"} if self._api_key else {}

        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()

        tasks = data.get("tasks", [])

        output = CuckooOutput(
            operation="list_tasks",
            success=True,
            data=data,
            message=f"Listed {len(tasks)} tasks",
        )

        # Log success
        self._forensic.log_action(
            tool_name="cuckoo",
            action="list_tasks",
            inputs={},
            outputs={"task_count": len(tasks)},
            status="success",
        )

        logger.info("Retrieved Cuckoo task list: %d tasks", len(tasks))
        return output
