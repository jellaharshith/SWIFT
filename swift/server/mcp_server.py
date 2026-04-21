"""MCP (Model Context Protocol) server for SWIFT.

Registers all 5 defensive tools with clear descriptions and usage guidelines.
Each tool is permission-checked and forensically logged before execution.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from log.logger import get_logger
from security.logging import ForensicLogger
from security.permissions import PermissionLayer
from tools.cuckoo_tool import CuckooTool
from tools.git_integrity_tool import GitIntegrityTool
from tools.nmap_tool import NmapTool
from tools.sandbox_tool import SandboxTool
from tools.semgrep_tool import SemgrepTool

logger = get_logger(__name__)


class MCPServer:
    """MCP server for SWIFT defensive tools.

    Manages registration and execution of 5 security tools:
    1. semgrep_tool - Safe code vulnerability scanning
    2. nmap_tool - Controlled network reconnaissance
    3. cuckoo_tool - Safe malware analysis API wrapper
    4. sandbox_tool - Docker-based code execution isolation
    5. git_integrity_tool - Repository integrity verification

    All tools enforce:
    - Permission checks (PermissionLayer)
    - Forensic logging (ForensicLogger)
    - Input validation (Pydantic v2 schemas)
    - Defensive-only scope
    """

    def __init__(
        self,
        permission_layer: Optional[PermissionLayer] = None,
        audit_log_path: str = "log/audit_mcp_tools.json",
    ) -> None:
        """Initialize MCP server with all tools.

        Args:
            permission_layer: Permission enforcement layer (creates new if None).
            audit_log_path: Path to forensic audit log.
        """
        self._permissions = permission_layer or PermissionLayer()
        self._forensic = ForensicLogger(audit_log_path)

        # Initialize all tools with shared permission layer and audit log
        self.semgrep = SemgrepTool(
            permission_layer=self._permissions,
            audit_log_path=audit_log_path,
        )
        self.nmap = NmapTool(
            permission_layer=self._permissions,
            audit_log_path=audit_log_path,
        )
        self.cuckoo = CuckooTool(
            permission_layer=self._permissions,
            audit_log_path=audit_log_path,
        )
        self.sandbox = SandboxTool(
            permission_layer=self._permissions,
            audit_log_path=audit_log_path,
        )
        self.git_integrity = GitIntegrityTool(
            permission_layer=self._permissions,
            audit_log_path=audit_log_path,
        )

    def list_tools(self) -> List[Dict[str, Any]]:
        """List all available tools with descriptions.

        Returns:
            List of tool descriptors with name, description, and usage.
        """
        return [
            {
                "name": "semgrep",
                "description": "Safe code vulnerability scanning",
                "category": "scanning",
                "methods": ["scan"],
                "usage": "Scan repository for vulnerabilities using semgrep ruleset.",
                "parameters": {
                    "repo_path": "Path to repository or file to scan",
                    "ruleset": "Semgrep ruleset (auto, p/c, p/cpp, p/security-audit, p/owasp-top-ten)",
                    "timeout_seconds": "Timeout in seconds (optional)",
                },
                "returns": {
                    "findings": "List of findings",
                    "finding_count": "Total number of findings",
                    "ruleset_used": "Ruleset that was used",
                },
                "permissions": ["SCAN_REPO"],
                "defensive_only": True,
            },
            {
                "name": "nmap",
                "description": "Controlled network reconnaissance",
                "category": "reconnaissance",
                "methods": ["scan"],
                "usage": "Scan target for open ports and services (basic, service, or OS detection mode).",
                "parameters": {
                    "target": "Target host or network (IP, domain, CIDR)",
                    "ports": "Port range (1-1000 default)",
                    "mode": "Scan mode (basic, service, os)",
                    "host_timeout": "Timeout per host (30s default)",
                },
                "returns": {
                    "target": "Target that was scanned",
                    "open_ports": "List of open port numbers",
                    "services": "Port to service mapping",
                    "os_guess": "Detected OS (os mode only)",
                    "raw_output": "Raw nmap output",
                },
                "permissions": ["SCAN_REPO"],
                "defensive_only": True,
                "blocked_forever": ["--script", "-sC", "exploit", "vuln"],
            },
            {
                "name": "cuckoo",
                "description": "Safe malware analysis API wrapper",
                "category": "malware_analysis",
                "methods": ["submit_file", "get_report", "get_status", "list_tasks"],
                "usage": "Interact with Cuckoo sandbox (read-only + submit operations only).",
                "operations": {
                    "submit_file": "Submit file for analysis",
                    "get_report": "Get analysis report for task",
                    "get_status": "Get status of analysis task",
                    "list_tasks": "List all tasks",
                },
                "parameters": {
                    "operation": "Operation to execute",
                    "file_path": "Path to file (submit_file only)",
                    "task_id": "Task ID (get_report, get_status)",
                },
                "returns": {
                    "operation": "Operation executed",
                    "success": "Whether operation succeeded",
                    "data": "Response from Cuckoo API",
                    "message": "Status message",
                },
                "permissions": ["API_CALL"],
                "defensive_only": True,
                "blocked_forever": ["delete", "modify", "reconfigure"],
            },
            {
                "name": "sandbox",
                "description": "Docker-based code execution isolation",
                "category": "execution",
                "methods": ["execute"],
                "usage": "Execute command in isolated Docker container with strict security constraints.",
                "constraints": {
                    "privileged_mode": False,
                    "host_pid": False,
                    "read_only_fs": True,
                    "network_access": False,
                    "memory_limit": "512m",
                    "cpu_limit": "1",
                    "timeout_max": "3600s",
                },
                "parameters": {
                    "image": "Docker image to run (python:3.11-slim default)",
                    "command": "Command and args to execute",
                    "mounts": "Mount paths (approved roots only)",
                    "timeout_seconds": "Timeout in seconds (1-3600)",
                    "working_dir": "Working directory in container",
                },
                "returns": {
                    "exit_code": "Container exit code",
                    "stdout": "Standard output",
                    "stderr": "Standard error",
                    "duration_ms": "Execution duration",
                    "timed_out": "Whether execution timed out",
                },
                "permissions": ["TEST_PATCH"],
                "defensive_only": True,
                "approved_mount_roots": ["/tmp", "/var/tmp", "/home", "/opt"],
            },
            {
                "name": "git_integrity",
                "description": "Repository integrity verification",
                "category": "verification",
                "methods": ["verify"],
                "usage": "Verify git repository integrity and detect suspicious patterns.",
                "detects": [
                    "Detached HEAD",
                    "Uncommitted changes",
                    "Untracked files",
                    "Modified files",
                    "Force pushes",
                    "Large files (>10MB)",
                ],
                "parameters": {
                    "repo_path": "Path to git repository",
                },
                "returns": {
                    "repo_path": "Repository path checked",
                    "is_git_repo": "Whether path is valid git repo",
                    "branch": "Current branch name",
                    "head_commit": "Current HEAD commit hash",
                    "working_tree_clean": "Whether working tree is clean",
                    "untracked_files": "List of untracked files",
                    "modified_files": "List of modified files",
                    "suspicious_history_signals": "Detected suspicious patterns",
                },
                "permissions": ["READ_FILE"],
                "defensive_only": True,
            },
        ]

    def get_tool_info(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific tool.

        Args:
            tool_name: Name of tool to get info for.

        Returns:
            Tool descriptor dict or None if tool not found.
        """
        tools = {t["name"]: t for t in self.list_tools()}
        return tools.get(tool_name)

    def get_forensic_log(self) -> str:
        """Get path to forensic audit log.

        Returns:
            Path to audit log file.
        """
        return self._forensic._log_path

    def get_integrity_report(self) -> Dict[str, Any]:
        """Get integrity verification report for audit log.

        Returns:
            Report with total entries, verification status, and tampered entries.
        """
        return self._forensic.get_integrity_report()

    def verify_audit_log_integrity(self) -> bool:
        """Verify forensic audit log integrity.

        Returns:
            True if log is verified clean, False if tampering detected.
        """
        return self._forensic.verify_integrity()
