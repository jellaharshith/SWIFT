"""Safe MCP tool wrapper for nmap network reconnaissance.

Enforces permission checks, forensic logging, and strict flag filtering.
Supports basic, service, and OS detection modes with controlled command building.
"""
from __future__ import annotations

import re
import subprocess
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator

from log.logger import get_logger
from security.logging import ForensicLogger
from security.permissions import Permission, PermissionDenied, PermissionLayer

logger = get_logger(__name__)

# Allowed flags (strict whitelist)
ALLOWED_FLAGS = {"-sS", "-sV", "-O", "-p", "--open", "-T2", "-oX", "--host-timeout"}

# Forever blocked: script execution, exploit, vuln detection
BLOCKED_PATTERNS = {
    r"--script",
    r"-sC",
    r"exploit",
    r"vuln",
    r"--script-args",
    r"-NSE",
}


class NmapInput(BaseModel):
    """Input schema for nmap tool."""

    target: str = Field(
        ...,
        description="Target host or network (IP, domain, or CIDR)",
    )
    ports: str = Field(
        default="1-1000",
        description="Port range (e.g., 1-1000, 22,80,443)",
    )
    mode: Literal["basic", "service", "os"] = Field(
        default="basic",
        description="Scan mode: basic (port sweep), service (version detection), os (OS detection)",
    )
    host_timeout: str = Field(
        default="30s",
        description="Timeout per host (e.g., 30s, 5m)",
    )

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        """Validate target is not obviously invalid."""
        if not v or len(v) == 0:
            raise ValueError("Target cannot be empty")
        if len(v) > 255:
            raise ValueError("Target too long")
        # Allow IP, CIDR, domain, hostname
        if not re.match(r"^[\w.\-/:]+$", v):
            raise ValueError("Target contains invalid characters")
        return v

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, v: str) -> str:
        """Validate port specification."""
        if not v or len(v) == 0:
            raise ValueError("Port specification cannot be empty")
        # Allow ranges (1-1000) and comma-separated (22,80,443)
        if not re.match(r"^[\d,\-]+$", v):
            raise ValueError("Ports must be numbers, ranges (1-1000), or comma-separated")
        return v

    @field_validator("host_timeout")
    @classmethod
    def validate_host_timeout(cls, v: str) -> str:
        """Validate timeout format."""
        if not re.match(r"^\d+[smh]?$", v):
            raise ValueError("Timeout must be: 30s, 5m, 1h")
        return v


class NmapOutput(BaseModel):
    """Output schema for nmap tool."""

    target: str = Field(
        ...,
        description="Target that was scanned",
    )
    open_ports: List[int] = Field(
        ...,
        description="List of open port numbers",
    )
    services: Dict[str, str] = Field(
        ...,
        description="Port → service mapping (port_num → service_name)",
    )
    os_guess: Optional[str] = Field(
        default=None,
        description="Detected OS (only in 'os' mode)",
    )
    raw_output: str = Field(
        ...,
        description="Raw nmap text output for reference",
    )


class NmapTool:
    """Safe wrapper for nmap network reconnaissance.

    - Strictly validates inputs and target
    - Enforces allowlist of safe flags
    - Blocks script execution, exploit detection, vulnerability scanning
    - Builds command internally (no freeform flag injection)
    - Parses XML output safely
    - Permission-checked and forensically logged
    """

    def __init__(
        self,
        permission_layer: Optional[PermissionLayer] = None,
        audit_log_path: str = "log/audit_mcp_tools.json",
    ) -> None:
        """Initialize nmap tool.

        Args:
            permission_layer: Permission enforcement layer (creates new if None).
            audit_log_path: Path to forensic audit log.
        """
        self._permissions = permission_layer or PermissionLayer()
        self._forensic = ForensicLogger(audit_log_path)

    def _build_command(
        self,
        target: str,
        ports: str,
        mode: Literal["basic", "service", "os"],
        host_timeout: str,
    ) -> List[str]:
        """Build nmap command based on mode (no freeform flags).

        Args:
            target: Target host/network.
            ports: Port specification.
            mode: Scan mode.
            host_timeout: Timeout per host.

        Returns:
            List of command arguments for subprocess.
        """
        cmd = ["nmap"]

        # Add mode-specific flags
        if mode == "basic":
            cmd.extend(["-sS"])  # SYN stealth scan
        elif mode == "service":
            cmd.extend(["-sS", "-sV"])  # SYN + service detection
        elif mode == "os":
            cmd.extend(["-sS", "-O", "-sV"])  # SYN + OS + service

        # Add common flags
        cmd.extend([
            "-p", ports,
            "--open",
            "-T2",  # Polite timing
            "--host-timeout", host_timeout,
            "-oX", "-",  # Output XML to stdout
        ])

        # Add target
        cmd.append(target)

        return cmd

    def scan(
        self,
        target: str,
        ports: str = "1-1000",
        mode: Literal["basic", "service", "os"] = "basic",
        host_timeout: str = "30s",
    ) -> NmapOutput:
        """Scan target with nmap for open ports and services.

        Args:
            target: Target host or network (IP, domain, CIDR).
            ports: Port range or comma-separated list.
            mode: Scan mode (basic=port sweep, service=version detection, os=OS detection).
            host_timeout: Timeout per host (30s, 5m, etc).

        Returns:
            NmapOutput with open ports, services, and raw output.

        Raises:
            PermissionDenied: If tool use not permitted.
            ValueError: If inputs invalid.
        """
        # Validate inputs
        try:
            input_schema = NmapInput(
                target=target,
                ports=ports,
                mode=mode,
                host_timeout=host_timeout,
            )
        except ValueError as e:
            logger.error("Input validation failed: %s", e)
            self._forensic.log_action(
                tool_name="nmap",
                action="scan",
                inputs={
                    "target": target,
                    "ports": ports,
                    "mode": mode,
                    "host_timeout": host_timeout,
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
            logger.warning("Nmap scan denied: %s", e)
            self._forensic.log_action(
                tool_name="nmap",
                action="scan",
                inputs=input_schema.model_dump(),
                outputs={},
                status="denied",
                error_message=str(e),
            )
            raise

        logger.info("Starting nmap scan: target=%s, mode=%s", target, mode)

        try:
            # Build safe command (no freeform flags)
            cmd = self._build_command(target, ports, mode, host_timeout)

            # Run nmap
            result = subprocess.run(
                cmd,
                shell=False,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )

            # Parse XML output
            open_ports, services, os_guess = self._parse_xml(result.stdout)

            # Create output
            output = NmapOutput(
                target=target,
                open_ports=open_ports,
                services=services,
                os_guess=os_guess,
                raw_output=result.stdout,
            )

            # Log success
            self._forensic.log_action(
                tool_name="nmap",
                action="scan",
                inputs=input_schema.model_dump(),
                outputs={
                    "target": target,
                    "open_ports_count": len(open_ports),
                    "mode": mode,
                },
                status="success",
            )

            logger.info("Nmap scan complete: %d open ports found", len(open_ports))
            return output

        except subprocess.TimeoutExpired as e:
            logger.error("Nmap scan timeout: %s", e)
            self._forensic.log_action(
                tool_name="nmap",
                action="scan",
                inputs=input_schema.model_dump(),
                outputs={},
                status="failure",
                error_message="Scan timed out after 5 minutes",
            )
            raise TimeoutError("Nmap scan timed out after 5 minutes") from e

        except Exception as e:
            logger.error("Nmap scan failed: %s", e)
            self._forensic.log_action(
                tool_name="nmap",
                action="scan",
                inputs=input_schema.model_dump(),
                outputs={},
                status="failure",
                error_message=str(e),
            )
            raise

    def _parse_xml(self, xml_output: str) -> tuple[List[int], Dict[str, str], Optional[str]]:
        """Parse nmap XML output safely.

        Args:
            xml_output: Raw XML from nmap -oX -.

        Returns:
            Tuple of (open_ports, services_dict, os_guess).
        """
        open_ports = []
        services = {}
        os_guess = None

        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError as e:
            logger.error("Failed to parse nmap XML: %s", e)
            return [], {}, None

        # Extract open ports and services
        for host in root.findall(".//host"):
            for port in host.findall(".//port[@protocol='tcp']"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    port_num = int(port.get("portid"))
                    open_ports.append(port_num)

                    # Extract service info
                    service = port.find("service")
                    if service is not None:
                        service_name = service.get("name", "unknown")
                        services[str(port_num)] = service_name

            # Extract OS guess (if available)
            for osmatch in host.findall(".//osmatch"):
                if os_guess is None:
                    os_guess = osmatch.get("name")
                    break

        open_ports.sort()
        return open_ports, services, os_guess
