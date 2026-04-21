"""Tests for nmap MCP tool."""
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from security.permissions import Permission, PermissionDenied, PermissionLayer
from tools.nmap_tool import NmapInput, NmapOutput, NmapTool


class TestNmapInputValidation:
    """Test input schema validation."""

    def test_valid_input_creates_schema(self):
        """Valid input should create schema."""
        schema = NmapInput(
            target="192.168.1.1",
            ports="1-1000",
            mode="basic",
            host_timeout="30s",
        )
        assert schema.target == "192.168.1.1"
        assert schema.ports == "1-1000"
        assert schema.mode == "basic"

    def test_empty_target_raises(self):
        """Empty target should raise."""
        with pytest.raises(ValueError, match="cannot be empty"):
            NmapInput(target="", ports="1-1000")

    def test_invalid_characters_in_target_raises(self):
        """Invalid characters in target should raise."""
        with pytest.raises(ValueError, match="invalid characters"):
            NmapInput(target="target<script>", ports="1-1000")

    def test_valid_targets(self):
        """Various valid targets should work."""
        valid_targets = [
            "192.168.1.1",
            "example.com",
            "example.com/24",
            "host-name",
            "10.0.0.0/8",
        ]
        for target in valid_targets:
            schema = NmapInput(target=target, ports="1-1000")
            assert schema.target == target

    def test_invalid_ports_raises(self):
        """Invalid port specification should raise."""
        with pytest.raises(ValueError, match="must be numbers"):
            NmapInput(target="localhost", ports="abc")

    def test_valid_ports(self):
        """Various valid port specs should work."""
        valid_ports = ["1-1000", "22,80,443", "1-65535"]
        for ports in valid_ports:
            schema = NmapInput(target="localhost", ports=ports)
            assert schema.ports == ports

    def test_invalid_timeout_raises(self):
        """Invalid timeout format should raise."""
        with pytest.raises(ValueError, match="must be"):
            NmapInput(target="localhost", ports="1-1000", host_timeout="invalid")

    def test_valid_timeouts(self):
        """Various valid timeout formats should work."""
        valid_timeouts = ["30s", "5m", "1h"]
        for timeout in valid_timeouts:
            schema = NmapInput(
                target="localhost",
                ports="1-1000",
                host_timeout=timeout,
            )
            assert schema.host_timeout == timeout


class TestNmapOutputSchema:
    """Test output schema."""

    def test_output_schema_creates_successfully(self):
        """Output schema should create with valid data."""
        output = NmapOutput(
            target="192.168.1.1",
            open_ports=[22, 80, 443],
            services={"22": "ssh", "80": "http", "443": "https"},
            os_guess="Linux",
            raw_output="nmap output",
        )
        assert output.target == "192.168.1.1"
        assert len(output.open_ports) == 3


class TestNmapToolPermissions:
    """Test permission enforcement."""

    def test_permission_check_on_scan(self):
        """Scan should check permission."""
        perm_layer = PermissionLayer()
        perm_layer.set_permission(Permission.SCAN_REPO, False)
        tool = NmapTool(permission_layer=perm_layer)

        with pytest.raises(PermissionDenied):
            tool.scan("192.168.1.1")

    def test_permission_granted_allows_scan(self):
        """Scan with permission granted should not raise permission error."""
        perm_layer = PermissionLayer()
        tool = NmapTool(permission_layer=perm_layer)

        xml_output = """<?xml version="1.0"?>
        <nmaprun scanner="nmap" args="test" start="1234567890" startstr="test" version="7.92">
            <host start="1" startstr="test" end="1" endstr="test">
                <ports>
                    <port protocol="tcp" portid="80">
                        <state state="open" reason="syn-ack" reason_ttl="0"/>
                        <service name="http"/>
                    </port>
                </ports>
            </host>
        </nmaprun>"""

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=xml_output,
            )
            # Should not raise PermissionDenied
            result = tool.scan("192.168.1.1")
            assert isinstance(result, NmapOutput)


class TestNmapToolCommandBuilding:
    """Test nmap command building."""

    def test_basic_mode_command(self):
        """Basic mode should use -sS."""
        perm_layer = PermissionLayer()
        tool = NmapTool(permission_layer=perm_layer)

        cmd = tool._build_command("localhost", "1-1000", "basic", "30s")
        assert "nmap" in cmd
        assert "-sS" in cmd
        assert "-sV" not in cmd  # Service detection not in basic
        assert "localhost" in cmd
        assert "-p" in cmd
        assert "1-1000" in cmd

    def test_service_mode_command(self):
        """Service mode should use -sS and -sV."""
        perm_layer = PermissionLayer()
        tool = NmapTool(permission_layer=perm_layer)

        cmd = tool._build_command("localhost", "1-1000", "service", "30s")
        assert "-sS" in cmd
        assert "-sV" in cmd
        assert "-O" not in cmd  # OS detection not in service

    def test_os_mode_command(self):
        """OS mode should use -sS, -O, and -sV."""
        perm_layer = PermissionLayer()
        tool = NmapTool(permission_layer=perm_layer)

        cmd = tool._build_command("localhost", "1-1000", "os", "30s")
        assert "-sS" in cmd
        assert "-O" in cmd
        assert "-sV" in cmd

    def test_command_has_required_flags(self):
        """Command should always have safety flags."""
        perm_layer = PermissionLayer()
        tool = NmapTool(permission_layer=perm_layer)

        cmd = tool._build_command("localhost", "1-1000", "basic", "30s")
        assert "--open" in cmd  # Only open ports
        assert "-T2" in cmd  # Polite timing
        assert "-oX" in cmd  # XML output
        assert "--host-timeout" in cmd


class TestNmapToolScan:
    """Test nmap scanning."""

    def test_scan_with_no_open_ports(self):
        """Scan with no open ports should return empty list."""
        perm_layer = PermissionLayer()
        tool = NmapTool(permission_layer=perm_layer)

        xml_output = """<?xml version="1.0"?>
        <nmaprun>
            <host>
                <ports/>
            </host>
        </nmaprun>"""

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=xml_output,
            )
            result = tool.scan("192.168.1.1")
            assert result.open_ports == []

    def test_scan_with_open_ports(self):
        """Scan with open ports should return them."""
        perm_layer = PermissionLayer()
        tool = NmapTool(permission_layer=perm_layer)

        xml_output = """<?xml version="1.0"?>
        <nmaprun>
            <host>
                <ports>
                    <port protocol="tcp" portid="22">
                        <state state="open"/>
                        <service name="ssh"/>
                    </port>
                    <port protocol="tcp" portid="80">
                        <state state="open"/>
                        <service name="http"/>
                    </port>
                    <port protocol="tcp" portid="443">
                        <state state="open"/>
                        <service name="https"/>
                    </port>
                </ports>
            </host>
        </nmaprun>"""

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=xml_output,
            )
            result = tool.scan("192.168.1.1")
            assert result.open_ports == [22, 80, 443]
            assert result.services == {"22": "ssh", "80": "http", "443": "https"}

    def test_scan_with_closed_ports_ignored(self):
        """Scan should ignore closed ports."""
        perm_layer = PermissionLayer()
        tool = NmapTool(permission_layer=perm_layer)

        xml_output = """<?xml version="1.0"?>
        <nmaprun>
            <host>
                <ports>
                    <port protocol="tcp" portid="22">
                        <state state="open"/>
                        <service name="ssh"/>
                    </port>
                    <port protocol="tcp" portid="23">
                        <state state="closed"/>
                        <service name="telnet"/>
                    </port>
                </ports>
            </host>
        </nmaprun>"""

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=xml_output,
            )
            result = tool.scan("192.168.1.1")
            assert result.open_ports == [22]

    def test_scan_with_os_detection(self):
        """Scan with OS mode should detect OS."""
        perm_layer = PermissionLayer()
        tool = NmapTool(permission_layer=perm_layer)

        xml_output = """<?xml version="1.0"?>
        <nmaprun>
            <host>
                <ports/>
                <osmatch name="Linux 5.x - 6.x" accuracy="95"/>
            </host>
        </nmaprun>"""

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=xml_output,
            )
            result = tool.scan("192.168.1.1", mode="os")
            assert result.os_guess == "Linux 5.x - 6.x"

    def test_scan_timeout_raises(self):
        """Scan timeout should raise TimeoutError."""
        perm_layer = PermissionLayer()
        tool = NmapTool(permission_layer=perm_layer)

        with patch("subprocess.run") as mock_run:
            from subprocess import TimeoutExpired
            mock_run.side_effect = TimeoutExpired("nmap", 300)
            with pytest.raises(TimeoutError):
                tool.scan("192.168.1.1")


class TestNmapToolForensicLogging:
    """Test forensic logging."""

    def test_successful_scan_logged(self):
        """Successful scan should be logged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = str(Path(tmpdir) / "audit.json")
            perm_layer = PermissionLayer()
            tool = NmapTool(permission_layer=perm_layer, audit_log_path=log_path)

            xml_output = """<?xml version="1.0"?>
            <nmaprun>
                <host>
                    <ports/>
                </host>
            </nmaprun>"""

            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout=xml_output,
                )
                tool.scan("192.168.1.1")

                # Verify log entry created
                import json as json_module
                with open(log_path, "r") as f:
                    entries = json_module.load(f)
                assert len(entries) > 0
                assert entries[0]["tool_name"] == "nmap"
                assert entries[0]["status"] == "success"

    def test_permission_denied_logged(self):
        """Permission denied should be logged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = str(Path(tmpdir) / "audit.json")
            perm_layer = PermissionLayer()
            perm_layer.set_permission(Permission.SCAN_REPO, False)
            tool = NmapTool(permission_layer=perm_layer, audit_log_path=log_path)

            try:
                tool.scan("192.168.1.1")
            except PermissionDenied:
                pass

            # Verify log entry created with denied status
            import json as json_module
            with open(log_path, "r") as f:
                entries = json_module.load(f)
            assert len(entries) > 0
            assert entries[0]["status"] == "denied"
