"""Tests for Docker sandbox MCP tool."""
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from security.permissions import Permission, PermissionDenied, PermissionLayer
from tools.sandbox_tool import SandboxInput, SandboxOutput, SandboxTool


class TestSandboxInputValidation:
    """Test input schema validation."""

    def test_valid_input_creates_schema(self):
        """Valid input should create schema."""
        schema = SandboxInput(
            image="python:3.11-slim",
            command=["python", "script.py"],
            mounts=[],
            timeout_seconds=30,
        )
        assert schema.image == "python:3.11-slim"
        assert schema.command == ["python", "script.py"]
        assert schema.timeout_seconds == 30

    def test_empty_command_raises(self):
        """Empty command should raise."""
        with pytest.raises(ValueError, match="cannot be empty"):
            SandboxInput(command=[], timeout_seconds=30)

    def test_timeout_too_low_raises(self):
        """Timeout < 1 should raise."""
        with pytest.raises(ValueError, match="between 1 and 3600"):
            SandboxInput(command=["echo"], timeout_seconds=0)

    def test_timeout_too_high_raises(self):
        """Timeout > 3600 should raise."""
        with pytest.raises(ValueError, match="between 1 and 3600"):
            SandboxInput(command=["echo"], timeout_seconds=4000)

    def test_valid_timeouts(self):
        """Valid timeout values should work."""
        for timeout in [1, 30, 60, 3600]:
            schema = SandboxInput(command=["echo"], timeout_seconds=timeout)
            assert schema.timeout_seconds == timeout

    def test_invalid_mount_format_raises(self):
        """Invalid mount format should raise."""
        with pytest.raises(ValueError, match="Invalid mount format"):
            SandboxInput(
                command=["echo"],
                mounts=["/host:/container:rw:extra"],
            )

    def test_mount_path_must_be_approved(self):
        """Mount path must be under approved root."""
        with pytest.raises(ValueError, match="not under approved roots"):
            SandboxInput(
                command=["echo"],
                mounts=["/etc/passwd:/etc/passwd"],
            )

    def test_approved_mount_roots(self):
        """Approved mount roots should work."""
        approved_mounts = [
            "/tmp:/tmp",
            "/var/tmp:/var/tmp",
            "/home/user:/home/user:ro",
            "/opt/app:/app:rw",
        ]
        for mount in approved_mounts:
            schema = SandboxInput(command=["echo"], mounts=[mount])
            assert mount in schema.mounts


class TestSandboxOutputSchema:
    """Test output schema."""

    def test_output_schema_creates_successfully(self):
        """Output schema should create with valid data."""
        output = SandboxOutput(
            exit_code=0,
            stdout="output",
            stderr="",
            duration_ms=100,
            timed_out=False,
        )
        assert output.exit_code == 0
        assert output.timed_out is False


class TestSandboxToolPermissions:
    """Test permission enforcement."""

    def test_permission_check_on_execute(self):
        """Execute should check permission."""
        perm_layer = PermissionLayer()
        perm_layer.set_permission(Permission.TEST_PATCH, False)
        tool = SandboxTool(permission_layer=perm_layer)

        with pytest.raises(PermissionDenied):
            tool.execute(command=["echo", "test"])

    def test_permission_granted_allows_execute(self):
        """Execute with permission granted should not raise permission error."""
        perm_layer = PermissionLayer()
        tool = SandboxTool(permission_layer=perm_layer)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="test output",
                stderr="",
            )
            # Should not raise PermissionDenied
            result = tool.execute(command=["echo", "test"])
            assert isinstance(result, SandboxOutput)


class TestSandboxToolCommandBuilding:
    """Test Docker command building."""

    def test_docker_command_has_security_flags(self):
        """Docker command should have security flags."""
        perm_layer = PermissionLayer()
        tool = SandboxTool(permission_layer=perm_layer)

        cmd = tool._build_docker_command(
            "python:3.11-slim",
            ["python", "script.py"],
            [],
            None,
        )

        # Check for security flags
        assert "--rm" in cmd  # Remove after exit
        assert "--read-only" in cmd  # Read-only FS
        assert "--network=none" in cmd  # No network
        assert "--pids-limit=100" in cmd  # Limit processes
        assert "--memory=512m" in cmd  # Memory limit
        assert "--cpus=1" in cmd  # CPU limit
        assert "--security-opt=no-new-privileges:true" in cmd

    def test_docker_command_includes_image_and_command(self):
        """Docker command should include image and command."""
        perm_layer = PermissionLayer()
        tool = SandboxTool(permission_layer=perm_layer)

        cmd = tool._build_docker_command(
            "python:3.11-slim",
            ["python", "script.py"],
            [],
            None,
        )

        assert "docker" in cmd
        assert "run" in cmd
        assert "python:3.11-slim" in cmd
        assert "python" in cmd
        assert "script.py" in cmd

    def test_docker_command_with_mounts(self):
        """Docker command should include mount specifications."""
        perm_layer = PermissionLayer()
        tool = SandboxTool(permission_layer=perm_layer)

        cmd = tool._build_docker_command(
            "python:3.11-slim",
            ["python", "script.py"],
            ["/tmp/code:/code:ro"],
            None,
        )

        assert "-v" in cmd
        assert "/tmp/code:/code:ro" in cmd

    def test_docker_command_with_working_dir(self):
        """Docker command should include working directory."""
        perm_layer = PermissionLayer()
        tool = SandboxTool(permission_layer=perm_layer)

        cmd = tool._build_docker_command(
            "python:3.11-slim",
            ["python", "script.py"],
            [],
            "/app",
        )

        assert "-w" in cmd
        assert "/app" in cmd


class TestSandboxToolExecute:
    """Test sandbox execution."""

    def test_execute_success(self):
        """Successful execution should return output."""
        perm_layer = PermissionLayer()
        tool = SandboxTool(permission_layer=perm_layer)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="Hello, World!",
                stderr="",
            )
            result = tool.execute(command=["echo", "Hello, World!"])
            assert result.exit_code == 0
            assert result.stdout == "Hello, World!"
            assert result.timed_out is False

    def test_execute_with_error(self):
        """Execution with error should return error."""
        perm_layer = PermissionLayer()
        tool = SandboxTool(permission_layer=perm_layer)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="Error message",
            )
            result = tool.execute(command=["false"])
            assert result.exit_code == 1
            assert result.stderr == "Error message"

    def test_execute_with_timeout(self):
        """Execution timeout should return timeout flag."""
        perm_layer = PermissionLayer()
        tool = SandboxTool(permission_layer=perm_layer)

        with patch("subprocess.run") as mock_run:
            from subprocess import TimeoutExpired
            mock_run.side_effect = TimeoutExpired("docker", 30)
            result = tool.execute(command=["sleep", "1000"], timeout_seconds=30)
            assert result.timed_out is True
            assert result.exit_code == 124  # Timeout exit code

    def test_execute_tracks_duration(self):
        """Execution should track duration."""
        perm_layer = PermissionLayer()
        tool = SandboxTool(permission_layer=perm_layer)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="",
                stderr="",
            )
            result = tool.execute(command=["echo"])
            assert result.duration_ms >= 0

    def test_execute_with_custom_image(self):
        """Execute with custom image should use it."""
        perm_layer = PermissionLayer()
        tool = SandboxTool(permission_layer=perm_layer)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="",
                stderr="",
            )
            tool.execute(
                command=["python", "test.py"],
                image="python:3.12",
            )
            # Verify docker command was called
            cmd = mock_run.call_args[0][0]
            assert "python:3.12" in cmd

    def test_execute_with_mounts(self):
        """Execute with mounts should include them."""
        perm_layer = PermissionLayer()
        tool = SandboxTool(permission_layer=perm_layer)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="",
                stderr="",
            )
            tool.execute(
                command=["python", "test.py"],
                mounts=["/tmp/code:/code:ro"],
            )
            # Verify docker command was called
            cmd = mock_run.call_args[0][0]
            assert "-v" in cmd
            assert "/tmp/code:/code:ro" in cmd


class TestSandboxToolForensicLogging:
    """Test forensic logging."""

    def test_successful_execution_logged(self):
        """Successful execution should be logged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = str(Path(tmpdir) / "audit.json")
            perm_layer = PermissionLayer()
            tool = SandboxTool(permission_layer=perm_layer, audit_log_path=log_path)

            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout="output",
                    stderr="",
                )
                tool.execute(command=["echo", "test"])

                # Verify log entry created
                import json as json_module
                with open(log_path, "r") as f:
                    entries = json_module.load(f)
                assert len(entries) > 0
                assert entries[0]["tool_name"] == "sandbox"
                assert entries[0]["status"] == "success"

    def test_permission_denied_logged(self):
        """Permission denied should be logged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = str(Path(tmpdir) / "audit.json")
            perm_layer = PermissionLayer()
            perm_layer.set_permission(Permission.TEST_PATCH, False)
            tool = SandboxTool(permission_layer=perm_layer, audit_log_path=log_path)

            try:
                tool.execute(command=["echo", "test"])
            except PermissionDenied:
                pass

            # Verify log entry created with denied status
            import json as json_module
            with open(log_path, "r") as f:
                entries = json_module.load(f)
            assert len(entries) > 0
            assert entries[0]["status"] == "denied"
