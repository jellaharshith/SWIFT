"""Tests for Cuckoo MCP tool."""
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from security.permissions import Permission, PermissionDenied, PermissionLayer
from tools.cuckoo_tool import CuckooInput, CuckooOutput, CuckooTool, ALLOWED_OPERATIONS


class TestCuckooInputValidation:
    """Test input schema validation."""

    def test_valid_submit_file_input(self):
        """Valid submit_file input should create schema."""
        schema = CuckooInput(
            operation="submit_file",
            file_path="/tmp/test.bin",
        )
        assert schema.operation == "submit_file"
        assert schema.file_path == "/tmp/test.bin"

    def test_valid_get_report_input(self):
        """Valid get_report input should create schema."""
        schema = CuckooInput(
            operation="get_report",
            task_id=42,
        )
        assert schema.operation == "get_report"
        assert schema.task_id == 42

    def test_invalid_operation_raises(self):
        """Invalid operation should raise."""
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            CuckooInput(operation="delete", task_id=1)

    def test_submit_file_without_path_raises(self):
        """submit_file without file_path should raise."""
        schema = CuckooInput(operation="submit_file")
        with pytest.raises(ValueError, match="requires file_path"):
            schema.validate_operation_args()

    def test_get_report_without_task_id_raises(self):
        """get_report without task_id should raise."""
        schema = CuckooInput(operation="get_report")
        with pytest.raises(ValueError, match="requires task_id"):
            schema.validate_operation_args()

    def test_all_allowed_operations_valid(self):
        """All allowed operations should be valid."""
        for op in ALLOWED_OPERATIONS:
            schema = CuckooInput(operation=op, task_id=1, file_path="/tmp/test")
            assert schema.operation == op


class TestCuckooOutputSchema:
    """Test output schema."""

    def test_output_schema_creates_successfully(self):
        """Output schema should create with valid data."""
        output = CuckooOutput(
            operation="submit_file",
            success=True,
            data={"task_id": 42},
            message="File submitted",
        )
        assert output.operation == "submit_file"
        assert output.success is True
        assert output.data["task_id"] == 42


class TestCuckooToolPermissions:
    """Test permission enforcement."""

    def test_permission_check_on_execute(self):
        """Execute should check permission."""
        perm_layer = PermissionLayer()
        perm_layer.set_permission(Permission.API_CALL, False)
        tool = CuckooTool(permission_layer=perm_layer)

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.bin"
            test_file.write_bytes(b"test content")

            with pytest.raises(PermissionDenied):
                tool.execute("submit_file", file_path=str(test_file))

    def test_permission_granted_allows_execute(self):
        """Execute with permission granted should not raise permission error."""
        perm_layer = PermissionLayer()
        tool = CuckooTool(permission_layer=perm_layer)

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.bin"
            test_file.write_bytes(b"test content")

            with patch("requests.post") as mock_post:
                mock_post.return_value = MagicMock(
                    json=lambda: {"task_id": 42},
                )
                # Should not raise PermissionDenied
                result = tool.execute("submit_file", file_path=str(test_file))
                assert result.success is True


class TestCuckooToolSubmitFile:
    """Test submit_file operation."""

    def test_submit_file_success(self):
        """Submit file should succeed and return task ID."""
        perm_layer = PermissionLayer()
        tool = CuckooTool(permission_layer=perm_layer)

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.bin"
            test_file.write_bytes(b"malware")

            with patch("requests.post") as mock_post:
                mock_post.return_value = MagicMock(
                    json=lambda: {"task_id": 42},
                )
                result = tool.execute("submit_file", file_path=str(test_file))
                assert result.success is True
                assert result.operation == "submit_file"
                assert result.data["task_id"] == 42

    def test_submit_nonexistent_file_raises(self):
        """Submit nonexistent file should raise."""
        perm_layer = PermissionLayer()
        tool = CuckooTool(permission_layer=perm_layer)

        with pytest.raises(FileNotFoundError):
            tool.execute("submit_file", file_path="/nonexistent/file.bin")

    def test_submit_file_api_error(self):
        """Submit file API error should raise."""
        perm_layer = PermissionLayer()
        tool = CuckooTool(permission_layer=perm_layer)

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.bin"
            test_file.write_bytes(b"test")

            with patch("requests.post") as mock_post:
                mock_post.side_effect = requests.RequestException("API error")
                with pytest.raises(requests.RequestException):
                    tool.execute("submit_file", file_path=str(test_file))


class TestCuckooToolGetReport:
    """Test get_report operation."""

    def test_get_report_success(self):
        """Get report should succeed and return report."""
        perm_layer = PermissionLayer()
        tool = CuckooTool(permission_layer=perm_layer)

        report_data = {
            "info": {"status": "reported", "score": 8.5},
            "behavior": {"processes": []},
        }

        with patch("requests.get") as mock_get:
            mock_get.return_value = MagicMock(
                json=lambda: report_data,
            )
            result = tool.execute("get_report", task_id=42)
            assert result.success is True
            assert result.operation == "get_report"
            assert result.data["info"]["score"] == 8.5

    def test_get_report_api_error(self):
        """Get report API error should raise."""
        perm_layer = PermissionLayer()
        tool = CuckooTool(permission_layer=perm_layer)

        with patch("requests.get") as mock_get:
            mock_get.side_effect = requests.RequestException("API error")
            with pytest.raises(requests.RequestException):
                tool.execute("get_report", task_id=42)


class TestCuckooToolGetStatus:
    """Test get_status operation."""

    def test_get_status_success(self):
        """Get status should succeed and return status."""
        perm_layer = PermissionLayer()
        tool = CuckooTool(permission_layer=perm_layer)

        task_data = {
            "task": {"status": "reported", "id": 42},
        }

        with patch("requests.get") as mock_get:
            mock_get.return_value = MagicMock(
                json=lambda: task_data,
            )
            result = tool.execute("get_status", task_id=42)
            assert result.success is True
            assert result.operation == "get_status"
            assert "reported" in result.message

    def test_get_status_api_error(self):
        """Get status API error should raise."""
        perm_layer = PermissionLayer()
        tool = CuckooTool(permission_layer=perm_layer)

        with patch("requests.get") as mock_get:
            mock_get.side_effect = requests.RequestException("API error")
            with pytest.raises(requests.RequestException):
                tool.execute("get_status", task_id=42)


class TestCuckooToolListTasks:
    """Test list_tasks operation."""

    def test_list_tasks_success(self):
        """List tasks should succeed and return tasks."""
        perm_layer = PermissionLayer()
        tool = CuckooTool(permission_layer=perm_layer)

        tasks_data = {
            "tasks": [
                {"id": 1, "status": "completed"},
                {"id": 2, "status": "reported"},
            ],
        }

        with patch("requests.get") as mock_get:
            mock_get.return_value = MagicMock(
                json=lambda: tasks_data,
            )
            result = tool.execute("list_tasks")
            assert result.success is True
            assert result.operation == "list_tasks"
            assert len(result.data["tasks"]) == 2

    def test_list_tasks_api_error(self):
        """List tasks API error should raise."""
        perm_layer = PermissionLayer()
        tool = CuckooTool(permission_layer=perm_layer)

        with patch("requests.get") as mock_get:
            mock_get.side_effect = requests.RequestException("API error")
            with pytest.raises(requests.RequestException):
                tool.execute("list_tasks")


class TestCuckooToolForensicLogging:
    """Test forensic logging."""

    def test_successful_operation_logged(self):
        """Successful operation should be logged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = str(Path(tmpdir) / "audit.json")
            perm_layer = PermissionLayer()
            tool = CuckooTool(permission_layer=perm_layer, audit_log_path=log_path)

            test_file = Path(tmpdir) / "test.bin"
            test_file.write_bytes(b"test")

            with patch("requests.post") as mock_post:
                mock_post.return_value = MagicMock(
                    json=lambda: {"task_id": 42},
                )
                tool.execute("submit_file", file_path=str(test_file))

                # Verify log entry created
                import json as json_module
                with open(log_path, "r") as f:
                    entries = json_module.load(f)
                assert len(entries) > 0
                assert entries[0]["tool_name"] == "cuckoo"
                assert entries[0]["status"] == "success"

    def test_permission_denied_logged(self):
        """Permission denied should be logged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = str(Path(tmpdir) / "audit.json")
            perm_layer = PermissionLayer()
            perm_layer.set_permission(Permission.API_CALL, False)
            tool = CuckooTool(permission_layer=perm_layer, audit_log_path=log_path)

            test_file = Path(tmpdir) / "test.bin"
            test_file.write_bytes(b"test")

            try:
                tool.execute("submit_file", file_path=str(test_file))
            except PermissionDenied:
                pass

            # Verify log entry created with denied status
            import json as json_module
            with open(log_path, "r") as f:
                entries = json_module.load(f)
            assert len(entries) > 0
            assert entries[0]["status"] == "denied"
