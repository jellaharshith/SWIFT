"""Tests for semgrep MCP tool."""
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from security.permissions import Permission, PermissionDenied, PermissionLayer
from tools.semgrep_tool import SemgrepInput, SemgrepOutput, SemgrepTool, APPROVED_RULESETS


class TestSemgrepInputValidation:
    """Test input schema validation."""

    def test_valid_input_creates_schema(self):
        """Valid input should create schema."""
        with tempfile.TemporaryDirectory() as tmpdir:
            schema = SemgrepInput(
                repo_path=tmpdir,
                ruleset="auto",
                timeout_seconds=60,
            )
            assert schema.repo_path == tmpdir
            assert schema.ruleset == "auto"
            assert schema.timeout_seconds == 60

    def test_nonexistent_repo_path_raises(self):
        """Nonexistent repo path should raise."""
        with pytest.raises(ValueError, match="does not exist"):
            SemgrepInput(repo_path="/nonexistent/path", ruleset="auto")

    def test_invalid_ruleset_raises(self):
        """Invalid ruleset should raise."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(ValueError, match="not approved"):
                SemgrepInput(repo_path=tmpdir, ruleset="invalid-ruleset")

    def test_approved_rulesets_all_valid(self):
        """All approved rulesets should be valid."""
        with tempfile.TemporaryDirectory() as tmpdir:
            for ruleset in APPROVED_RULESETS:
                schema = SemgrepInput(repo_path=tmpdir, ruleset=ruleset)
                assert schema.ruleset == ruleset

    def test_none_timeout_is_valid(self):
        """None timeout should be valid."""
        with tempfile.TemporaryDirectory() as tmpdir:
            schema = SemgrepInput(repo_path=tmpdir, ruleset="auto", timeout_seconds=None)
            assert schema.timeout_seconds is None


class TestSemgrepOutputSchema:
    """Test output schema."""

    def test_output_schema_creates_successfully(self):
        """Output schema should create with valid data."""
        output = SemgrepOutput(
            findings=[{"rule": "test", "file": "test.py"}],
            finding_count=1,
            ruleset_used="auto",
        )
        assert output.finding_count == 1
        assert output.ruleset_used == "auto"


class TestSemgrepToolPermissions:
    """Test permission enforcement."""

    def test_permission_check_on_scan(self):
        """Scan should check permission."""
        perm_layer = PermissionLayer()
        perm_layer.set_permission(Permission.SCAN_REPO, False)
        tool = SemgrepTool(permission_layer=perm_layer)

        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(PermissionDenied):
                tool.scan(tmpdir, ruleset="auto")

    def test_permission_granted_allows_scan(self):
        """Scan with permission granted should not raise permission error."""
        perm_layer = PermissionLayer()
        tool = SemgrepTool(permission_layer=perm_layer)

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout=json.dumps({"results": []}),
                )
                # Should not raise PermissionDenied
                result = tool.scan(tmpdir, ruleset="auto")
                assert result.finding_count == 0


class TestSemgrepToolScan:
    """Test semgrep scanning."""

    def test_scan_with_empty_findings(self):
        """Scan with no findings should return empty list."""
        perm_layer = PermissionLayer()
        tool = SemgrepTool(permission_layer=perm_layer)

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout=json.dumps({"results": []}),
                )
                result = tool.scan(tmpdir, ruleset="auto")
                assert result.finding_count == 0
                assert result.findings == []

    def test_scan_with_findings(self):
        """Scan with findings should return them."""
        perm_layer = PermissionLayer()
        tool = SemgrepTool(permission_layer=perm_layer)

        findings = [
            {"rule": "sql-injection", "file": "app.py", "line": 10},
            {"rule": "hardcoded-secret", "file": "config.py", "line": 5},
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout=json.dumps({"results": findings}),
                )
                result = tool.scan(tmpdir, ruleset="auto")
                assert result.finding_count == 2
                assert len(result.findings) == 2

    def test_scan_respects_ruleset(self):
        """Scan should use specified ruleset."""
        perm_layer = PermissionLayer()
        tool = SemgrepTool(permission_layer=perm_layer)

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout=json.dumps({"results": []}),
                )
                result = tool.scan(tmpdir, ruleset="p/security-audit")
                assert result.ruleset_used == "p/security-audit"
                # Verify command included correct ruleset
                assert mock_run.call_args[0][0][3] == "p/security-audit"

    def test_scan_timeout_raises(self):
        """Scan timeout should raise TimeoutError."""
        perm_layer = PermissionLayer()
        tool = SemgrepTool(permission_layer=perm_layer)

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("subprocess.run") as mock_run:
                from subprocess import TimeoutExpired
                mock_run.side_effect = TimeoutExpired("semgrep", 10)
                with pytest.raises(TimeoutError):
                    tool.scan(tmpdir, ruleset="auto", timeout_seconds=10)

    def test_scan_invalid_json_raises(self):
        """Scan with invalid JSON output should raise."""
        perm_layer = PermissionLayer()
        tool = SemgrepTool(permission_layer=perm_layer)

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout="not valid json",
                )
                with pytest.raises(ValueError, match="not valid JSON"):
                    tool.scan(tmpdir, ruleset="auto")

    def test_scan_invalid_ruleset_raises(self):
        """Scan with invalid ruleset should raise."""
        perm_layer = PermissionLayer()
        tool = SemgrepTool(permission_layer=perm_layer)

        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(ValueError, match="not approved"):
                tool.scan(tmpdir, ruleset="invalid-ruleset")


class TestSemgrepToolForensicLogging:
    """Test forensic logging."""

    def test_successful_scan_logged(self):
        """Successful scan should be logged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = str(Path(tmpdir) / "audit.json")
            perm_layer = PermissionLayer()
            tool = SemgrepTool(permission_layer=perm_layer, audit_log_path=log_path)

            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout=json.dumps({"results": []}),
                )
                tool.scan(tmpdir, ruleset="auto")

                # Verify log entry created
                import json as json_module
                with open(log_path, "r") as f:
                    entries = json_module.load(f)
                assert len(entries) > 0
                assert entries[0]["tool_name"] == "semgrep"
                assert entries[0]["status"] == "success"

    def test_permission_denied_logged(self):
        """Permission denied should be logged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = str(Path(tmpdir) / "audit.json")
            perm_layer = PermissionLayer()
            perm_layer.set_permission(Permission.SCAN_REPO, False)
            tool = SemgrepTool(permission_layer=perm_layer, audit_log_path=log_path)

            try:
                tool.scan(tmpdir, ruleset="auto")
            except PermissionDenied:
                pass

            # Verify log entry created with denied status
            import json as json_module
            with open(log_path, "r") as f:
                entries = json_module.load(f)
            assert len(entries) > 0
            assert entries[0]["status"] == "denied"

    def test_failure_logged(self):
        """Scan failure should be logged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = str(Path(tmpdir) / "audit.json")
            perm_layer = PermissionLayer()
            tool = SemgrepTool(permission_layer=perm_layer, audit_log_path=log_path)

            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout="invalid json",
                )
                try:
                    tool.scan(tmpdir, ruleset="auto")
                except ValueError:
                    pass

            # Verify log entry created with failure status
            import json as json_module
            with open(log_path, "r") as f:
                entries = json_module.load(f)
            assert len(entries) > 0
            assert entries[0]["status"] == "failure"
