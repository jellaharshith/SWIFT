"""Tests for permission enforcement layer."""
import pytest
from security.permissions import Permission, PermissionDenied, PermissionLayer


class TestPermissionLayer:
    """Test permission enforcement."""

    def test_all_permissions_granted_by_default(self):
        """All permissions should be allowed by default."""
        layer = PermissionLayer()
        for perm in Permission:
            context = {}
            # API_CALL requires model context
            if perm == Permission.API_CALL:
                context = {"model": "claude-sonnet-4-6"}
            layer.check_permission(perm, context)  # Should not raise

    def test_permission_can_be_denied(self):
        """Permission can be disabled."""
        layer = PermissionLayer()
        layer.set_permission(Permission.API_CALL, False)
        with pytest.raises(PermissionDenied):
            layer.check_permission(Permission.API_CALL)

    def test_permission_can_be_re_enabled(self):
        """Denied permission can be re-enabled."""
        layer = PermissionLayer()
        layer.set_permission(Permission.SCAN_REPO, False)
        with pytest.raises(PermissionDenied):
            layer.check_permission(Permission.SCAN_REPO)

        layer.set_permission(Permission.SCAN_REPO, True)
        layer.check_permission(Permission.SCAN_REPO)  # Should not raise

    def test_unknown_permission_raises(self):
        """Unknown permission should raise."""
        from enum import Enum
        class FakePermission(Enum):
            FAKE = "fake"

        layer = PermissionLayer()
        with pytest.raises(PermissionDenied):
            layer.check_permission(FakePermission.FAKE)

    def test_file_size_limit_enforced(self):
        """READ_FILE permission enforces file size limit."""
        layer = PermissionLayer()
        # Default limit is 100MB
        layer.check_permission(Permission.READ_FILE, {"file_size_mb": 50})  # Under limit
        with pytest.raises(PermissionDenied):
            layer.check_permission(Permission.READ_FILE, {"file_size_mb": 150})  # Over limit

    def test_api_call_model_whitelist(self):
        """API_CALL permission enforces model whitelist."""
        layer = PermissionLayer()
        layer.check_permission(Permission.API_CALL, {"model": "claude-sonnet-4-6"})  # Allowed
        with pytest.raises(PermissionDenied):
            layer.check_permission(Permission.API_CALL, {"model": "gpt-4"})  # Not allowed

    def test_denial_count_tracked(self):
        """Track count of permission denials."""
        layer = PermissionLayer()
        layer.set_permission(Permission.SCAN_REPO, False)

        for _ in range(3):
            try:
                layer.check_permission(Permission.SCAN_REPO)
            except PermissionDenied:
                pass

        summary = layer.denial_summary()
        assert summary.get("scan_repo") == 3

    def test_wrap_tool_call_decorator(self):
        """Decorator wraps function with permission check."""
        layer = PermissionLayer()
        layer.set_permission(Permission.API_CALL, False)

        @layer.wrap_tool_call(Permission.API_CALL)
        def my_api_call():
            return "success"

        with pytest.raises(PermissionDenied):
            my_api_call()

    def test_decorator_allows_permitted_call(self):
        """Decorator allows permitted call."""
        layer = PermissionLayer()

        @layer.wrap_tool_call(Permission.SCAN_REPO)
        def my_scan():
            return "scanned"

        result = my_scan()
        assert result == "scanned"
