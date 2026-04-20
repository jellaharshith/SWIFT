"""Permission enforcement layer — all tool calls validated before execution."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from log.logger import get_logger

logger = get_logger()


class Permission(Enum):
    """Enumeration of allowed operations."""
    SCAN_REPO = "scan_repo"              # Trigger vulnerability scan
    GENERATE_PATCHES = "generate_patches"  # Generate security patches
    TEST_PATCH = "test_patch"            # Run patch in sandbox
    READ_FILE = "read_file"              # Read source file
    WRITE_LOG = "write_log"              # Write to audit log
    API_CALL = "api_call"                # Call external API (Anthropic)


class PermissionDenied(Exception):
    """Raised when operation permission denied."""
    pass


@dataclass
class AccessControl:
    """Rules for an operation."""
    permission: Permission
    allowed: bool = True
    max_file_size_mb: Optional[int] = None  # For READ_FILE
    allowed_apis: Optional[List[str]] = None  # For API_CALL (e.g., ["claude-haiku", "claude-sonnet"])
    rate_limit_per_min: Optional[int] = None  # For API_CALL


class PermissionLayer:
    """Central permission gate for all tool operations.

    All tool calls must pass through check_permission() before execution.
    Unauthorized operations raise PermissionDenied.
    """

    def __init__(self) -> None:
        """Initialize permission layer with default rules."""
        self._rules: Dict[Permission, AccessControl] = {
            Permission.SCAN_REPO: AccessControl(
                permission=Permission.SCAN_REPO,
                allowed=True,
            ),
            Permission.GENERATE_PATCHES: AccessControl(
                permission=Permission.GENERATE_PATCHES,
                allowed=True,
            ),
            Permission.TEST_PATCH: AccessControl(
                permission=Permission.TEST_PATCH,
                allowed=True,
            ),
            Permission.READ_FILE: AccessControl(
                permission=Permission.READ_FILE,
                allowed=True,
                max_file_size_mb=100,  # Prevent reading huge files
            ),
            Permission.WRITE_LOG: AccessControl(
                permission=Permission.WRITE_LOG,
                allowed=True,
            ),
            Permission.API_CALL: AccessControl(
                permission=Permission.API_CALL,
                allowed=True,
                allowed_apis=["claude-haiku-4-5-20251001", "claude-sonnet-4-6"],
                rate_limit_per_min=100,
            ),
        }
        self._denial_count: Dict[str, int] = {}  # Track denials per operation

    def check_permission(
        self,
        permission: Permission,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Check if operation is allowed.

        Args:
            permission: Operation being requested.
            context: Optional context (e.g., {"file_size_mb": 50, "model": "claude-haiku"}).

        Raises:
            PermissionDenied: If operation not allowed.
        """
        context = context or {}
        rule = self._rules.get(permission)

        if rule is None:
            logger.error("Unknown permission: %s", permission)
            raise PermissionDenied(f"Unknown permission: {permission}")

        if not rule.allowed:
            logger.warning("Permission denied: %s (disabled)", permission)
            self._denial_count[permission.value] = self._denial_count.get(permission.value, 0) + 1
            raise PermissionDenied(f"Permission denied: {permission.value}")

        # Enforce constraints based on context
        if permission == Permission.READ_FILE and rule.max_file_size_mb:
            file_size_mb = context.get("file_size_mb", 0)
            if file_size_mb > rule.max_file_size_mb:
                logger.error(
                    "File too large: %d MB > %d MB limit",
                    file_size_mb, rule.max_file_size_mb
                )
                raise PermissionDenied(
                    f"File too large: {file_size_mb}MB exceeds {rule.max_file_size_mb}MB limit"
                )

        if permission == Permission.API_CALL and rule.allowed_apis:
            model = context.get("model", "unknown")
            if model not in rule.allowed_apis:
                logger.error("API call denied for model: %s", model)
                raise PermissionDenied(f"Model {model} not in allowed list: {rule.allowed_apis}")

        logger.debug("Permission granted: %s", permission)

    def set_permission(self, permission: Permission, allowed: bool) -> None:
        """Enable or disable a permission.

        Args:
            permission: Operation to enable/disable.
            allowed: True to allow, False to deny.
        """
        if permission not in self._rules:
            logger.error("Unknown permission: %s", permission)
            return

        self._rules[permission].allowed = allowed
        logger.info("Permission %s set to %s", permission.value, allowed)

    def wrap_tool_call(self, permission: Permission, context: Optional[Dict[str, Any]] = None) -> Callable:
        """Decorator to wrap a tool call with permission check.

        Usage:
            @permission_layer.wrap_tool_call(Permission.API_CALL, {"model": "claude-sonnet-4-6"})
            def call_sonnet(prompt):
                ...

        Args:
            permission: Required permission.
            context: Context for permission evaluation.

        Returns:
            Decorator function.
        """
        def decorator(func: Callable) -> Callable:
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                self.check_permission(permission, context)
                return func(*args, **kwargs)
            return wrapper
        return decorator

    def denial_summary(self) -> Dict[str, int]:
        """Get count of permission denials by operation.

        Returns:
            Dict mapping operation name to denial count.
        """
        return self._denial_count.copy()
