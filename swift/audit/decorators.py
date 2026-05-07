"""Decorators for audit logging around probe execution."""
import functools
import time
from typing import Callable, Any


def audit_logged(event_type: str) -> Callable:
    """Wrap an async probe method with start/end/error audit log entries.

    Reads _global_logger from audit package at call time (not import time),
    so it works even when logger is set after import.
    If _global_logger is None, the probe runs without logging (graceful degradation).

    Args:
        event_type: The base event type string (e.g. "probe_executed").

    Returns:
        Decorator that wraps async probe methods.
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        async def wrapper(self: Any, target: Any, session: Any = None, *args: Any, **kwargs: Any) -> Any:
            import audit as _audit_pkg  # late import to pick up runtime _global_logger
            logger = _audit_pkg._global_logger
            probe_name = getattr(self, "name", fn.__name__)
            target_str = str(target)

            t0 = time.perf_counter()
            if logger:
                await logger.log(
                    f"{event_type}_start",
                    {"probe": probe_name, "target": target_str},
                )
            try:
                result = await fn(self, target, session, *args, **kwargs)
                duration_ms = int((time.perf_counter() - t0) * 1000)
                if logger:
                    await logger.log(
                        f"{event_type}_end",
                        {
                            "probe": probe_name,
                            "duration_ms": duration_ms,
                            "finding_count": len(result or []),
                        },
                    )
                return result
            except Exception as exc:
                if logger:
                    await logger.log(
                        f"{event_type}_error",
                        {"probe": probe_name, "error": type(exc).__name__},
                    )
                raise

        return wrapper
    return decorator
