"""Logging infrastructure for SWIFT."""
from __future__ import annotations

import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

_SECRET_PATTERNS = [
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9._\-]+"),
    re.compile(r"(?i)(api[_\-]?key|token|password|secret)[\"'\s:=]+[\"']?([A-Za-z0-9_\-]{16,})"),
]
_REDACTED = "***REDACTED***"


def _redact(text: str) -> str:
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(_REDACTED, text)
    for env_key in ("ANTHROPIC_API_KEY", "GITHUB_TOKEN", "OPENAI_API_KEY"):
        val = os.environ.get(env_key, "")
        if val and len(val) > 8 and val in text:
            text = text.replace(val, _REDACTED)
    return text


class _SecretRedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = _redact(str(record.msg))
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: _redact(str(v)) for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(_redact(str(a)) for a in record.args)
        return True


class _JSONFormatter(logging.Formatter):
    """Format log records as JSON for structured log/swift.log."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload)


class _LowercaseLevelFormatter(logging.Formatter):
    """Format logs with lowercase level names for container stdout.

    Transforms log level names from standard uppercase (INFO, WARNING, ERROR)
    to lowercase (info, warning, error) to match container log aggregation
    expectations.

    Example:
        2026-04-21 10:15:32,123 [info] swift: Scan started
        2026-04-21 10:15:33,456 [warning] swift: Retry needed
        2026-04-21 10:15:34,789 [error] swift: Fatal error

    IMPORTANT: This temporarily modifies LogRecord.levelname during formatting,
    then restores the original. Safe for multiple handlers on the same logger.
    If you have external handlers that expect standard uppercase levels,
    they will receive the restored original value.
    """

    def format(self, record: logging.LogRecord) -> str:
        # Temporarily lowercase the level name before formatting
        original_levelname = record.levelname
        record.levelname = record.levelname.lower()
        result = super().format(record)
        record.levelname = original_levelname  # Restore original
        return result


def get_logger(name: str = "swift") -> logging.Logger:
    """Return (or create) the named logger with stream + file handlers.

    Creates log/ directory if it does not exist. Uses logging.getLogger()
    so calling multiple times returns the same logger instance.

    Args:
        name: Logger name. Defaults to 'swift'.

    Returns:
        Configured Logger instance.
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger  # Already configured

    logger.setLevel(logging.DEBUG)

    # Human-readable stderr handler with lowercase levels
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(
        _LowercaseLevelFormatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )

    # JSON file handler
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "log")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "swift.log")
    file_handler = logging.FileHandler(log_path)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(_JSONFormatter())

    redact_filter = _SecretRedactingFilter()
    stream_handler.addFilter(redact_filter)
    file_handler.addFilter(redact_filter)

    logger.addHandler(stream_handler)
    logger.addHandler(file_handler)
    return logger


class MetricsCollector:
    """Collects scan metrics: cost, vulnerability count, timing.

    Intentionally NOT a singleton — each test creates a fresh instance.
    """

    def __init__(self) -> None:
        self.scan_id: Optional[str] = None
        self.repo_path: Optional[str] = None
        self.total_cost_usd: float = 0.0
        self.vulnerability_count: int = 0
        self._start_time: Optional[float] = None

    def start_scan(self, scan_id: str, repo_path: str) -> None:
        self.scan_id = scan_id
        self.repo_path = repo_path
        self._start_time = time.monotonic()

    def add_cost(self, cost: float) -> None:
        self.total_cost_usd += cost

    def record_vulnerability(self, vuln_id: str) -> None:
        self.vulnerability_count += 1

    def summary(self) -> Dict[str, Any]:
        elapsed = (
            time.monotonic() - self._start_time
            if self._start_time is not None
            else 0.0
        )
        return {
            "scan_id": self.scan_id,
            "repo_path": self.repo_path,
            "total_cost_usd": self.total_cost_usd,
            "vulnerability_count": self.vulnerability_count,
            "duration_seconds": elapsed,
        }
