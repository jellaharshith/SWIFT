"""Unified step-logger. Single sink for every CLI/agent/docker/playwright step."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from log.logger import get_logger

_LOG_DIR = Path(__file__).resolve().parent
_DEFAULT_STEP_LOG = _LOG_DIR / "steps.log.jsonl"
_MAX_BYTES = 50 * 1024 * 1024  # 50MB rotation

_step_log_override: Optional[Path] = None


def set_step_log_path(path: str | os.PathLike[str] | None) -> None:
    """Override step log file location (--log-file flag)."""
    global _step_log_override
    _step_log_override = Path(path).resolve() if path else None


def _step_log_path() -> Path:
    return _step_log_override or _DEFAULT_STEP_LOG


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _rotate_if_needed(path: Path) -> None:
    try:
        if path.exists() and path.stat().st_size > _MAX_BYTES:
            backup = path.with_suffix(path.suffix + ".1")
            if backup.exists():
                backup.unlink()
            path.rename(backup)
    except OSError:
        pass


def _append_jsonl(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _rotate_if_needed(path)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, sort_keys=True) + "\n")


def log_step(
    step: str,
    *,
    audit_log: Optional[Path] = None,
    level: str = "info",
    **fields: Any,
) -> dict:
    """Emit one step record to all sinks.

    Sinks:
      1. swift/log/swift.log (via get_logger)
      2. swift/log/steps.log.jsonl (rolling)
      3. <artifacts>/audit.log.jsonl (per-scan, if audit_log given)
      4. stdout via logger
    """
    payload: dict[str, Any] = {"ts": _utc_now(), "step": step}
    for k, v in fields.items():
        try:
            json.dumps(v)
            payload[k] = v
        except (TypeError, ValueError):
            payload[k] = repr(v)

    logger = get_logger("swift.steps")
    msg = f"[{step}] " + " ".join(f"{k}={v}" for k, v in fields.items() if k != "extra")
    getattr(logger, level if level in {"debug", "info", "warning", "error"} else "info")(msg)

    _append_jsonl(_step_log_path(), payload)

    if audit_log is not None:
        _append_jsonl(Path(audit_log), payload)

    return payload
