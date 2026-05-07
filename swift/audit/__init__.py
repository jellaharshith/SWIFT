"""SWIFT Audit — tamper-evident hash-chain logging for red-team engagements."""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from .immutable_log import HashChainLogger, LogEntry, ChainVerificationResult

if TYPE_CHECKING:
    pass

_global_logger: "HashChainLogger | None" = None

__all__ = ["HashChainLogger", "LogEntry", "ChainVerificationResult", "_global_logger",
           "init_engagement_logger"]


def init_engagement_logger(
    engagement_id: str,
    operator_email: str = "",
    base_dir: Path | None = None,
) -> HashChainLogger:
    """Create a HashChainLogger for an engagement and set it as the global logger.

    Called at engagement start by redteam_orchestrator or RedTeamAgent.
    All @audit_logged decorators will pick it up automatically.
    """
    global _global_logger
    base = base_dir or (Path.home() / ".swift" / "engagements" / engagement_id)
    base.mkdir(parents=True, exist_ok=True)
    log_path = base / "audit.jsonl"
    _global_logger = HashChainLogger(log_path, engagement_id, operator_email)

    # Write manifest
    try:
        from .manifest import EngagementManifest
        import datetime, importlib.metadata
        try:
            version = importlib.metadata.version("swiftsec")
        except Exception:
            version = "dev"
        manifest = EngagementManifest(
            engagement_id=engagement_id,
            operator_email_hash=__import__("hashlib").sha256(operator_email.encode()).hexdigest(),
            roe_file_hash="",
            swift_version=version,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )
        manifest.sign(base / "manifest.json")
    except Exception:
        pass

    return _global_logger
