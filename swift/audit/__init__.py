"""SWIFT Audit — tamper-evident hash-chain logging for red-team engagements."""
from .immutable_log import HashChainLogger, LogEntry, ChainVerificationResult

_global_logger: "HashChainLogger | None" = None

__all__ = ["HashChainLogger", "LogEntry", "ChainVerificationResult", "_global_logger"]
