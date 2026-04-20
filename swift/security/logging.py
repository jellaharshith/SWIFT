"""Forensic logging — append-only, tamper-evident audit trail."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from log.logger import get_logger

logger = get_logger()


@dataclass
class LogEntry:
    """Single audit log entry with hash chain for tamper detection."""
    entry_id: int
    timestamp: str  # ISO 8601
    tool_name: str
    action: str
    inputs: Dict[str, Any]
    outputs: Dict[str, Any]
    status: str  # "success", "failure", "denied"
    error_message: Optional[str] = None
    previous_hash: str = ""  # SHA256 of previous entry
    current_hash: str = ""   # SHA256 of this entry (computed)

    def compute_hash(self) -> str:
        """Compute SHA256 hash of this entry.

        Includes all fields except current_hash (to prevent circular dependency).
        Hash is deterministic and order-preserving.

        Returns:
            Hex-encoded SHA256 hash.
        """
        data_dict = {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp,
            "tool_name": self.tool_name,
            "action": self.action,
            "inputs": self.inputs,
            "outputs": self.outputs,
            "status": self.status,
            "error_message": self.error_message,
            "previous_hash": self.previous_hash,
        }
        data_json = json.dumps(data_dict, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(data_json.encode()).hexdigest()


class ForensicLogger:
    """Append-only, tamper-evident audit logger.

    - Every action logged: tool, action, inputs, outputs, timestamp
    - Logs are append-only (no deletion, no modification)
    - Hash chain: each entry includes hash of previous entry
    - Tamper detection: compute hash of each entry, verify against stored hash
    - JSON format, structured and queryable

    Usage:
        logger = ForensicLogger("/var/log/swift/audit.json")
        logger.log_action("api_call", "sonnet_scan", inputs={...}, outputs={...})
        entries = logger.read_entries()
        is_tampered = logger.verify_integrity()
    """

    def __init__(self, log_path: str) -> None:
        """Initialize forensic logger.

        Args:
            log_path: Path to audit log file. Parent directory created if missing.
        """
        self._log_path = Path(log_path)
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._entry_count = 0
        self._last_hash = ""

        # Load existing log to continue hash chain
        if self._log_path.exists():
            try:
                with open(self._log_path, "r") as f:
                    existing = json.load(f)
                if existing and len(existing) > 0:
                    last_entry = existing[-1]
                    self._entry_count = last_entry.get("entry_id", 0)
                    self._last_hash = last_entry.get("current_hash", "")
                    logger.debug("Loaded %d existing log entries", self._entry_count)
            except Exception as e:
                logger.error("Failed to load existing log: %s", e)
                self._entry_count = 0
                self._last_hash = ""

    def log_action(
        self,
        tool_name: str,
        action: str,
        inputs: Dict[str, Any],
        outputs: Optional[Dict[str, Any]] = None,
        status: str = "success",
        error_message: Optional[str] = None,
    ) -> LogEntry:
        """Log a tool action to forensic audit trail.

        Args:
            tool_name: Name of tool (e.g., "sonnet_scanner", "sandbox")
            action: Action performed (e.g., "analyze_line", "test_patch")
            inputs: Input parameters (will be serialized to JSON)
            outputs: Output result (will be serialized to JSON)
            status: "success", "failure", or "denied"
            error_message: Optional error message if status != "success"

        Returns:
            LogEntry that was written.
        """
        self._entry_count += 1
        timestamp = datetime.now(timezone.utc).isoformat()

        entry = LogEntry(
            entry_id=self._entry_count,
            timestamp=timestamp,
            tool_name=tool_name,
            action=action,
            inputs=inputs,
            outputs=outputs or {},
            status=status,
            error_message=error_message,
            previous_hash=self._last_hash,
        )

        # Compute hash and attach
        entry.current_hash = entry.compute_hash()
        self._last_hash = entry.current_hash

        # Append to log file (append-only)
        try:
            existing: List[Dict[str, Any]] = []
            if self._log_path.exists():
                with open(self._log_path, "r") as f:
                    existing = json.load(f)

            existing.append(asdict(entry))

            # Write atomically: write to temp, then rename
            temp_path = self._log_path.with_suffix(".tmp")
            with open(temp_path, "w") as f:
                json.dump(existing, f, indent=2, default=str)
            temp_path.replace(self._log_path)

            logger.debug(
                "Logged action: %s.%s (entry %d, status=%s)",
                tool_name, action, self._entry_count, status
            )
        except Exception as e:
            logger.error("Failed to write audit log: %s", e)

        return entry

    def read_entries(self) -> List[LogEntry]:
        """Read all log entries from file.

        Returns:
            List of LogEntry objects in chronological order.
        """
        if not self._log_path.exists():
            return []

        try:
            with open(self._log_path, "r") as f:
                data = json.load(f)
            entries = [LogEntry(**entry_dict) for entry_dict in data]
            return entries
        except Exception as e:
            logger.error("Failed to read audit log: %s", e)
            return []

    def verify_integrity(self) -> bool:
        """Verify hash chain integrity — detect tampering.

        Computes hash of each entry and verifies against stored hash.
        If any mismatch found, log was tampered with.

        Returns:
            True if log integrity verified, False if tampering detected.
        """
        entries = self.read_entries()
        if not entries:
            return True  # Empty log is not tampered

        previous_hash = ""
        for i, entry in enumerate(entries):
            # Recompute hash
            computed_hash = entry.compute_hash()

            # Verify against stored hash
            if computed_hash != entry.current_hash:
                logger.error(
                    "Hash mismatch at entry %d: computed=%s, stored=%s",
                    entry.entry_id, computed_hash[:16], entry.current_hash[:16]
                )
                return False

            # Verify hash chain
            if entry.previous_hash != previous_hash:
                logger.error(
                    "Chain broken at entry %d: expected previous_hash=%s, found=%s",
                    entry.entry_id, previous_hash[:16], entry.previous_hash[:16]
                )
                return False

            previous_hash = computed_hash

        logger.info("Audit log integrity verified (%d entries)", len(entries))
        return True

    def get_integrity_report(self) -> Dict[str, Any]:
        """Generate integrity verification report.

        Returns:
            Dict with: total_entries, verified (bool), tampered_entries (list of IDs)
        """
        entries = self.read_entries()
        tampered = []
        previous_hash = ""

        for entry in entries:
            computed = entry.compute_hash()
            if computed != entry.current_hash:
                tampered.append(entry.entry_id)
            if entry.previous_hash != previous_hash:
                tampered.append(entry.entry_id)
            previous_hash = computed

        return {
            "total_entries": len(entries),
            "verified": len(tampered) == 0,
            "tampered_entries": tampered,
        }
