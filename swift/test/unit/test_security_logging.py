"""Tests for forensic append-only logging."""
import json
import tempfile
from pathlib import Path

import pytest

from security.logging import ForensicLogger, LogEntry


class TestForensicLogger:
    """Test append-only forensic logging."""

    @pytest.fixture
    def temp_log_file(self):
        """Create temp log file for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.json"
            yield str(log_path)

    def test_log_action_creates_entry(self, temp_log_file):
        """Log action should create and persist entry."""
        logger = ForensicLogger(temp_log_file)
        entry = logger.log_action(
            "sonnet_scanner",
            "analyze_line",
            inputs={"file": "app.py", "line": 42},
            outputs={"confidence": 0.97},
            status="success",
        )
        assert entry.entry_id == 1
        assert entry.tool_name == "sonnet_scanner"
        assert entry.action == "analyze_line"

    def test_log_action_persists_to_file(self, temp_log_file):
        """Log entry should be written to file."""
        logger = ForensicLogger(temp_log_file)
        logger.log_action("test_tool", "test_action", inputs={}, outputs={})

        # Verify file exists and contains entry
        with open(temp_log_file, "r") as f:
            data = json.load(f)
        assert len(data) == 1
        assert data[0]["tool_name"] == "test_tool"

    def test_log_entry_ids_increment(self, temp_log_file):
        """Entry IDs should increment sequentially."""
        logger = ForensicLogger(temp_log_file)
        entry1 = logger.log_action("tool1", "action1", inputs={}, outputs={})
        entry2 = logger.log_action("tool2", "action2", inputs={}, outputs={})
        entry3 = logger.log_action("tool3", "action3", inputs={}, outputs={})

        assert entry1.entry_id == 1
        assert entry2.entry_id == 2
        assert entry3.entry_id == 3

    def test_hash_chain_integrity(self, temp_log_file):
        """Each entry's previous_hash should match previous entry's current_hash."""
        logger = ForensicLogger(temp_log_file)
        entry1 = logger.log_action("tool1", "action1", inputs={}, outputs={})
        entry2 = logger.log_action("tool2", "action2", inputs={}, outputs={})

        assert entry1.previous_hash == ""  # First entry has no previous
        assert entry2.previous_hash == entry1.current_hash

    def test_log_hash_is_deterministic(self, temp_log_file):
        """Same entry content should produce same hash."""
        entry = LogEntry(
            entry_id=1,
            timestamp="2026-04-20T00:00:00Z",
            tool_name="tool",
            action="action",
            inputs={"x": 1},
            outputs={"y": 2},
            status="success",
            error_message=None,
            previous_hash="",
        )
        hash1 = entry.compute_hash()
        hash2 = entry.compute_hash()
        assert hash1 == hash2

    def test_verify_integrity_detects_tampering(self, temp_log_file):
        """Integrity check should detect modified entries."""
        logger = ForensicLogger(temp_log_file)
        logger.log_action("tool1", "action1", inputs={}, outputs={})

        # Tamper with log file
        with open(temp_log_file, "r") as f:
            data = json.load(f)
        data[0]["tool_name"] = "tampered_tool"  # Modify entry
        with open(temp_log_file, "w") as f:
            json.dump(data, f)

        # Verify integrity should fail
        logger2 = ForensicLogger(temp_log_file)
        assert not logger2.verify_integrity()

    def test_verify_integrity_passes_clean_log(self, temp_log_file):
        """Integrity check should pass clean log."""
        logger = ForensicLogger(temp_log_file)
        logger.log_action("tool1", "action1", inputs={}, outputs={})
        logger.log_action("tool2", "action2", inputs={}, outputs={})

        logger2 = ForensicLogger(temp_log_file)
        assert logger2.verify_integrity()

    def test_read_entries_returns_all(self, temp_log_file):
        """Read entries should return all logged entries."""
        logger = ForensicLogger(temp_log_file)
        logger.log_action("tool1", "action1", inputs={}, outputs={})
        logger.log_action("tool2", "action2", inputs={}, outputs={})
        logger.log_action("tool3", "action3", inputs={}, outputs={})

        entries = logger.read_entries()
        assert len(entries) == 3
        assert entries[0].entry_id == 1
        assert entries[1].entry_id == 2
        assert entries[2].entry_id == 3

    def test_integrity_report_counts_tampered(self, temp_log_file):
        """Integrity report should list tampered entry IDs."""
        logger = ForensicLogger(temp_log_file)
        logger.log_action("tool1", "action1", inputs={}, outputs={})

        # Tamper
        with open(temp_log_file, "r") as f:
            data = json.load(f)
        data[0]["action"] = "tampered"
        with open(temp_log_file, "w") as f:
            json.dump(data, f)

        logger2 = ForensicLogger(temp_log_file)
        report = logger2.get_integrity_report()
        assert not report["verified"]
        assert 1 in report["tampered_entries"]

    def test_log_preserves_error_messages(self, temp_log_file):
        """Log should preserve error message for failed actions."""
        logger = ForensicLogger(temp_log_file)
        entry = logger.log_action(
            "tool",
            "action",
            inputs={},
            outputs={},
            status="failure",
            error_message="Database connection timeout",
        )
        assert entry.error_message == "Database connection timeout"
        assert entry.status == "failure"

    def test_load_existing_log_continues_sequence(self, temp_log_file):
        """Loading existing log should continue entry sequence."""
        logger1 = ForensicLogger(temp_log_file)
        entry1 = logger1.log_action("tool1", "action1", inputs={}, outputs={})

        # Create new logger instance, should load existing log
        logger2 = ForensicLogger(temp_log_file)
        entry2 = logger2.log_action("tool2", "action2", inputs={}, outputs={})

        assert entry1.entry_id == 1
        assert entry2.entry_id == 2
        assert entry2.previous_hash == entry1.current_hash
