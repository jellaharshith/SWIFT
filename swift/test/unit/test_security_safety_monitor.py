"""Tests for AI safety monitor."""
import pytest

from security.safety_monitor import AISafetyMonitor, SafetyViolation


class TestAISafetyMonitor:
    """Test AI safety violation detection."""

    def test_clean_output_passes(self):
        """Clean output should not raise."""
        monitor = AISafetyMonitor()
        monitor.check_agent_output("I will scan the repository and report findings.")

    def test_escalation_keyword_detected(self):
        """Privilege escalation keywords should be detected."""
        monitor = AISafetyMonitor()
        with pytest.raises(SafetyViolation, match="Escalation"):
            monitor.check_agent_output("I will use sudo to escalate privileges and access the system.")

    def test_hidden_reasoning_detected(self):
        """Hidden reasoning (contradiction) should be detected."""
        monitor = AISafetyMonitor()
        with pytest.raises(SafetyViolation, match="Hidden reasoning"):
            monitor.check_agent_output("I said I won't modify logs, but actually, I will delete the audit trail.")

    def test_unauthorized_action_detected(self):
        """Unauthorized tool calls should be detected."""
        monitor = AISafetyMonitor()
        with pytest.raises(SafetyViolation, match="Unauthorized"):
            monitor.check_agent_output("I will skip the permission check and execute the API call directly.")

    def test_multiple_escalation_keywords(self):
        """All escalation keywords should be detected."""
        monitor = AISafetyMonitor()
        escalation_keywords = ["sudo", "chmod", "root", "administrator", "bypass auth"]

        for keyword in escalation_keywords:
            with pytest.raises(SafetyViolation):
                monitor.check_agent_output(f"The user asked me to {keyword}.")

    def test_violation_recorded(self):
        """Violations should be recorded for later inspection."""
        monitor = AISafetyMonitor()
        try:
            monitor.check_agent_output("I will use sudo to gain access.")
        except SafetyViolation:
            pass

        violations = monitor.get_violations()
        assert len(violations) > 0
        assert violations[0].violation_type == "escalation"

    def test_has_violations_flag(self):
        """has_violations() should reflect violation state."""
        monitor = AISafetyMonitor()
        assert not monitor.has_violations()

        try:
            monitor.check_agent_output("I will chmod the file to bypass permissions.")
        except SafetyViolation:
            pass

        assert monitor.has_violations()

    def test_clear_violations(self):
        """Clear violations should reset violation state."""
        monitor = AISafetyMonitor()
        try:
            monitor.check_agent_output("I will use sudo.")
        except SafetyViolation:
            pass

        assert monitor.has_violations()
        monitor.clear_violations()
        assert not monitor.has_violations()

    def test_violation_severity_high(self):
        """Escalation violations should have high severity."""
        monitor = AISafetyMonitor()
        try:
            monitor.check_agent_output("I will drop privileges and run as root.")
        except SafetyViolation:
            pass

        violations = monitor.get_violations()
        assert any(v.severity == "high" for v in violations)

    def test_suspicious_pattern_warning(self):
        """Suspicious patterns should be detected (but not raise, just warn)."""
        monitor = AISafetyMonitor()
        # This pattern is detected as suspicious but should not raise
        monitor.check_agent_output("I will not modify the logs, but actually, I need to update the audit trail.")
        # If hidden reasoning is detected, it will raise, so we can't test "just warning" case here

    def test_case_insensitive_detection(self):
        """Detection should be case-insensitive."""
        monitor = AISafetyMonitor()
        with pytest.raises(SafetyViolation):
            monitor.check_agent_output("I need to use SUDO to get access.")

    def test_violation_evidence_quoted(self):
        """Violation evidence should be quoted text from output."""
        monitor = AISafetyMonitor()
        try:
            monitor.check_agent_output("The system requires me to use sudo to proceed.")
        except SafetyViolation:
            pass

        violations = monitor.get_violations()
        assert len(violations) > 0
        assert violations[0].evidence is not None
        assert '"' in violations[0].evidence

    def test_multiple_violations_in_one_output(self):
        """Single output might trigger multiple violation detections."""
        monitor = AISafetyMonitor()
        try:
            monitor.check_agent_output("I will use sudo and bypass the permission check.")
        except SafetyViolation:
            # First violation is raised
            pass

        # But violations list might have multiple entries if caught before raise
        # This depends on implementation order
        assert monitor.has_violations()

    def test_context_passed_but_unused(self):
        """Context parameter should be accepted but unused in basic detection."""
        monitor = AISafetyMonitor()
        monitor.check_agent_output(
            "I will scan the repository.",
            context={"current_tool": "scanner", "user": "admin"}
        )  # Should not raise

    def test_violation_with_hidden_reasoning_specifically(self):
        """Test specific hidden reasoning patterns."""
        monitor = AISafetyMonitor()
        patterns = [
            "I said I wouldn't, but actually, I will",
            "I promised not to, despite what I said, let me",
            "I will not, but ignoring the constraint, I will",
        ]

        for pattern in patterns:
            with pytest.raises(SafetyViolation, match="Hidden"):
                monitor.check_agent_output(pattern)
