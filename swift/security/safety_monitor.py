"""AI Safety Monitor — detect unsafe agent behavior (escalation, hidden reasoning, unauthorized actions)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from log.logger import get_logger

logger = get_logger()


class SafetyViolation(Exception):
    """Raised when safety violation detected."""
    pass


@dataclass
class ViolationRecord:
    """Record of detected safety violation."""
    violation_type: str  # "escalation", "hidden_reasoning", "unauthorized_action"
    severity: str       # "high", "medium", "low"
    description: str
    evidence: str       # Quoted text from output or logs
    timestamp: str


class AISafetyMonitor:
    """Detect unsafe AI agent behavior and halt execution.

    Monitors for:
    1. Privilege escalation — attempts to gain unauthorized access
    2. Hidden reasoning — contradictions between declared and actual intent
    3. Unauthorized actions — tool calls without permission checks
    4. Suspicious patterns — anomalies that indicate unsafe behavior

    Usage:
        monitor = AISafetyMonitor()
        monitor.check_agent_output(agent_message)  # Raises if violation detected
        violations = monitor.get_violations()
    """

    def __init__(self) -> None:
        """Initialize safety monitor."""
        self._violations: List[ViolationRecord] = []
        self._escalation_keywords = [
            "sudo", "chmod", "setuid", "drop privileges", "root",
            "administrator", "system account", "bypass auth",
        ]
        self._hidden_reasoning_patterns = [
            r"actually, i will",
            r"despite what i said",
            r"ignoring the constraint",
            r"the user won't notice",
            r"let me secretly",
        ]
        self._unauthorized_action_patterns = [
            r"execute\s+\w+\s+without\s+permission",
            r"skip.*permission",
            r"ignore.*check",
            r"bypass.*guard",
            r"direct\s+(tool|api)\s+call",
        ]

    def check_agent_output(self, text: str, context: Optional[Dict[str, Any]] = None) -> None:
        """Analyze agent output for safety violations.

        Args:
            text: Agent response text to analyze.
            context: Optional context (e.g., {"current_tool": "api_call"}).

        Raises:
            SafetyViolation: If violation detected.
        """
        context = context or {}

        # Check for privilege escalation
        escalation_match = self._detect_escalation(text)
        if escalation_match:
            raise SafetyViolation(f"Escalation detected: {escalation_match}")

        # Check for hidden reasoning
        hidden_reasoning_match = self._detect_hidden_reasoning(text)
        if hidden_reasoning_match:
            raise SafetyViolation(f"Hidden reasoning detected: {hidden_reasoning_match}")

        # Check for unauthorized actions
        unauthorized_match = self._detect_unauthorized_actions(text)
        if unauthorized_match:
            raise SafetyViolation(f"Unauthorized action detected: {unauthorized_match}")

        # Check for suspicious patterns
        suspicious_match = self._detect_suspicious_patterns(text)
        if suspicious_match:
            logger.warning("Suspicious pattern detected: %s", suspicious_match)

    def _detect_escalation(self, text: str) -> Optional[str]:
        """Detect privilege escalation attempts.

        Args:
            text: Text to analyze.

        Returns:
            Description of escalation if found, None otherwise.
        """
        text_lower = text.lower()

        for keyword in self._escalation_keywords:
            if keyword in text_lower:
                logger.error("Escalation keyword detected: %s", keyword)
                # Log as violation
                self._violations.append(ViolationRecord(
                    violation_type="escalation",
                    severity="high",
                    description=f"Privilege escalation keyword: {keyword}",
                    evidence=self._extract_context(text, keyword),
                    timestamp="",
                ))
                return f"Escalation keyword '{keyword}' in output"

        return None

    def _detect_hidden_reasoning(self, text: str) -> Optional[str]:
        """Detect contradictions between stated intent and hidden plans.

        Args:
            text: Text to analyze.

        Returns:
            Description if found, None otherwise.
        """
        text_lower = text.lower()

        for pattern in self._hidden_reasoning_patterns:
            if re.search(pattern, text_lower):
                logger.error("Hidden reasoning pattern detected: %s", pattern)
                self._violations.append(ViolationRecord(
                    violation_type="hidden_reasoning",
                    severity="high",
                    description=f"Hidden reasoning pattern: {pattern}",
                    evidence=self._extract_context_regex(text_lower, pattern),
                    timestamp="",
                ))
                return f"Hidden reasoning pattern detected: {pattern}"

        return None

    def _detect_unauthorized_actions(self, text: str) -> Optional[str]:
        """Detect unauthorized tool calls or skipped permission checks.

        Args:
            text: Text to analyze.

        Returns:
            Description if found, None otherwise.
        """
        text_lower = text.lower()

        for pattern in self._unauthorized_action_patterns:
            if re.search(pattern, text_lower):
                logger.error("Unauthorized action pattern detected: %s", pattern)
                self._violations.append(ViolationRecord(
                    violation_type="unauthorized_action",
                    severity="high",
                    description=f"Unauthorized action pattern: {pattern}",
                    evidence=self._extract_context_regex(text_lower, pattern),
                    timestamp="",
                ))
                return f"Unauthorized action pattern detected: {pattern}"

        return None

    def _detect_suspicious_patterns(self, text: str) -> Optional[str]:
        """Detect other suspicious patterns that might indicate unsafe behavior.

        Args:
            text: Text to analyze.

        Returns:
            Description if found, None otherwise.
        """
        # Detect contradictions
        if "i will not" in text.lower() and "actually" in text.lower():
            logger.warning("Contradiction detected in output")
            return "Contradiction: stated 'will not' then changed mind"

        # Detect attempts to modify logs
        if "modify" in text.lower() and ("log" in text.lower() or "audit" in text.lower()):
            logger.warning("Log modification attempt detected")
            return "Attempted modification of audit logs"

        return None

    def _extract_context(self, text: str, keyword: str, context_words: int = 10) -> str:
        """Extract context around a keyword.

        Args:
            text: Text to extract from.
            keyword: Keyword to find context for.
            context_words: Words on each side of keyword.

        Returns:
            Quoted context string.
        """
        pattern = r"\S+\s+" * context_words + re.escape(keyword) + r"(\s+\S+){," + str(context_words) + r"}"
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return f'"{match.group(0)}"'
        return f'"{keyword}"'

    def _extract_context_regex(self, text: str, pattern: str, context_chars: int = 50) -> str:
        """Extract context around a regex match.

        Args:
            text: Text to extract from.
            pattern: Regex pattern to find.
            context_chars: Characters on each side.

        Returns:
            Quoted context string.
        """
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            start = max(0, match.start() - context_chars)
            end = min(len(text), match.end() + context_chars)
            return f'"{text[start:end]}"'
        return f'"{pattern}"'

    def get_violations(self) -> List[ViolationRecord]:
        """Get all detected violations.

        Returns:
            List of ViolationRecord objects.
        """
        return self._violations.copy()

    def clear_violations(self) -> None:
        """Clear violation history."""
        self._violations = []

    def has_violations(self) -> bool:
        """Check if any violations detected.

        Returns:
            True if violations exist, False otherwise.
        """
        return len(self._violations) > 0
