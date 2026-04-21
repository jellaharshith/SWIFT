"""Exploit chain detection — identify multi-step attack paths."""
from __future__ import annotations

import itertools
import json
import time
from typing import Any, List, Optional

from agent.models import AttackStep, ExploitChain, Vulnerability
from log.logger import get_logger
from utils.json_safe import safe_parse_json_array

logger = get_logger()

# Timeout protection: skip chain detection if exceeds this duration (seconds)
MAX_CHAIN_DETECTION_TIME = 30

_PROMPT_TEMPLATE = """\
You are an expert security architect specializing in attack path analysis.

Analyze the following confirmed vulnerabilities and identify exploit chains — sequences of multiple vulnerabilities that can be chained together into a complete attack.

Vulnerabilities:
{vulns_json}

For each exploit chain you identify:
1. List the vulnerability IDs in attack order
2. Describe the complete attack path (entry point → escalation → final impact)
3. Identify the entry point (file:line)
4. Describe the final impact/compromise achieved
5. Assign a severity (CRITICAL, HIGH, MEDIUM, LOW)
6. Rate your confidence in the chain (0.0-1.0)

Respond with ONLY valid JSON array (no markdown, no explanation):
[
  {{
    "chain_id": "CHAIN-001",
    "name": "SQL Injection → Auth Bypass → Admin Access",
    "vulnerability_ids": ["SWIFT-001", "SWIFT-003"],
    "attack_path": "1. Exploit SQL injection in login query to bypass authentication\\n2. Access admin panel without credentials\\n3. Modify user roles to grant admin access",
    "attack_steps": [
      {{
        "step": 1,
        "description": "Exploit SQL injection in login query to bypass authentication",
        "vuln_id": "SWIFT-001",
        "entry_point": "auth/views.py:42"
      }},
      {{
        "step": 2,
        "description": "Access admin panel without credentials",
        "vuln_id": "SWIFT-003",
        "entry_point": "admin/views.py:15"
      }}
    ],
    "entry_point": "auth/views.py:42",
    "impact": "Full admin access without credentials",
    "severity": "CRITICAL",
    "confidence": 0.92
  }}
]

If no chains exist, return: []
"""


class ExploitChainDetector:
    """Detect multi-step attack paths using Claude Sonnet.

    Chain detection is best-effort: errors are logged, not raised.
    Confidence gate: only include chains with confidence >= 0.85.

    Args:
        client: Anthropic client instance.
        model: Sonnet model ID.
    """

    MODEL = "claude-sonnet-4-6"
    CONFIDENCE_THRESHOLD = 0.85
    _counter: itertools.count = itertools.count(1)

    def __init__(self, client: Any, model: str = MODEL) -> None:
        self._client = client
        self._model = model

    def detect_chains(
        self, vulnerabilities: List[Vulnerability]
    ) -> List[ExploitChain]:
        """Detect exploit chains from a list of vulnerabilities.

        Best-effort chain detection with timeout and error resilience.
        Returns empty list on timeout or any error (partial results still propagate).

        Args:
            vulnerabilities: List of confirmed Vulnerability objects.

        Returns:
            List of ExploitChain objects with confidence >= 0.85.
            Empty list if < 2 vulnerabilities, timeout, parse error, or API error.
        """
        if len(vulnerabilities) < 2:
            logger.debug("Too few vulnerabilities for chains (%d < 2)", len(vulnerabilities))
            return []

        # Start timeout clock
        start_time = time.monotonic()

        try:
            vulns_json = json.dumps(
                [
                    {
                        "id": v.id,
                        "file_path": v.file_path,
                        "line_number": v.line_number,
                        "vuln_type": v.vuln_type,
                        "description": v.description,
                        "severity": v.severity,
                    }
                    for v in vulnerabilities
                ],
                indent=2,
            )
        except Exception as e:
            logger.warning("Failed to serialize vulnerabilities for chain detection: %s", e)
            return []

        prompt = _PROMPT_TEMPLATE.format(vulns_json=vulns_json)

        try:
            # Check timeout before API call
            elapsed = time.monotonic() - start_time
            if elapsed > MAX_CHAIN_DETECTION_TIME:
                logger.warning("Chain detection skipped (prep timeout: %.1fs)", elapsed)
                return []

            raw = self._call_api(prompt)

            # Check timeout after API call
            elapsed = time.monotonic() - start_time
            if elapsed > MAX_CHAIN_DETECTION_TIME:
                logger.warning("Chain detection skipped (API timeout: %.1fs)", elapsed)
                return []

            # Handle empty response
            if not raw or not raw.strip():
                logger.warning("Chain detection returned empty response")
                return []

            chains = self._parse_response(raw)
            logger.info("Detected %d exploit chains (%.1fs)", len(chains), elapsed)
            return chains
        except Exception as e:
            elapsed = time.monotonic() - start_time
            logger.warning("Chain detection failed after %.1fs (proceeding without chains): %s", elapsed, e)
            return []

    def _call_api(self, prompt: str) -> str:
        """Call Claude Sonnet API.

        Args:
            prompt: The full prompt to send.

        Returns:
            Raw response text.
        """
        response = self._client.messages.create(
            model=self._model,
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text

    def _parse_response(self, raw: str) -> List[ExploitChain]:
        """Parse chain detection response using safe JSON parsing.

        Handles malformed JSON gracefully by returning empty list instead of raising.
        Confidence gate: only includes chains with confidence >= 0.85.

        Args:
            raw: Raw response text from API.

        Returns:
            List of ExploitChain objects (confidence >= 0.85).
            Empty list if JSON parse fails.
        """
        # Use safe parsing to handle invalid JSON without crashing
        data = safe_parse_json_array(raw)
        if not data:
            logger.warning("Chain response is not valid JSON array, returning empty")
            return []

        chains = []
        for item in data:
            try:
                confidence = item.get("confidence")
                if confidence is None:
                    logger.debug("Chain item missing confidence, skipping")
                    continue

                if confidence < self.CONFIDENCE_THRESHOLD:
                    logger.debug(
                        "Chain confidence %.2f below threshold %.2f, skipping",
                        confidence,
                        self.CONFIDENCE_THRESHOLD,
                    )
                    continue

                chain_id = item.get("chain_id") or f"CHAIN-{next(self._counter):03d}"

                # Parse attack steps if present
                attack_steps = []
                if "attack_steps" in item and isinstance(item["attack_steps"], list):
                    for step_data in item["attack_steps"]:
                        try:
                            attack_steps.append(
                                AttackStep(
                                    step=step_data.get("step", len(attack_steps) + 1),
                                    description=step_data.get("description", ""),
                                    vuln_id=step_data.get("vuln_id", ""),
                                    entry_point=step_data.get("entry_point", ""),
                                )
                            )
                        except Exception as e:
                            logger.debug("Failed to parse attack step: %s", e)
                            continue

                chain = ExploitChain(
                    chain_id=chain_id,
                    name=item.get("name", "Unknown chain"),
                    vulnerability_ids=item.get("vulnerability_ids", []),
                    attack_path=item.get("attack_path", ""),
                    entry_point=item.get("entry_point", ""),
                    impact=item.get("impact", ""),
                    severity=item.get("severity", "MEDIUM").upper(),
                    confidence=float(confidence),
                    attack_steps=attack_steps,
                )
                chains.append(chain)
            except Exception as e:
                logger.warning("Failed to parse chain item: %s", e)
                continue

        return chains
