"""Sonnet analysis scanner — THE 95% CONFIDENCE GATE."""
from __future__ import annotations

import itertools
import json
from typing import Any, Optional

from agent.models import Vulnerability
from log.logger import get_logger

logger = get_logger()

_PROMPT_TEMPLATE = """\
You are an expert security analyst. Analyze the following Python code for security vulnerabilities.

File: {file_path}
Line: {line_number}

Source code:
```python
{source_code}
```

Respond with ONLY valid JSON (no markdown, no explanation):
{{
  "confidence": <float 0.0-1.0>,
  "vuln_type": "<sql_injection|command_injection|hardcoded_secret|weak_crypto|unsafe_deserialization|other>",
  "description": "<precise description of the vulnerability>",
  "severity": "<critical|high|medium|low>",
  "code_snippet": "<the exact vulnerable line or lines>"
}}

If no vulnerability, return: {{"confidence": 0.0, "vuln_type": "none", "description": "clean", "severity": "low", "code_snippet": ""}}
"""


class SonnetAnalysisScanner:
    """Deep analysis with 95% confidence gate using Claude Sonnet.

    The 95% rule: if confidence < 0.95, log warning and return None.
    This prevents false positives from reaching the output.

    Args:
        client: Anthropic client instance.
        model: Sonnet model ID.
    """

    MODEL = "claude-sonnet-4-6"
    CONFIDENCE_THRESHOLD = 0.95
    _counter: itertools.count = itertools.count(1)

    def __init__(self, client: Any, model: str = MODEL) -> None:
        self._client = client
        self._model = model

    def analyze_line(
        self, file_path: str, line_number: int, source_code: str
    ) -> Optional[Vulnerability]:
        """Analyze a specific line for vulnerabilities.

        Args:
            file_path: Path for context in prompt.
            line_number: 1-indexed line to analyze.
            source_code: Full file source.

        Returns:
            Vulnerability if confidence >= 0.95, else None.
        """
        prompt = _PROMPT_TEMPLATE.format(
            file_path=file_path,
            line_number=line_number,
            source_code=source_code,
        )
        raw = self._call_api(prompt)
        return self._parse_response(raw, file_path, line_number)

    def _call_api(self, prompt: str) -> str:
        response = self._client.messages.create(
            model=self._model,
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text

    def _parse_response(
        self, raw: str, file_path: str, line_number: int
    ) -> Optional[Vulnerability]:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("Sonnet returned invalid JSON for %s:%d", file_path, line_number)
            return None

        confidence = data.get("confidence")
        if confidence is None:
            logger.warning("Missing confidence field for %s:%d", file_path, line_number)
            return None

        if confidence < self.CONFIDENCE_THRESHOLD:
            logger.warning(
                "Low confidence %.2f for %s:%d — suppressed (threshold=%.2f)",
                confidence, file_path, line_number, self.CONFIDENCE_THRESHOLD,
            )
            return None

        vuln_id = f"SWIFT-{next(self._counter):03d}"
        return Vulnerability(
            id=vuln_id,
            file_path=file_path,
            line_number=line_number,
            vuln_type=data.get("vuln_type", "unknown"),
            description=data.get("description", ""),
            confidence=float(confidence),
            severity=data.get("severity", "medium").upper(),
            code_snippet=data.get("code_snippet", ""),
        )
