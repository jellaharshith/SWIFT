"""Sonnet analysis scanner — THE 95% CONFIDENCE GATE."""
from __future__ import annotations

import itertools
import json
import re
from typing import Any, Optional

from agent.models import Vulnerability
from agent.pentester_persona import build_sonnet_pentester_prompt
from log.logger import get_logger

logger = get_logger()


def _clean_json(json_str: str) -> str:
    """Clean malformed JSON: remove trailing commas, fix syntax errors.

    Handles:
    - Trailing commas before } or ]
    - Extra whitespace
    - Common Sonnet mistakes

    Args:
        json_str: Raw JSON string that may be malformed.

    Returns:
        Cleaned JSON string with common syntax errors fixed.
    """
    # Remove trailing commas before } or ]
    json_str = re.sub(r',(\s*[}\]])', r'\1', json_str)

    # Remove any leading/trailing whitespace
    json_str = json_str.strip()

    return json_str

_PROMPT_TEMPLATE = """\
You are an expert security analyst. Analyze the following {language} code for security vulnerabilities.

File: {file_path}
Line: {line_number}

Source code:
```{language}
{source_code}
```

RESPOND WITH ONLY VALID JSON (no markdown, no explanation):

For each vulnerability found, extract the COMPLETE evidence bundle:

1. **confidence** (0.0-1.0): Your confidence that this is a real vulnerability
2. **vuln_type**: Category (sql_injection|command_injection|hardcoded_secret|weak_crypto|unsafe_deserialization|other)
3. **description**: Precise description of the vulnerability
4. **severity**: Level (critical|high|medium|low)
5. **code_snippet**: The exact vulnerable line(s)
6. **cwe_id**: CWE identifier (e.g., "CWE-89" for SQL injection)
7. **cwe_url**: URL to CWE definition (https://cwe.mitre.org/data/definitions/{{number}}.html)
8. **owasp_category**: Map to OWASP Top 10 2021 (e.g., "A03:2021 – Injection")
9. **exploit_description**: Detailed explanation of how an attacker could exploit this
10. **exploit_impact**: What an attacker can do (compromise, steal, execute, etc.)
11. **remediation**: Step-by-step instructions to fix this vulnerability
12. **remediation_code**: Code snippet showing the fixed version
13. **remediation_effort**: Effort level (LOW|MEDIUM|HIGH) based on complexity
14. **remediation_time_minutes**: Estimated minutes to fix (5-60 range)
15. **references**: Array of URLs to OWASP/CWE security documentation

RESPONSE FORMAT:
{{
  "confidence": <float 0.0-1.0>,
  "vuln_type": "<string>",
  "description": "<string>",
  "severity": "<critical|high|medium|low>",
  "code_snippet": "<string>",
  "cwe_id": "<e.g., CWE-89>",
  "cwe_url": "<https://cwe.mitre.org/data/definitions/XX.html>",
  "owasp_category": "<e.g., A03:2021 – Injection>",
  "exploit_description": "<string>",
  "exploit_impact": "<string>",
  "remediation": "<string>",
  "remediation_code": "<string>",
  "remediation_effort": "<LOW|MEDIUM|HIGH>",
  "remediation_time_minutes": <integer 5-60>,
  "references": ["<url1>", "<url2>", ...]
}}

If NO vulnerability, return:
{{
  "confidence": 0.0,
  "vuln_type": "none",
  "description": "clean",
  "severity": "low",
  "code_snippet": "",
  "cwe_id": null,
  "cwe_url": null,
  "owasp_category": null,
  "exploit_description": null,
  "exploit_impact": null,
  "remediation": null,
  "remediation_code": null,
  "remediation_effort": null,
  "remediation_time_minutes": null,
  "references": []
}}
"""


class SonnetAnalysisScanner:
    """Deep analysis with confidence tiers using Claude Sonnet.

    Two-tier model:
    - CONFIRMED: confidence ≥ 95% (high-confidence findings)
    - REVIEW_REQUIRED: confidence 65-95% (useful for triage, not verified)
    - Suppressed: confidence < 65% (not output)

    Args:
        client: Anthropic client instance.
        model: Sonnet model ID.
    """

    MODEL = "claude-sonnet-4-6"
    HIGH_CONFIDENCE_THRESHOLD = 0.95
    REVIEW_THRESHOLD = 0.65
    _counter: itertools.count = itertools.count(1)

    def __init__(self, client: Any, model: str = MODEL, mode: str = "pentester") -> None:
        self._client = client
        self._model = model
        self._mode = mode

    def analyze_line(
        self, file_path: str, line_number: int, source_code: str
    ) -> Optional[Vulnerability]:
        """Analyze a specific line for vulnerabilities.

        Args:
            file_path: Path for context in prompt.
            line_number: 1-indexed line to analyze.
            source_code: Full file source.

        Returns:
            Vulnerability with status CONFIRMED/REVIEW_REQUIRED if confidence >= 0.65, else None.
        """
        language = self._detect_language(file_path)
        if self._mode != "passive":
            prompt = build_sonnet_pentester_prompt(
                file_path=file_path,
                line_number=line_number,
                source_code=source_code,
                language=language,
            )
        else:
            prompt = _PROMPT_TEMPLATE.format(
                file_path=file_path,
                line_number=line_number,
                source_code=source_code,
                language=language,
            )
        raw = self._call_api(prompt)
        return self._parse_response(raw, file_path, line_number)

    @staticmethod
    def _detect_language(file_path: str) -> str:
        """Detect language from file extension.

        Args:
            file_path: Path to analyze.

        Returns:
            Language identifier for code block (python, javascript, typescript, or 'code').
        """
        import os as _os
        ext = _os.path.splitext(file_path)[1].lower()
        return {
            ".py": "python",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".js": "javascript",
            ".jsx": "javascript",
        }.get(ext, "code")

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
        # Try to extract JSON from markdown code blocks (e.g., ```json {...}```)
        json_str = self._extract_json(raw)

        # Log raw for debugging
        raw_preview = raw[:200].replace('\n', ' ')
        logger.debug("Sonnet raw response (first 200 chars): %s", raw_preview)

        # Attempt to clean JSON
        cleaned_json = _clean_json(json_str)

        # Log cleaned for debugging
        cleaned_preview = cleaned_json[:200].replace('\n', ' ')
        logger.debug("Sonnet cleaned JSON (first 200 chars): %s", cleaned_preview)

        # Try to parse
        try:
            data = json.loads(cleaned_json)
        except json.JSONDecodeError as e:
            logger.warning(
                "Sonnet JSON parse failed for %s:%d after cleaning: %s",
                file_path, line_number, str(e)
            )
            return None

        confidence = data.get("confidence")
        if confidence is None:
            logger.warning("Missing confidence field for %s:%d", file_path, line_number)
            return None

        # Two-tier confidence model
        if confidence < self.REVIEW_THRESHOLD:
            logger.warning(
                "Low confidence %.2f for %s:%d — suppressed (threshold=%.2f)",
                confidence, file_path, line_number, self.REVIEW_THRESHOLD,
            )
            return None

        # Determine status based on confidence tier
        if confidence >= self.HIGH_CONFIDENCE_THRESHOLD:
            status = "CONFIRMED"
        else:
            status = "REVIEW_REQUIRED"
            logger.info(
                "Medium confidence %.2f for %s:%d — marked REVIEW_REQUIRED",
                confidence, file_path, line_number,
            )

        vuln_id = f"SWIFT-{next(self._counter):03d}"

        # Parse remediation_time_minutes as integer
        remediation_time = data.get("remediation_time_minutes")
        if remediation_time is not None:
            try:
                remediation_time = int(remediation_time)
            except (ValueError, TypeError):
                remediation_time = None

        # Parse references as list
        references = data.get("references", [])
        if references is None:
            references = []
        elif not isinstance(references, list):
            references = []

        return Vulnerability(
            id=vuln_id,
            file_path=file_path,
            line_number=line_number,
            vuln_type=data.get("vuln_type", "unknown"),
            description=data.get("description", ""),
            confidence=float(confidence),
            severity=data.get("severity", "medium").upper(),
            code_snippet=data.get("code_snippet", ""),
            status=status,
            cwe_id=data.get("cwe_id"),
            cwe_url=data.get("cwe_url"),
            owasp_category=data.get("owasp_category"),
            exploit_description=data.get("exploit_description"),
            exploit_impact=data.get("exploit_impact"),
            remediation=data.get("remediation"),
            remediation_code=data.get("remediation_code"),
            remediation_effort=data.get("remediation_effort"),
            remediation_time_minutes=remediation_time,
            references=references,
        )

    @staticmethod
    def _extract_json(raw: str) -> str:
        """Extract JSON from markdown code blocks or raw text.

        Handles:
        - ```json {...}```
        - ```{...}```
        - Raw JSON
        - Partial JSON (greedy match from first { to last })
        """
        # Try markdown code blocks first
        match = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', raw)
        if match:
            return match.group(1)

        # Try raw JSON: greedy match from first { to last }
        # This handles malformed JSON with extra text
        match = re.search(r'\{[\s\S]*\}', raw)
        if match:
            return match.group(0)

        return raw
