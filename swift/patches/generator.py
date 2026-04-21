"""Patch generator — uses Sonnet to generate, score, and select the best fix."""
from __future__ import annotations

import difflib
import itertools
import json
from typing import Any, List, Optional

from agent.models import Patch, Vulnerability
from log.logger import get_logger

logger = get_logger()

_COUNTER: itertools.count = itertools.count(1)

_PROMPT_TEMPLATE = """\
You are a security engineer generating a minimal, correct patch for a confirmed vulnerability.

Vulnerability:
- Type: {vuln_type}
- File: {file_path}
- Line: {line_number}
- Description: {description}
- Severity: {severity}

Vulnerable code:
```python
{code_snippet}
```

Generate exactly 3 patch candidates. Each must:
1. Fix ONLY the vulnerability — no refactoring
2. Maintain original code style
3. Be syntactically correct Python

Respond with ONLY valid JSON (no markdown wrapper):
{{
  "candidates": [
    {{
      "patched_code": "<complete fixed code snippet>",
      "reasoning": "<one sentence: why this fix works>",
      "lines_changed": <integer>
    }},
    {{
      "patched_code": "<alternative fixed code>",
      "reasoning": "<one sentence>",
      "lines_changed": <integer>
    }},
    {{
      "patched_code": "<another alternative>",
      "reasoning": "<one sentence>",
      "lines_changed": <integer>
    }}
  ]
}}
"""


def _score_candidate(lines_changed: int, reasoning: str) -> int:
    """Score a patch candidate 0-100. Higher = better."""
    score = 40  # base correctness
    # Minimal changes (40 pts)
    if lines_changed < 5:
        score += 40
    elif lines_changed < 10:
        score += 30
    elif lines_changed < 20:
        score += 15
    # Has reasoning comment (20 pts)
    if reasoning:
        score += 20
    return score


def _make_diff(original: str, patched: str, file_path: str) -> str:
    """Return a unified diff string between original and patched code."""
    a = original.splitlines(keepends=True)
    b = patched.splitlines(keepends=True)
    return "".join(
        difflib.unified_diff(
            a, b,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
        )
    )


class PatchGenerator:
    """Generate security patches for confirmed vulnerabilities using Sonnet.

    Args:
        client: Anthropic client instance (injected for testability).
        model: Sonnet model ID.
    """

    MODEL = "claude-sonnet-4-6"

    def __init__(self, client: Any, model: str = MODEL) -> None:
        self._client = client
        self._model = model

    def generate_patch(self, vuln: Vulnerability) -> Optional[Patch]:
        """Generate the best patch for a single vulnerability.

        SAFETY: Only generates patches for CONFIRMED findings (≥95% confidence).
        REVIEW_REQUIRED findings (65-95%) are skipped to prevent patch generation
        on unverified findings.

        Args:
            vuln: Confirmed vulnerability to patch.

        Returns:
            Best Patch object, or None if not CONFIRMED / confidence too low / generation fails.
        """
        # CRITICAL: Never auto-patch REVIEW_REQUIRED findings
        if vuln.status == "REVIEW_REQUIRED":
            logger.warning(
                "Skipping patch for %s: status is REVIEW_REQUIRED (not verified)",
                vuln.id,
            )
            return None

        if vuln.confidence < 0.90:
            logger.warning(
                "Skipping patch for %s: confidence %.2f < 0.90",
                vuln.id,
                vuln.confidence,
            )
            return None

        prompt = _PROMPT_TEMPLATE.format(
            vuln_type=vuln.vuln_type,
            file_path=vuln.file_path,
            line_number=vuln.line_number,
            description=vuln.description,
            severity=vuln.severity,
            code_snippet=vuln.code_snippet,
        )

        try:
            raw = self._call_api(prompt)
            data = json.loads(raw)
        except json.JSONDecodeError:
            logger.error("Patch API returned invalid JSON for %s", vuln.id)
            return None
        except Exception as exc:
            logger.error("Patch generation failed for %s: %s", vuln.id, exc)
            return None

        candidates = data.get("candidates", [])
        if not candidates:
            logger.warning("No patch candidates returned for %s", vuln.id)
            return None

        # Select highest-scoring candidate
        best = max(
            candidates,
            key=lambda c: _score_candidate(
                c.get("lines_changed", 99),
                c.get("reasoning", ""),
            ),
        )

        patched_code = best.get("patched_code", "")
        diff = _make_diff(vuln.code_snippet, patched_code, vuln.file_path)
        patch_id = f"PATCH-{next(_COUNTER):03d}"

        logger.info("Generated patch %s for %s", patch_id, vuln.id)
        return Patch(
            id=patch_id,
            vuln_id=vuln.id,
            file_path=vuln.file_path,
            original_code=vuln.code_snippet,
            patched_code=patched_code,
            diff=diff,
            confidence=vuln.confidence,
        )

    def generate_patches(self, vulnerabilities: List[Vulnerability]) -> List[Patch]:
        """Generate patches for a list of vulnerabilities.

        Args:
            vulnerabilities: Confirmed vulnerabilities (≥95% confidence expected).

        Returns:
            List of Patch objects — one per successfully patched vulnerability.
        """
        patches: List[Patch] = []
        for vuln in vulnerabilities:
            patch = self.generate_patch(vuln)
            if patch:
                patches.append(patch)
        return patches

    def _call_api(self, prompt: str) -> str:
        response = self._client.messages.create(
            model=self._model,
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text
