"""Stage 1 API scanner using Claude Haiku for fast triage."""
from __future__ import annotations

import re
import time
from typing import Any, Optional, Set

from agent.pentester_persona import build_haiku_pentester_prompt


class HaikuTriageScanner:
    """Call Haiku to identify suspicious line numbers from pre-flagged code.

    Args:
        client: Anthropic client instance. Injected for testability.
        model: Haiku model ID (default: claude-haiku-4-5-20251001).
        max_retries: Number of retry attempts on API error (default: 3).
        mode: Scan persona — "pentester" (default) uses offensive framing;
            "passive" uses the original defensive reviewer framing.
    """

    MODEL = "claude-haiku-4-5-20251001"

    def __init__(
        self,
        client: Any,
        model: str = MODEL,
        max_retries: int = 3,
        mode: str = "pentester",
    ) -> None:
        self._client = client
        self._model = model
        self._max_retries = max_retries
        self._mode = mode

    def scan_lines(
        self, file_path: str, source_code: str, flagged_lines: Set[int]
    ) -> Set[int]:
        """Ask Haiku which flagged lines are suspicious.

        Args:
            file_path: Path shown in prompt for context.
            source_code: Full file content.
            flagged_lines: Line numbers pre-flagged by regex triage.

        Returns:
            Set of line numbers Haiku considers suspicious.

        Raises:
            Exception: After max_retries failed attempts.
        """
        prompt = self._build_prompt(file_path, source_code, flagged_lines)
        response_text = self._call_with_retry(prompt)
        return self._parse_line_numbers(response_text)

    def _build_prompt(
        self, file_path: str, source_code: str, flagged_lines: Set[int]
    ) -> str:
        import os as _os
        lines_str = ", ".join(str(n) for n in sorted(flagged_lines))
        ext = _os.path.splitext(file_path)[1].lower()
        lang = {
            ".py": "python", ".ts": "typescript", ".tsx": "typescript",
            ".js": "javascript", ".jsx": "javascript",
        }.get(ext, "code")
        if self._mode != "passive":
            return build_haiku_pentester_prompt(
                file_path=file_path,
                source_code=source_code,
                flagged_lines=sorted(flagged_lines),
                lang=lang,
            )
        # Passive / defensive mode — original prompt
        return (
            f"You are a security code reviewer analyzing {file_path}.\n"
            f"These lines were flagged by static analysis: {lines_str}\n\n"
            f"Source code:\n```{lang}\n{source_code}\n```\n\n"
            "List only the line numbers that contain real security vulnerabilities "
            "(e.g. XSS, prompt injection, CORS misconfiguration, hardcoded secrets, "
            "command injection, open redirect, error leakage). "
            "Respond with line numbers only, comma-separated. "
            "If none are suspicious, say 'none'."
        )

    def _call_with_retry(self, prompt: str) -> str:
        last_exc: Optional[Exception] = None
        for attempt in range(self._max_retries):
            try:
                response = self._client.messages.create(
                    model=self._model,
                    max_tokens=256,
                    messages=[{"role": "user", "content": prompt}],
                )
                return response.content[0].text
            except Exception as exc:
                last_exc = exc
                if attempt < self._max_retries - 1:
                    time.sleep(2 ** attempt)
        raise last_exc  # type: ignore[misc]

    @staticmethod
    def _parse_line_numbers(text: str) -> Set[int]:
        """Extract all integers from response text."""
        return {int(n) for n in re.findall(r"\d+", text)}
