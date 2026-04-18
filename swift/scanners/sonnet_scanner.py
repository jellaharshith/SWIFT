"""Sonnet analysis scanner stub — replaced in Task 6."""
from __future__ import annotations
from typing import Any, Optional
from agent.models import Vulnerability


class SonnetAnalysisScanner:
    """Stub — implemented in Task 6."""

    def __init__(self, client: Any, model: str = "claude-sonnet-4-6") -> None:
        self._client = client
        self._model = model

    def analyze_line(
        self, file_path: str, line_number: int, source_code: str
    ) -> Optional[Vulnerability]:
        raise NotImplementedError("SonnetAnalysisScanner not yet implemented")
