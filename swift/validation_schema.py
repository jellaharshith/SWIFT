"""Structured result schema for patch validation runs."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ValidationResult:
    """Deterministic validation result payload."""

    success: bool
    patch_applied: bool
    syntax_ok: bool
    tests_ok: bool
    commands_run: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    workspace: str = ""
    summary: str = ""

    def to_json_dict(self) -> dict[str, Any]:
        """Return stable JSON-ready dictionary."""
        return asdict(self)
