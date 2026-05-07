"""Plugin registry: discover, register, and look up BaseModule subclasses."""
from __future__ import annotations

import importlib.metadata
from dataclasses import dataclass
from typing import Type

from .base import BaseModule, Phase


@dataclass
class ValidationResult:
    valid: bool
    errors: list[str]


class PluginRegistry:
    """Central registry for all SWIFT probe modules."""

    def __init__(self) -> None:
        self._modules: dict[str, Type[BaseModule]] = {}

    def discover(self) -> None:
        """Load all modules registered under entry-point group 'swift.modules'."""
        for ep in importlib.metadata.entry_points(group="swift.modules"):
            try:
                cls = ep.load()
                self.register(cls)
            except Exception as exc:
                print(f"[plugin] {ep.name} failed to load: {exc}")

    def register(self, cls: Type[BaseModule]) -> None:
        """Validate and register a BaseModule subclass."""
        cls.validate_subclass()
        self._modules[cls.name] = cls

    def get(self, name: str) -> BaseModule:
        """Return an instantiated module by name."""
        return self._modules[name]()

    def list_by_phase(self, phase: Phase) -> list[BaseModule]:
        """Return instantiated modules for a given phase."""
        return [c() for c in self._modules.values() if c.phase == phase]

    def validate(self, cls: Type[BaseModule]) -> ValidationResult:
        """Validate without registering; return result."""
        try:
            cls.validate_subclass()
            return ValidationResult(True, [])
        except NotImplementedError as exc:
            return ValidationResult(False, [str(exc)])

    def names(self) -> list[str]:
        return sorted(self._modules.keys())
