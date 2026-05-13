"""Lightweight event bus for scan progress notifications."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EventType(str, Enum):
    PROBE_START = "probe_start"
    PROBE_DONE = "probe_done"
    FINDING = "finding"
    PHASE_START = "phase_start"
    PHASE_DONE = "phase_done"
    SCAN_DONE = "scan_done"
    ERROR = "error"


@dataclass
class ScanEvent:
    type: EventType
    data: dict[str, Any] = field(default_factory=dict)


class ScanEventBus:
    """Pub/sub event bus. Subscribers receive ScanEvent objects."""

    def __init__(self) -> None:
        self._subscribers: list[Callable[[ScanEvent], None]] = []

    def subscribe(self, callback: Callable[[ScanEvent], None]) -> None:
        self._subscribers.append(callback)

    def emit(self, event: ScanEvent) -> None:
        for cb in self._subscribers:
            try:
                cb(event)
            except Exception:
                pass  # never let a subscriber crash the scan

    def emit_type(self, event_type: EventType, **data: Any) -> None:
        self.emit(ScanEvent(type=event_type, data=data))


# Module-level singleton for use by scan pipeline
_bus: ScanEventBus | None = None


def get_bus() -> ScanEventBus:
    global _bus
    if _bus is None:
        _bus = ScanEventBus()
    return _bus


def reset_bus() -> None:
    global _bus
    _bus = None
