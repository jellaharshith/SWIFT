"""Rich TUI live dashboard for scan progress."""
from __future__ import annotations

from rich.console import Console
from rich.live import Live
from rich.table import Table

from events.bus import ScanEventBus, ScanEvent, EventType


class ScanTUI:
    """Live Rich TUI that subscribes to ScanEventBus events."""

    def __init__(self, bus: ScanEventBus) -> None:
        self._bus = bus
        self._console = Console()
        self._findings: list[dict] = []
        self._current_phase = "initializing"
        self._probe_count = 0
        bus.subscribe(self._on_event)

    def _on_event(self, event: ScanEvent) -> None:
        if event.type == EventType.PHASE_START:
            self._current_phase = event.data.get("phase", "")
        elif event.type == EventType.PROBE_DONE:
            self._probe_count += 1
        elif event.type == EventType.FINDING:
            self._findings.append(event.data)

    def _build_layout(self) -> Table:
        table = Table(title=f"SWIFT Live Scan — Phase: {self._current_phase}")
        table.add_column("Probes Run")
        table.add_column("Findings")
        table.add_row(str(self._probe_count), str(len(self._findings)))
        return table

    def run(self, scan_fn, *args, **kwargs):
        """Run scan_fn inside a Live display."""
        with Live(self._build_layout(), refresh_per_second=4, console=self._console) as live:
            def refresh(_: ScanEvent) -> None:
                live.update(self._build_layout())
            self._bus.subscribe(refresh)
            return scan_fn(*args, **kwargs)
