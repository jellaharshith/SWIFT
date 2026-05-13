"""Unit tests for ScanEventBus."""
import pytest

from events.bus import (
    EventType,
    ScanEvent,
    ScanEventBus,
    get_bus,
    reset_bus,
)


def test_subscribe_and_emit() -> None:
    bus = ScanEventBus()
    received: list[ScanEvent] = []
    bus.subscribe(received.append)
    event = ScanEvent(type=EventType.FINDING, data={"vuln": "xss"})
    bus.emit(event)
    assert len(received) == 1
    assert received[0].type == EventType.FINDING
    assert received[0].data["vuln"] == "xss"


def test_emit_type_helper() -> None:
    bus = ScanEventBus()
    received: list[ScanEvent] = []
    bus.subscribe(received.append)
    bus.emit_type(EventType.PROBE_START, target="http://localhost")
    assert len(received) == 1
    assert received[0].type == EventType.PROBE_START
    assert received[0].data["target"] == "http://localhost"


def test_multiple_subscribers() -> None:
    bus = ScanEventBus()
    log_a: list[ScanEvent] = []
    log_b: list[ScanEvent] = []
    bus.subscribe(log_a.append)
    bus.subscribe(log_b.append)
    bus.emit(ScanEvent(type=EventType.SCAN_DONE))
    assert len(log_a) == 1
    assert len(log_b) == 1


def test_subscriber_exception_does_not_crash_bus() -> None:
    bus = ScanEventBus()

    def bad_subscriber(_: ScanEvent) -> None:
        raise RuntimeError("boom")

    received: list[ScanEvent] = []
    bus.subscribe(bad_subscriber)
    bus.subscribe(received.append)

    bus.emit(ScanEvent(type=EventType.ERROR))
    # The good subscriber still fired
    assert len(received) == 1


def test_get_bus_singleton() -> None:
    reset_bus()
    bus1 = get_bus()
    bus2 = get_bus()
    assert bus1 is bus2


def test_reset_bus_creates_new_instance() -> None:
    reset_bus()
    bus1 = get_bus()
    reset_bus()
    bus2 = get_bus()
    assert bus1 is not bus2


def test_event_type_values() -> None:
    assert EventType.FINDING == "finding"
    assert EventType.PROBE_DONE == "probe_done"
    assert EventType.SCAN_DONE == "scan_done"


def test_scan_event_default_data() -> None:
    event = ScanEvent(type=EventType.PHASE_START)
    assert event.data == {}
