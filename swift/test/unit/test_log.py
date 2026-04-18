import logging
import pytest
from log.logger import get_logger, MetricsCollector


def test_setup_logging_returns_logger():
    logger = get_logger()
    assert isinstance(logger, logging.Logger)
    assert logger.name == "swift"


def test_metrics_collector_start_scan():
    m = MetricsCollector()
    m.start_scan("SCAN-001", "/tmp/repo")
    assert m.scan_id == "SCAN-001"
    assert m.repo_path == "/tmp/repo"


def test_metrics_collector_accumulates_cost():
    m = MetricsCollector()
    m.add_cost(0.05)
    m.add_cost(0.10)
    assert abs(m.total_cost_usd - 0.15) < 1e-9


def test_metrics_collector_summary():
    m = MetricsCollector()
    m.start_scan("SCAN-001", "/tmp/repo")
    m.add_cost(0.05)
    summary = m.summary()
    assert "total_cost_usd" in summary
    assert summary["total_cost_usd"] == pytest.approx(0.05)


def test_metrics_collector_vuln_tracking():
    m = MetricsCollector()
    m.record_vulnerability("SWIFT-001")
    m.record_vulnerability("SWIFT-002")
    assert m.vulnerability_count == 2
