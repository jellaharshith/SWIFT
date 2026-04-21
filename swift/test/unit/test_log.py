import logging
import pytest
from log.logger import get_logger, MetricsCollector, _LowercaseLevelFormatter


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


def _test_logger_level_lowercase(level_name: str, log_method: str) -> None:
    """Helper: Test that a log level outputs lowercase name.

    Args:
        level_name: Level name in uppercase (e.g., "WARNING")
        log_method: Logger method name (e.g., "warning")
    """
    import io

    logger = get_logger(f"test_{level_name.lower()}")
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(
        _LowercaseLevelFormatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    logger.handlers = [handler]

    getattr(logger, log_method)(f"test {level_name.lower()}")
    output = stream.getvalue()

    # Verify lowercase
    assert f"[{level_name.lower()}]" in output
    assert f"[{level_name}]" not in output


def test_logger_info_uses_lowercase_info(capsys):
    """Verify [info] not [INFO] in log output."""
    logger = get_logger("test_info")
    logger.info("test message")
    captured = capsys.readouterr()
    assert "[info]" in captured.err
    assert "[INFO]" not in captured.err


def test_logger_warning_uses_lowercase() -> None:
    """Verify WARNING logs output [warning] not [WARNING]."""
    _test_logger_level_lowercase("WARNING", "warning")


def test_logger_error_uses_lowercase() -> None:
    """Verify ERROR logs output [error] not [ERROR]."""
    _test_logger_level_lowercase("ERROR", "error")


def test_logger_custom_level_uses_lowercase() -> None:
    """Verify custom log levels are also lowercased."""
    import io

    # Register custom level
    custom_level = 25
    level_name = "CUSTOM"
    logging.addLevelName(custom_level, level_name)

    logger = get_logger("test_custom_level")
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(
        _LowercaseLevelFormatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    logger.handlers = [handler]

    # Log at custom level
    logger.log(custom_level, "test custom level")
    output = stream.getvalue()

    # Should be lowercase
    assert "[custom]" in output.lower()
