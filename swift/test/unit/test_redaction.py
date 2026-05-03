"""Tests for secret redaction in logging."""
import logging

from log.logger import _SecretRedactingFilter, _redact


def test_redact_sk_ant_key():
    secret = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890"
    assert "sk-ant-" not in _redact(secret)
    assert "***REDACTED***" in _redact(secret)


def test_redact_bearer_token():
    text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"
    result = _redact(text)
    assert "eyJ" not in result
    assert "***REDACTED***" in result


def test_redact_env_value(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-supersecretvalue12345")
    assert "supersecretvalue12345" not in _redact("key=sk-ant-test-supersecretvalue12345")


def test_filter_scrubs_msg():
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname="", lineno=0,
        msg="found sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890 in config",
        args=(), exc_info=None,
    )
    _SecretRedactingFilter().filter(record)
    assert "sk-ant-" not in record.msg
    assert "***REDACTED***" in record.msg


def test_safe_string_unchanged():
    assert _redact("hello world safe text") == "hello world safe text"
