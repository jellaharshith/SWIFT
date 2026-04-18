import pytest
from unittest.mock import MagicMock, patch
from scanners.haiku_scanner import HaikuTriageScanner


def _make_client(response_text: str) -> MagicMock:
    msg = MagicMock()
    msg.content = [MagicMock(text=response_text)]
    client = MagicMock()
    client.messages.create.return_value = msg
    return client


def test_haiku_calls_correct_model():
    client = _make_client("Lines 5, 10")
    scanner = HaikuTriageScanner(client=client)
    scanner.scan_lines("app.py", "code", {5, 10})
    call_kwargs = client.messages.create.call_args[1]
    assert call_kwargs["model"] == "claude-haiku-4-5-20251001"


def test_haiku_returns_line_numbers():
    client = _make_client("Lines 5, 10 are suspicious")
    scanner = HaikuTriageScanner(client=client)
    result = scanner.scan_lines("app.py", "code", {5, 10})
    assert 5 in result
    assert 10 in result


def test_haiku_empty_response_returns_empty_set():
    client = _make_client("No suspicious lines found.")
    scanner = HaikuTriageScanner(client=client)
    result = scanner.scan_lines("app.py", "code", {1})
    assert result == set()


def test_haiku_parses_varied_formats():
    client = _make_client("Line 3 and line 7 look suspicious.")
    scanner = HaikuTriageScanner(client=client)
    result = scanner.scan_lines("app.py", "code", {3, 7})
    assert 3 in result
    assert 7 in result


def test_haiku_retry_on_api_error():
    msg = MagicMock()
    msg.content = [MagicMock(text="Line 1")]
    client = MagicMock()
    client.messages.create.side_effect = [Exception("timeout"), msg]
    scanner = HaikuTriageScanner(client=client, max_retries=3)
    with patch("time.sleep"):
        result = scanner.scan_lines("app.py", "code", {1})
    assert 1 in result
    assert client.messages.create.call_count == 2


def test_haiku_exhausted_retries_raises():
    client = MagicMock()
    client.messages.create.side_effect = Exception("API down")
    scanner = HaikuTriageScanner(client=client, max_retries=3)
    with patch("time.sleep"):
        with pytest.raises(Exception, match="API down"):
            scanner.scan_lines("app.py", "code", {1})
    assert client.messages.create.call_count == 3


def test_haiku_builds_correct_prompt():
    client = _make_client("Line 1")
    scanner = HaikuTriageScanner(client=client)
    scanner.scan_lines("app.py", "x = 1\n", {1})
    prompt = client.messages.create.call_args[1]["messages"][0]["content"]
    assert "app.py" in prompt
    assert "x = 1" in prompt
