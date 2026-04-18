import itertools
import json
import pytest
from unittest.mock import MagicMock, patch
from scanners.sonnet_scanner import SonnetAnalysisScanner
from agent.models import Vulnerability


def _make_client(response_json: dict) -> MagicMock:
    msg = MagicMock()
    msg.content = [MagicMock(text=json.dumps(response_json))]
    client = MagicMock()
    client.messages.create.return_value = msg
    return client


VULN_97 = {
    "confidence": 0.97,
    "vuln_type": "sql_injection",
    "description": "SQL injection via f-string",
    "severity": "critical",
    "code_snippet": "query = f'SELECT * FROM users WHERE id={uid}'",
}

VULN_94 = {**VULN_97, "confidence": 0.94}
VULN_0 = {**VULN_97, "confidence": 0.0}


def test_sonnet_returns_vulnerability_at_95():
    client = _make_client(VULN_97)
    scanner = SonnetAnalysisScanner(client=client)
    result = scanner.analyze_line("app.py", 10, "source code")
    assert isinstance(result, Vulnerability)
    assert result.confidence == 0.97


def test_sonnet_returns_none_at_94():
    client = _make_client(VULN_94)
    scanner = SonnetAnalysisScanner(client=client)
    result = scanner.analyze_line("app.py", 10, "source code")
    assert result is None


def test_sonnet_returns_none_at_0():
    client = _make_client(VULN_0)
    scanner = SonnetAnalysisScanner(client=client)
    result = scanner.analyze_line("app.py", 10, "source code")
    assert result is None


def test_sonnet_low_confidence_is_logged():
    client = _make_client(VULN_94)
    scanner = SonnetAnalysisScanner(client=client)
    with patch("scanners.sonnet_scanner.logger") as mock_log:
        scanner.analyze_line("app.py", 10, "source code")
        mock_log.warning.assert_called_once()


def test_sonnet_calls_correct_model():
    client = _make_client(VULN_97)
    scanner = SonnetAnalysisScanner(client=client)
    scanner.analyze_line("app.py", 10, "source")
    call_kwargs = client.messages.create.call_args[1]
    assert call_kwargs["model"] == "claude-sonnet-4-6"


def test_sonnet_vulnerability_id_increments():
    client1 = _make_client(VULN_97)
    client2 = _make_client(VULN_97)
    # Reset counter for test isolation
    SonnetAnalysisScanner._counter = itertools.count(1)
    s1 = SonnetAnalysisScanner(client=client1)
    s2 = SonnetAnalysisScanner(client=client2)
    v1 = s1.analyze_line("app.py", 1, "src")
    v2 = s2.analyze_line("app.py", 2, "src")
    assert v1.id == "SWIFT-001"
    assert v2.id == "SWIFT-002"


def test_sonnet_invalid_json_returns_none():
    msg = MagicMock()
    msg.content = [MagicMock(text="not valid json at all")]
    client = MagicMock()
    client.messages.create.return_value = msg
    scanner = SonnetAnalysisScanner(client=client)
    result = scanner.analyze_line("app.py", 10, "source")
    assert result is None


def test_sonnet_missing_confidence_field_returns_none():
    client = _make_client({"vuln_type": "sql_injection", "description": "x"})
    scanner = SonnetAnalysisScanner(client=client)
    result = scanner.analyze_line("app.py", 10, "source")
    assert result is None


def test_sonnet_severity_normalized():
    client = _make_client(VULN_97)
    scanner = SonnetAnalysisScanner(client=client)
    result = scanner.analyze_line("app.py", 10, "source")
    assert result.severity == "CRITICAL"
