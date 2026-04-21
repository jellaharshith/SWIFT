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


def test_sonnet_extracts_evidence_fields():
    """Test that Sonnet extracts all evidence bundle fields."""
    client = _make_client({
        "confidence": 0.97,
        "vuln_type": "sql_injection",
        "description": "SQL injection via f-string",
        "severity": "critical",
        "code_snippet": "query = f'SELECT * FROM users WHERE id={uid}'",
        "cwe_id": "CWE-89",
        "cwe_url": "https://cwe.mitre.org/data/definitions/89.html",
        "owasp_category": "A03:2021 – Injection",
        "exploit_description": "An attacker can modify SQL queries by injecting malicious input through the 'uid' parameter",
        "exploit_impact": "Data exfiltration, unauthorized access to user accounts, data modification or deletion",
        "remediation": "Use parameterized queries instead of f-strings. Replace f'SELECT...' with a prepared statement.",
        "remediation_code": "cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))",
        "remediation_effort": "LOW",
        "remediation_time_minutes": 10,
        "references": [
            "https://owasp.org/Top10/A03_2021-Injection/",
            "https://cwe.mitre.org/data/definitions/89.html",
        ]
    })
    scanner = SonnetAnalysisScanner(client=client)
    result = scanner.analyze_line("app.py", 5, "source")

    assert result is not None
    assert result.cwe_id == "CWE-89"
    assert result.cwe_url == "https://cwe.mitre.org/data/definitions/89.html"
    assert result.owasp_category == "A03:2021 – Injection"
    assert result.exploit_description == "An attacker can modify SQL queries by injecting malicious input through the 'uid' parameter"
    assert result.exploit_impact == "Data exfiltration, unauthorized access to user accounts, data modification or deletion"
    assert result.remediation == "Use parameterized queries instead of f-strings. Replace f'SELECT...' with a prepared statement."
    assert result.remediation_code == "cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))"
    assert result.remediation_effort == "LOW"
    assert result.remediation_time_minutes == 10
    assert result.references == [
        "https://owasp.org/Top10/A03_2021-Injection/",
        "https://cwe.mitre.org/data/definitions/89.html",
    ]


def test_sonnet_maps_cwe_to_owasp():
    """Test that CWE to OWASP mapping is correctly extracted."""
    cwe_owasp_mapping = {
        "CWE-89": "A03:2021 – Injection",
        "CWE-502": "A08:2021 – Software and Data Integrity Failures",
        "CWE-798": "A07:2021 – Identification and Authentication Failures",
        "CWE-327": "A02:2021 – Cryptographic Failures",
    }

    for cwe_id, owasp_cat in cwe_owasp_mapping.items():
        client = _make_client({
            "confidence": 0.96,
            "vuln_type": "unknown",
            "description": f"Vulnerability {cwe_id}",
            "severity": "high",
            "code_snippet": "code",
            "cwe_id": cwe_id,
            "owasp_category": owasp_cat,
            "exploit_description": "test",
            "exploit_impact": "test",
            "remediation": "test",
            "remediation_code": "test",
            "remediation_effort": "MEDIUM",
            "remediation_time_minutes": 30,
            "references": []
        })
        scanner = SonnetAnalysisScanner(client=client)
        result = scanner.analyze_line("app.py", 1, "src")

        assert result is not None
        assert result.cwe_id == cwe_id
        assert result.owasp_category == owasp_cat


def test_sonnet_generates_remediation_code():
    """Test that remediation code is correctly extracted and formatted."""
    vulnerable_code = "query = f'SELECT * FROM users WHERE id={uid}'"
    remediated_code = "cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))"

    client = _make_client({
        "confidence": 0.99,
        "vuln_type": "sql_injection",
        "description": "SQL injection via f-string",
        "severity": "critical",
        "code_snippet": vulnerable_code,
        "cwe_id": "CWE-89",
        "cwe_url": "https://cwe.mitre.org/data/definitions/89.html",
        "owasp_category": "A03:2021 – Injection",
        "exploit_description": "Attacker can inject SQL code",
        "exploit_impact": "Full database compromise",
        "remediation": "Use parameterized queries",
        "remediation_code": remediated_code,
        "remediation_effort": "LOW",
        "remediation_time_minutes": 5,
        "references": ["https://cwe.mitre.org/data/definitions/89.html"]
    })
    scanner = SonnetAnalysisScanner(client=client)
    result = scanner.analyze_line("app.py", 15, "source")

    assert result is not None
    assert result.remediation_code == remediated_code
    assert result.remediation_effort == "LOW"
    assert result.remediation_time_minutes == 5
    assert result.code_snippet == vulnerable_code


def test_sonnet_handles_missing_evidence_fields():
    """Test that missing evidence fields are handled gracefully."""
    client = _make_client({
        "confidence": 0.97,
        "vuln_type": "sql_injection",
        "description": "SQL injection",
        "severity": "high",
        "code_snippet": "code",
        # Missing all evidence fields
    })
    scanner = SonnetAnalysisScanner(client=client)
    result = scanner.analyze_line("app.py", 5, "source")

    assert result is not None
    assert result.cwe_id is None
    assert result.cwe_url is None
    assert result.owasp_category is None
    assert result.exploit_description is None
    assert result.exploit_impact is None
    assert result.remediation is None
    assert result.remediation_code is None
    assert result.remediation_effort is None
    assert result.remediation_time_minutes is None
    assert result.references == []


def test_sonnet_parses_remediation_time_as_integer():
    """Test that remediation_time_minutes is correctly parsed as integer."""
    client = _make_client({
        "confidence": 0.96,
        "vuln_type": "weak_crypto",
        "description": "Weak encryption",
        "severity": "high",
        "code_snippet": "code",
        "remediation_time_minutes": 25,  # Should be integer
        "references": []
    })
    scanner = SonnetAnalysisScanner(client=client)
    result = scanner.analyze_line("app.py", 5, "source")

    assert result is not None
    assert isinstance(result.remediation_time_minutes, int)
    assert result.remediation_time_minutes == 25


def test_sonnet_handles_invalid_remediation_time():
    """Test that invalid remediation_time_minutes is handled gracefully."""
    client = _make_client({
        "confidence": 0.96,
        "vuln_type": "weak_crypto",
        "description": "Weak encryption",
        "severity": "high",
        "code_snippet": "code",
        "remediation_time_minutes": "not_a_number",  # Invalid
        "references": []
    })
    scanner = SonnetAnalysisScanner(client=client)
    result = scanner.analyze_line("app.py", 5, "source")

    assert result is not None
    assert result.remediation_time_minutes is None


def test_sonnet_parses_references_list():
    """Test that references are correctly parsed as a list."""
    refs = [
        "https://owasp.org/Top10/A03_2021-Injection/",
        "https://cwe.mitre.org/data/definitions/89.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    ]
    client = _make_client({
        "confidence": 0.95,
        "vuln_type": "sql_injection",
        "description": "SQL injection",
        "severity": "critical",
        "code_snippet": "code",
        "references": refs
    })
    scanner = SonnetAnalysisScanner(client=client)
    result = scanner.analyze_line("app.py", 5, "source")

    assert result is not None
    assert result.references == refs
    assert len(result.references) == 3


def test_sonnet_handles_null_references():
    """Test that null references are converted to empty list."""
    client = _make_client({
        "confidence": 0.95,
        "vuln_type": "sql_injection",
        "description": "SQL injection",
        "severity": "critical",
        "code_snippet": "code",
        "references": None
    })
    scanner = SonnetAnalysisScanner(client=client)
    result = scanner.analyze_line("app.py", 5, "source")

    assert result is not None
    assert result.references == []


def test_sonnet_confidence_gate_still_enforced():
    """Test that the 95% confidence gate is still enforced with evidence fields."""
    client = _make_client({
        "confidence": 0.94,  # Below threshold
        "vuln_type": "sql_injection",
        "description": "SQL injection",
        "severity": "critical",
        "code_snippet": "code",
        "cwe_id": "CWE-89",
        "cwe_url": "https://cwe.mitre.org/data/definitions/89.html",
        "owasp_category": "A03:2021 – Injection",
        "remediation": "Use parameterized queries",
        "references": []
    })
    scanner = SonnetAnalysisScanner(client=client)
    result = scanner.analyze_line("app.py", 5, "source")

    assert result is None  # Should be suppressed due to low confidence
