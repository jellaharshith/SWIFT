"""Unit tests for expanded browser/probes.py payload constants."""
from __future__ import annotations

import pytest

from browser.probes import (
    SSTI_PAYLOADS,
    SSTI_SIGNATURES,
    JWT_ATTACKS,
    JWT_WEAK_SECRETS,
    IDOR_PROBES,
    AUTH_BYPASS_HEADERS,
    AUTH_BYPASS_PATHS,
    NOSQL_PAYLOADS,
    PROTOTYPE_POLLUTION_PAYLOADS,
    CRLF_PAYLOADS,
    XXE_PAYLOADS,
    SMUGGLING_PROBES,
)


def test_ssti_payloads_defined():
    assert len(SSTI_PAYLOADS) >= 3
    assert any("7*7" in p for p in SSTI_PAYLOADS), "Expected a 7*7 expression in SSTI_PAYLOADS"


def test_ssti_signatures():
    assert "49" in SSTI_SIGNATURES


def test_nosql_payloads_defined():
    assert len(NOSQL_PAYLOADS) >= 2


def test_auth_bypass_headers_defined():
    assert "X-Forwarded-For" in AUTH_BYPASS_HEADERS
    assert AUTH_BYPASS_HEADERS["X-Forwarded-For"] == "127.0.0.1"


def test_prototype_pollution_payloads_defined():
    assert any("__proto__" in p for p in PROTOTYPE_POLLUTION_PAYLOADS)


def test_jwt_attacks_alg_none():
    assert "alg_none" in JWT_ATTACKS
    # alg:none token has no signature — ends with "."
    assert JWT_ATTACKS["alg_none"].endswith(".")


def test_jwt_weak_secrets():
    assert "secret" in JWT_WEAK_SECRETS
    assert "" in JWT_WEAK_SECRETS  # empty secret must be present


def test_idor_probes_sequential():
    assert IDOR_PROBES("1") == ["2", "0"]
    assert IDOR_PROBES("5") == ["6", "4"]
    assert IDOR_PROBES("0") == ["1", "0"]


def test_idor_probes_non_numeric():
    # Non-numeric IDs should return empty list gracefully
    assert IDOR_PROBES("abc") == []


def test_auth_bypass_paths():
    assert "..;/admin" in AUTH_BYPASS_PATHS
    assert "/.admin" in AUTH_BYPASS_PATHS


def test_crlf_payloads():
    assert len(CRLF_PAYLOADS) >= 2
    assert any("swift_crlf" in p for p in CRLF_PAYLOADS)


def test_xxe_payloads():
    assert len(XXE_PAYLOADS) == 2
    assert any("file:///etc/passwd" in p for p in XXE_PAYLOADS)
    assert any("169.254.169.254" in p for p in XXE_PAYLOADS)


def test_smuggling_probes_structure():
    assert len(SMUGGLING_PROBES) >= 2
    for probe in SMUGGLING_PROBES:
        assert "method" in probe
        assert "cl" in probe
        assert "te" in probe
        assert "body" in probe
        assert probe["method"] == "POST"


def test_ssti_signatures_includes_twig_output():
    # Twig {{7*'7'}} evaluates to "7777777"
    assert "7777777" in SSTI_SIGNATURES
