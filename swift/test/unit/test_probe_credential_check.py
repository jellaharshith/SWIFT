"""Unit tests for CredentialCheckProbe."""
from __future__ import annotations

import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from sdk.base import Severity, VulnType


@pytest.mark.asyncio
async def test_no_hibp_key_returns_empty():
    from probes.credential_check import CredentialCheckProbe
    probe = CredentialCheckProbe()
    target = MagicMock()
    target.__str__ = lambda s: "https://example.com"
    target.params = {}
    with patch.dict(os.environ, {}, clear=True):
        os.environ.pop("HIBP_API_KEY", None)
        findings = await probe.probe(target, None, MagicMock(allowed_techniques={"osint"}))
    assert findings == []


@pytest.mark.asyncio
async def test_hibp_breach_creates_finding():
    from probes.credential_check import CredentialCheckProbe
    probe = CredentialCheckProbe()

    html_resp = MagicMock()
    html_resp.status_code = 200
    html_resp.text = "No emails here"

    breach_resp = MagicMock()
    breach_resp.status_code = 200
    breach_resp.json.return_value = [{"Name": "Adobe"}, {"Name": "LinkedIn"}]

    with patch.dict(os.environ, {"HIBP_API_KEY": "test-key"}):
        with patch("probes.credential_check.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(side_effect=[html_resp, breach_resp])

            target = MagicMock()
            target.__str__ = lambda s: "https://example.com"
            target.params = {"emails": ["victim@example.com"]}
            findings = await probe.probe(target, None, MagicMock(allowed_techniques={"osint"}))

    assert any(f.vuln_type == VulnType.CREDENTIAL_BREACH for f in findings)
    if findings:
        assert findings[0].confidence >= 0.95
        assert findings[0].severity == Severity.HIGH
