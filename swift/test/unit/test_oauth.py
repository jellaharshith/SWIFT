"""Tests for OAuth/OIDC probe."""
import datetime
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from probes.oauth import OAuthProbe, OAuthDiscovery, OAuthSurface, _LIBRARY_PATTERNS
from sdk.base import VulnType, Severity
from sdk.testing import DEFAULT_TEST_ROE
from security.roe import ROE, ROEViolation


def test_library_patterns_defined():
    assert "auth0" in _LIBRARY_PATTERNS
    assert "okta" in _LIBRARY_PATTERNS
    assert "keycloak" in _LIBRARY_PATTERNS
    assert "cognito" in _LIBRARY_PATTERNS


def test_oauth_surface_defaults():
    s = OAuthSurface()
    assert s.authorization_endpoint == ""
    assert s.library_fingerprint is None


def test_fingerprint_auth0():
    assert OAuthDiscovery._fingerprint("auth0.com/oauth", {}) == "auth0"


def test_fingerprint_keycloak():
    assert OAuthDiscovery._fingerprint("/auth/realms/myrealm/openid-connect", {}) == "keycloak"


def test_fingerprint_unknown():
    assert OAuthDiscovery._fingerprint("example.com", {}) is None


async def test_oauth_probe_simulate_only():
    roe = ROE(
        engagement_id="t", authorized_targets=["*"],
        allowed_techniques={"oauth_attack"},
        window_start=datetime.datetime(2025, 1, 1),
        window_end=datetime.datetime(2035, 1, 1),
        contact="t", simulate_only=True,
    )
    results = await OAuthProbe().probe("http://target.com", None, roe)
    assert len(results) == 1
    assert results[0].severity == Severity.INFO


async def test_oauth_probe_roe_denied():
    roe = ROE(
        engagement_id="t", authorized_targets=["*"],
        allowed_techniques={"osint"},
        window_start=datetime.datetime(2025, 1, 1),
        window_end=datetime.datetime(2035, 1, 1),
        contact="t",
    )
    with pytest.raises(ROEViolation):
        await OAuthProbe().probe("http://target.com", None, roe)


async def test_oauth_probe_no_surface():
    with patch.object(OAuthDiscovery, "discover", new=AsyncMock(return_value=None)):
        results = await OAuthProbe().probe("http://target.com", None, DEFAULT_TEST_ROE)
    assert results == []


async def test_pkce_downgrade_detected():
    surface = OAuthSurface(
        authorization_endpoint="http://auth.target.com/authorize",
        token_endpoint="http://auth.target.com/token",
    )
    mock_resp = MagicMock()
    mock_resp.status_code = 302
    mock_resp.headers = {"location": "http://app.com/cb?code=abc123"}

    with patch("probes.oauth.httpx.AsyncClient") as MockClient:
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_cm)
        mock_cm.__aexit__ = AsyncMock(return_value=False)
        mock_cm.get = AsyncMock(return_value=mock_resp)
        MockClient.return_value = mock_cm
        findings = await OAuthProbe()._pkce_downgrade(surface, "http://target.com")

    assert len(findings) == 1
    assert findings[0].cwe_id == 287
    assert findings[0].severity == Severity.HIGH


async def test_implicit_flow_detected():
    surface = OAuthSurface(authorization_endpoint="http://auth.target.com/authorize")
    mock_resp = MagicMock()
    mock_resp.status_code = 302
    mock_resp.headers = {"location": "http://app.com/cb#access_token=eyJ"}

    with patch("probes.oauth.httpx.AsyncClient") as MockClient:
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_cm)
        mock_cm.__aexit__ = AsyncMock(return_value=False)
        mock_cm.get = AsyncMock(return_value=mock_resp)
        MockClient.return_value = mock_cm
        findings = await OAuthProbe()._token_leakage_recon(surface, "http://target.com")

    assert any(f.cwe_id == 522 for f in findings)
