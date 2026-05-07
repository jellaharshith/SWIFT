"""Tests for WebSocket probe."""
import asyncio
import datetime
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from probes.websocket import WebSocketProbe, WebSocketDiscovery, WebSocketEndpoint, _sanitize
from sdk.base import VulnType, Severity
from sdk.testing import DEFAULT_TEST_ROE
from security.roe import ROE, ROEViolation


def test_sanitize_truncates():
    long_str = "x" * 10000
    assert len(_sanitize(long_str)) == 4096


def test_sanitize_cc():
    assert "[CC-REDACTED]" in _sanitize("card: 4111 1111 1111 1111")
    assert "4111" not in _sanitize("card: 4111 1111 1111 1111")


def test_sanitize_bearer():
    assert "[REDACTED]" in _sanitize("Authorization: Bearer eyJhbGci.abc")
    assert "eyJhbGci" not in _sanitize("Authorization: Bearer eyJhbGci.abc")


def test_websocket_endpoint_defaults():
    ep = WebSocketEndpoint(url="ws://x.com/ws")
    assert ep.is_socket_io is False
    assert ep.requires_auth is False


@pytest.mark.asyncio
async def test_ws_probe_simulate_only():
    roe = ROE(
        engagement_id="t", authorized_targets=["*"],
        allowed_techniques={"websocket_attack"},
        window_start=datetime.datetime(2025, 1, 1),
        window_end=datetime.datetime(2035, 1, 1),
        contact="t", simulate_only=True,
    )
    results = await WebSocketProbe().probe("http://target.com", None, roe)
    assert len(results) == 1
    assert results[0].severity == Severity.INFO


@pytest.mark.asyncio
async def test_ws_probe_roe_denied():
    roe = ROE(
        engagement_id="t", authorized_targets=["*"],
        allowed_techniques={"osint"},
        window_start=datetime.datetime(2025, 1, 1),
        window_end=datetime.datetime(2035, 1, 1),
        contact="t",
    )
    with pytest.raises(ROEViolation):
        await WebSocketProbe().probe("ws://target.com/ws", None, roe)


@pytest.mark.asyncio
async def test_ws_probe_no_endpoints_no_crash():
    """Probe with no discoverable endpoints returns without crashing."""
    with patch.object(WebSocketDiscovery, "discover", new=AsyncMock(return_value=[])):
        with patch.object(WebSocketProbe, "_unauthenticated_upgrade", new=AsyncMock(return_value=[])):
            with patch.object(WebSocketProbe, "_message_injection", new=AsyncMock(return_value=[])):
                results = await WebSocketProbe().probe("http://target.com", None, DEFAULT_TEST_ROE)
    # Should return empty list without raising
    assert isinstance(results, list)


@pytest.mark.asyncio
async def test_unauthenticated_upgrade_finding():
    """Simulate successful WS upgrade returning data."""
    probe = WebSocketProbe()
    ep = WebSocketEndpoint(url="ws://target.com/ws")

    mock_ws = AsyncMock()
    mock_ws.__aenter__ = AsyncMock(return_value=mock_ws)
    mock_ws.__aexit__ = AsyncMock(return_value=False)
    mock_ws.send = AsyncMock()
    mock_ws.recv = AsyncMock(return_value='{"user": "alice", "balance": 100}')

    with patch("probes.websocket.websockets.connect", return_value=mock_ws):
        findings = await probe._unauthenticated_upgrade(ep)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].vuln_type == VulnType.WEBSOCKET


@pytest.mark.asyncio
async def test_message_injection_reflected():
    """XSS payload reflected back triggers finding."""
    probe = WebSocketProbe()
    ep = WebSocketEndpoint(url="ws://target.com/ws")
    xss = "<script>alert('xss')</script>"

    mock_ws = AsyncMock()
    mock_ws.__aenter__ = AsyncMock(return_value=mock_ws)
    mock_ws.__aexit__ = AsyncMock(return_value=False)
    mock_ws.send = AsyncMock()
    mock_ws.recv = AsyncMock(return_value=f"echo: {xss}")

    with patch("probes.websocket.websockets.connect", return_value=mock_ws):
        findings = await probe._message_injection(ep)

    assert len(findings) >= 1
    assert findings[0].vuln_type == VulnType.WEBSOCKET
