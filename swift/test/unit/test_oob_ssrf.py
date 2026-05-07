"""Tests for OOB SSRF probe — no real network calls."""
import asyncio
import datetime
import time
from unittest.mock import AsyncMock, patch
import pytest

from probes._oob.server import OOBCallbackServer, CallbackEvent
from probes.oob_ssrf import OOBSSRFProbe, _bypass_encodings
from sdk.base import VulnType, Severity
from sdk.testing import DEFAULT_TEST_ROE
from security.roe import ROE, ROEViolation


def test_bypass_encodings_aws():
    variants = _bypass_encodings("http://169.254.169.254/latest/")
    assert len(variants) >= 2
    assert "http://2852039166/" in variants


def test_bypass_encodings_localhost():
    variants = _bypass_encodings("http://127.0.0.1/")
    assert "http://[::1]/" in variants


def test_bypass_encodings_no_duplicates():
    variants = _bypass_encodings("http://169.254.169.254/")
    assert len(variants) == len(set(variants))


async def test_callback_server_starts():
    async with OOBCallbackServer(host="127.0.0.1") as cbs:
        assert cbs.port > 0
        url = cbs.alloc_url("tok1")
        assert "tok1" in url


async def test_callback_server_receives_http():
    import httpx
    async with OOBCallbackServer(host="127.0.0.1") as cbs:
        token = "testcb42"
        cb_url = cbs.alloc_url(token)
        try:
            async with httpx.AsyncClient(timeout=3) as client:
                await client.get(cb_url)
        except Exception:
            pass
        await asyncio.sleep(0.3)
        evt = await cbs.wait_for_callback(token, timeout=2.0)
        assert evt is not None
        assert evt.token == token


async def test_callback_server_timeout():
    async with OOBCallbackServer(host="127.0.0.1") as cbs:
        evt = await cbs.wait_for_callback("no_callback", timeout=0.3)
        assert evt is None


async def test_oob_ssrf_simulate_only():
    roe = ROE(
        engagement_id="t", authorized_targets=["*"],
        allowed_techniques={"oob_ssrf"},
        window_start=datetime.datetime(2025,1,1),
        window_end=datetime.datetime(2035,1,1),
        contact="t", simulate_only=True,
    )
    probe = OOBSSRFProbe()
    results = await probe.probe("http://target.com/?url=x", None, roe)
    assert len(results) == 1
    assert results[0].severity == Severity.INFO


async def test_oob_ssrf_roe_denied():
    roe = ROE(
        engagement_id="t", authorized_targets=["*"],
        allowed_techniques={"osint"},
        window_start=datetime.datetime(2025,1,1),
        window_end=datetime.datetime(2035,1,1),
        contact="t",
    )
    with pytest.raises(ROEViolation):
        await OOBSSRFProbe().probe("http://target.com/?url=x", None, roe)


async def test_oob_ssrf_confirmed_finding():
    mock_evt = CallbackEvent(
        token="abc", received_at=time.time(),
        source_ip="1.2.3.4", protocol="http",
        data={"method": "GET", "raw_request": "GET /abc HTTP/1.1"},
    )
    probe = OOBSSRFProbe()
    with patch("probes.oob_ssrf.OOBCallbackServer") as MockCBS:
        mock_cbs = AsyncMock()
        mock_cbs.__aenter__ = AsyncMock(return_value=mock_cbs)
        mock_cbs.__aexit__ = AsyncMock(return_value=False)
        mock_cbs.alloc_url.return_value = "http://127.0.0.1:9999/abc"
        mock_cbs.wait_for_callback = AsyncMock(return_value=mock_evt)
        MockCBS.return_value = mock_cbs
        with patch.object(probe, "_inject_http", new=AsyncMock()):
            results = await probe.probe(
                "http://target.com/?url=http://x.com", None, DEFAULT_TEST_ROE)

    assert len(results) >= 1
    oob = results[0]
    assert oob.oob_confirmed is True
    assert oob.confidence == 1.0
    assert oob.vuln_type == VulnType.OOB_SSRF
    assert oob.chain_primitive == "ssrf"


async def test_oob_ssrf_no_callback_no_finding():
    probe = OOBSSRFProbe()
    with patch("probes.oob_ssrf.OOBCallbackServer") as MockCBS:
        mock_cbs = AsyncMock()
        mock_cbs.__aenter__ = AsyncMock(return_value=mock_cbs)
        mock_cbs.__aexit__ = AsyncMock(return_value=False)
        mock_cbs.alloc_url.return_value = "http://127.0.0.1:9999/xyz"
        mock_cbs.wait_for_callback = AsyncMock(return_value=None)
        MockCBS.return_value = mock_cbs
        with patch.object(probe, "_inject_http", new=AsyncMock()):
            with patch.object(probe, "_try_reflected", new=AsyncMock(return_value=(False, ""))):
                results = await probe.probe(
                    "http://target.com/?url=http://x.com", None, DEFAULT_TEST_ROE)
    assert results == []
