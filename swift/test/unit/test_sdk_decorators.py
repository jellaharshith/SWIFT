"""Tests for sdk.decorators."""
import datetime
import pytest
from unittest.mock import AsyncMock, MagicMock
from sdk.base import BaseModule, Finding, Phase, VulnType, Severity
from sdk.decorators import roe_gated, retry
from security.roe import ROE


def _make_roe(techniques, simulate=False):
    return ROE(
        engagement_id="test",
        authorized_targets=["*"],
        allowed_techniques=set(techniques),
        window_start=datetime.datetime(2025, 1, 1),
        window_end=datetime.datetime(2035, 1, 1),
        contact="test",
        simulate_only=simulate,
    )


class _Probe(BaseModule):
    name = "test_probe"; phase = Phase.ACTIVE
    vuln_types = [VulnType.XSS]; author = "test"; version = "1.0"

    @roe_gated("active_scan")
    async def probe(self, target, session, roe):
        return [Finding(module=self.name, vuln_type=VulnType.XSS, severity=Severity.HIGH,
                        title="xss", description="d", target_url=str(target), confidence=0.9)]


async def test_roe_gated_allowed():
    roe = _make_roe({"active_scan"})
    p = _Probe()
    results = await p.probe("http://x.com", None, roe)
    assert len(results) == 1
    assert results[0].severity == Severity.HIGH


async def test_roe_gated_denied_raises():
    from security.roe import ROEViolation
    roe = _make_roe({"osint"})
    p = _Probe()
    with pytest.raises(ROEViolation):
        await p.probe("http://x.com", None, roe)


async def test_roe_gated_simulate_only_returns_info():
    roe = _make_roe({"active_scan"}, simulate=True)
    p = _Probe()
    results = await p.probe("http://x.com", None, roe)
    assert len(results) == 1
    assert results[0].severity == Severity.INFO
    assert "[SIM]" in results[0].title


async def test_retry_succeeds_first_try():
    calls = []
    @retry(max_attempts=3)
    async def fn():
        calls.append(1)
        return "ok"
    result = await fn()
    assert result == "ok"
    assert len(calls) == 1


async def test_retry_retries_on_network_error():
    import httpx
    calls = []
    @retry(max_attempts=3, backoff="exponential")
    async def fn():
        calls.append(1)
        if len(calls) < 3:
            raise httpx.NetworkError("fail")
        return "ok"
    # Patch sleep to avoid delay
    import sdk.decorators as dec
    orig = asyncio.sleep if False else None
    import asyncio
    orig_sleep = asyncio.sleep
    async def fast_sleep(_): pass
    import sdk.decorators as dec_mod
    dec_mod.asyncio.sleep = fast_sleep
    try:
        result = await fn()
        assert result == "ok"
        assert len(calls) == 3
    finally:
        dec_mod.asyncio.sleep = orig_sleep
