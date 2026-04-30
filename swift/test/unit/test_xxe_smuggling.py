"""Unit tests for XXE probe and HTTP smuggling detector (Layer 4)."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from browser.playwright_runner import BrowserScanResult, _probe_xxe
from browser.smuggling_probe import SmugglingResult, probe_smuggling


class TestProbeXxe:
    def test_detects_xxe_via_root_in_response(self):
        page = MagicMock()
        page.goto = AsyncMock()
        page.evaluate = AsyncMock(return_value="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1")
        result = BrowserScanResult(target="http://example.com")
        asyncio.run(_probe_xxe(page, "http://example.com", result))
        assert any(f.kind == "xxe" for f in result.findings)

    def test_detects_xxe_via_imds_in_response(self):
        page = MagicMock()
        page.goto = AsyncMock()
        page.evaluate = AsyncMock(return_value="169.254.169.254 ami-id")
        result = BrowserScanResult(target="http://example.com")
        asyncio.run(_probe_xxe(page, "http://example.com", result))
        assert any(f.kind == "xxe" for f in result.findings)

    def test_no_finding_when_response_clean(self):
        page = MagicMock()
        page.goto = AsyncMock()
        page.evaluate = AsyncMock(return_value="<error>XML parse error</error>")
        result = BrowserScanResult(target="http://example.com")
        asyncio.run(_probe_xxe(page, "http://example.com", result))
        assert not any(f.kind == "xxe" for f in result.findings)

    def test_skips_when_deadline_exceeded(self):
        import time
        page = MagicMock()
        page.evaluate = AsyncMock()
        result = BrowserScanResult(target="http://example.com")
        past = time.monotonic() - 1.0
        asyncio.run(_probe_xxe(page, "http://example.com", result, deadline=past))
        page.evaluate.assert_not_called()

    def test_finding_severity_is_critical(self):
        page = MagicMock()
        page.goto = AsyncMock()
        page.evaluate = AsyncMock(return_value="root:x:0:0")
        result = BrowserScanResult(target="http://example.com")
        asyncio.run(_probe_xxe(page, "http://example.com", result))
        findings = [f for f in result.findings if f.kind == "xxe"]
        assert findings[0].severity == "critical"


class TestSmugglingResult:
    def test_default_not_vulnerable(self):
        r = SmugglingResult()
        assert r.vulnerable is False
        assert r.variant == ""
        assert r.error is None

    def test_vulnerable_fields(self):
        r = SmugglingResult(vulnerable=True, variant="CL.TE", evidence="GPOST found")
        assert r.vulnerable is True
        assert r.variant == "CL.TE"


class TestProbeSmugglingConnectionRefused:
    def test_returns_error_on_connection_refused(self):
        async def run():
            with patch("browser.smuggling_probe._send_raw", side_effect=ConnectionRefusedError("refused")):
                return await probe_smuggling("127.0.0.1", 9999, "/")

        result = asyncio.run(run())
        assert result.vulnerable is False
        assert result.error is not None

    def test_returns_not_vulnerable_on_clean_response(self):
        async def run():
            with patch("browser.smuggling_probe._send_raw", return_value="HTTP/1.1 200 OK\r\n\r\nOK"):
                return await probe_smuggling("127.0.0.1", 80, "/")

        result = asyncio.run(run())
        assert result.vulnerable is False
