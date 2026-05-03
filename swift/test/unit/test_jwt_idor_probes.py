"""Unit tests for JWT alg:none and IDOR probes (Layer 3)."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from browser.playwright_runner import BrowserFinding, BrowserScanResult, _probe_jwt, _probe_idor


def _make_page(content: str = "<html></html>") -> MagicMock:
    page = MagicMock()
    page.set_extra_http_headers = AsyncMock()
    page.goto = AsyncMock()
    page.content = AsyncMock(return_value=content)
    page.evaluate = AsyncMock(return_value=None)
    return page


class TestProbeJwt:
    def test_adds_finding_when_admin_in_response(self):
        page = _make_page("<html>Welcome admin dashboard</html>")
        result = BrowserScanResult(target="http://example.com")
        asyncio.run(_probe_jwt(page, "http://example.com", result))
        assert any(f.kind == "jwt_alg_none" for f in result.findings)

    def test_no_finding_when_no_admin_keyword(self):
        page = _make_page("<html>Login page</html>")
        result = BrowserScanResult(target="http://example.com")
        asyncio.run(_probe_jwt(page, "http://example.com", result))
        assert not any(f.kind == "jwt_alg_none" for f in result.findings)

    def test_skips_when_deadline_exceeded(self):
        page = _make_page()
        result = BrowserScanResult(target="http://example.com")
        import time
        past_deadline = time.monotonic() - 1.0
        asyncio.run(_probe_jwt(page, "http://example.com", result, deadline=past_deadline))
        page.goto.assert_not_called()

    def test_finding_severity_is_high(self):
        page = _make_page("<html>admin profile</html>")
        result = BrowserScanResult(target="http://example.com")
        asyncio.run(_probe_jwt(page, "http://example.com", result))
        findings = [f for f in result.findings if f.kind == "jwt_alg_none"]
        assert findings[0].severity == "high"

    def test_resets_headers_after_probe(self):
        page = _make_page("<html>admin</html>")
        result = BrowserScanResult(target="http://example.com")
        asyncio.run(_probe_jwt(page, "http://example.com", result))
        # Second call to set_extra_http_headers should be with empty dict
        calls = page.set_extra_http_headers.call_args_list
        assert calls[-1].args[0] == {}


class TestProbeIdor:
    def test_detects_size_diff_over_10_percent(self):
        baseline = "x" * 1000
        variant = "y" * 1200  # 20% larger

        call_count = 0

        async def mock_content():
            nonlocal call_count
            call_count += 1
            return baseline if call_count == 1 else variant

        page = MagicMock()
        page.goto = AsyncMock()
        page.content = mock_content

        result = BrowserScanResult(target="http://example.com")
        asyncio.run(_probe_idor(page, "http://example.com?id=5", result))
        assert any(f.kind == "idor" for f in result.findings)

    def test_skips_non_numeric_params(self):
        page = _make_page()
        result = BrowserScanResult(target="http://example.com")
        asyncio.run(_probe_idor(page, "http://example.com?name=alice", result))
        assert page.goto.call_count == 0

    def test_no_finding_when_404_in_variant(self):
        baseline = "x" * 1000
        variant = "not found 404 error" * 100

        call_count = 0

        async def mock_content():
            nonlocal call_count
            call_count += 1
            return baseline if call_count == 1 else variant

        page = MagicMock()
        page.goto = AsyncMock()
        page.content = mock_content

        result = BrowserScanResult(target="http://example.com")
        asyncio.run(_probe_idor(page, "http://example.com?id=5", result))
        assert not any(f.kind == "idor" for f in result.findings)

    def test_skips_when_deadline_exceeded(self):
        page = _make_page()
        result = BrowserScanResult(target="http://example.com")
        import time
        past_deadline = time.monotonic() - 1.0
        asyncio.run(_probe_idor(page, "http://example.com?id=5", result, deadline=past_deadline))
        page.goto.assert_not_called()

    def test_no_finding_when_size_diff_under_threshold(self):
        baseline = "x" * 1000
        variant = "y" * 1050  # 5% — under 10% threshold

        call_count = 0

        async def mock_content():
            nonlocal call_count
            call_count += 1
            return baseline if call_count == 1 else variant

        page = MagicMock()
        page.goto = AsyncMock()
        page.content = mock_content

        result = BrowserScanResult(target="http://example.com")
        asyncio.run(_probe_idor(page, "http://example.com?id=5", result))
        assert not any(f.kind == "idor" for f in result.findings)
