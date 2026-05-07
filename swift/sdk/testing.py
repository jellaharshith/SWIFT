"""SwiftTestHarness: test utilities for module authors."""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Optional
from unittest.mock import AsyncMock, MagicMock

from security.roe import ROE
from .base import BaseModule, Finding, Severity, VulnType


DEFAULT_TEST_ROE = ROE(
    engagement_id="test",
    authorized_targets=["*"],
    allowed_techniques={
        "osint", "active_scan", "exploit", "post_exploit",
        "oob_ssrf", "oauth_attack", "websocket_attack", "bizlogic", "agentic_loop",
        "chain_execution",
    },
    window_start=datetime.datetime(2025, 1, 1),
    window_end=datetime.datetime(2035, 12, 31),
    contact="test",
    simulate_only=False,
)


class MockSessionManager:
    """Minimal SessionManager stub for use in tests."""

    def __init__(self) -> None:
        self._headers: dict[str, str] = {}
        self._cookies: dict[str, str] = {}
        self._oauth_token: Optional[str] = None
        self._ws_token: Optional[str] = None

    def get_headers(self) -> dict[str, str]:
        return dict(self._headers)

    def get_cookies(self) -> dict[str, str]:
        return dict(self._cookies)

    def set_header(self, key: str, value: str) -> None:
        self._headers[key] = value

    def set_cookie(self, key: str, value: str) -> None:
        self._cookies[key] = value

    def set_oauth_token(self, token: str, expires_at: Optional[datetime.datetime] = None) -> None:
        self._oauth_token = token
        self._headers["Authorization"] = f"Bearer {token}"

    def set_ws_token(self, token: str) -> None:
        self._ws_token = token

    async def attach(self, page) -> None:
        pass

    async def capture(self, page) -> None:
        pass


class SwiftTestHarness:
    """Test harness for BaseModule subclasses.

    Usage:
        harness = SwiftTestHarness(MyProbe())
        harness.mock_http("http://target.com/api", 200, '{"data": "x"}')
        findings = await harness.run("http://target.com")
        harness.assert_finding(VulnType.SSRF, min_confidence=0.9)
    """

    def __init__(self, module: BaseModule) -> None:
        self._module = module
        self._http_mocks: list[dict] = []
        self._playwright_mocks: list[dict] = []
        self._findings: list[Finding] = []

    def mock_http(self, url: str, status: int, body: str,
                  headers: dict[str, str] | None = None) -> None:
        self._http_mocks.append({"url": url, "status": status,
                                  "body": body, "headers": headers or {}})

    def mock_playwright(self, url: str, html: str) -> None:
        self._playwright_mocks.append({"url": url, "html": html})

    async def run(self, target_url: str, roe: ROE = DEFAULT_TEST_ROE) -> list[Finding]:
        session = MockSessionManager()
        self._findings = await self._module.probe(target_url, session, roe)
        return self._findings

    def assert_finding(self, vuln_type: Optional[str] = None,
                       severity: Optional[str] = None,
                       min_confidence: float = 0.0) -> None:
        for f in self._findings:
            type_ok = vuln_type is None or f.vuln_type.value == vuln_type
            sev_ok = severity is None or f.severity.value == severity
            conf_ok = f.confidence >= min_confidence
            if type_ok and sev_ok and conf_ok:
                return
        raise AssertionError(
            f"No finding matching vuln_type={vuln_type!r} severity={severity!r} "
            f"min_confidence={min_confidence} in {self._findings}"
        )

    def assert_no_findings(self) -> None:
        if self._findings:
            raise AssertionError(f"Expected no findings but got: {self._findings}")

    def assert_roe_respected(self, technique: str) -> None:
        """Verify module raises ROEViolation when technique is not allowed."""
        import asyncio
        from security.roe import ROEViolation
        restricted_roe = ROE(
            engagement_id="restricted",
            authorized_targets=["*"],
            allowed_techniques=set(),
            window_start=datetime.datetime(2025, 1, 1),
            window_end=datetime.datetime(2035, 12, 31),
            contact="test",
        )
        session = MockSessionManager()
        raised = False
        try:
            asyncio.get_event_loop().run_until_complete(
                self._module.probe("http://target.com", session, restricted_roe)
            )
        except (ROEViolation, SystemExit):
            raised = True
        if not raised:
            raise AssertionError(f"Expected ROEViolation for technique={technique!r}")
