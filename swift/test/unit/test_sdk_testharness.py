"""Tests for SwiftTestHarness and MockSessionManager."""
import datetime
import pytest
from sdk.base import BaseModule, Finding, Phase, VulnType, Severity
from sdk.testing import SwiftTestHarness, MockSessionManager, DEFAULT_TEST_ROE
from sdk.decorators import roe_gated


class _EchoProbe(BaseModule):
    name = "echo"; phase = Phase.ACTIVE; vuln_types = [VulnType.XSS]
    author = "test"; version = "1.0"

    @roe_gated("active_scan")
    async def probe(self, target, session, roe):
        return [Finding(module=self.name, vuln_type=VulnType.XSS, severity=Severity.HIGH,
                        title="xss", description="reflected", target_url=str(target),
                        confidence=0.95)]


class _SilentProbe(BaseModule):
    name = "silent"; phase = Phase.ACTIVE; vuln_types = [VulnType.SQLI]
    author = "test"; version = "1.0"

    @roe_gated("active_scan")
    async def probe(self, target, session, roe): return []


def test_mock_session_manager_headers():
    s = MockSessionManager()
    s.set_header("X-Test", "value")
    assert s.get_headers()["X-Test"] == "value"


def test_mock_session_manager_oauth_token():
    s = MockSessionManager()
    s.set_oauth_token("tok123")
    assert "Authorization" in s.get_headers()
    assert s._oauth_token == "tok123"


async def test_harness_run_returns_findings():
    h = SwiftTestHarness(_EchoProbe())
    findings = await h.run("http://target.com")
    assert len(findings) == 1
    assert findings[0].vuln_type == VulnType.XSS


async def test_harness_assert_finding_passes():
    h = SwiftTestHarness(_EchoProbe())
    await h.run("http://target.com")
    h.assert_finding(vuln_type="xss", severity="HIGH", min_confidence=0.9)


async def test_harness_assert_finding_fails():
    h = SwiftTestHarness(_SilentProbe())
    await h.run("http://target.com")
    with pytest.raises(AssertionError):
        h.assert_finding(vuln_type="sqli")


async def test_harness_assert_no_findings():
    h = SwiftTestHarness(_SilentProbe())
    await h.run("http://target.com")
    h.assert_no_findings()


def test_default_test_roe_has_all_techniques():
    required = {"active_scan", "oob_ssrf", "oauth_attack", "websocket_attack", "bizlogic"}
    assert required.issubset(DEFAULT_TEST_ROE.allowed_techniques)
    assert DEFAULT_TEST_ROE.simulate_only is False
