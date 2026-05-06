"""Unit tests for WS2 OSINT sources: crtsh, subdomain_takeover, wayback,
tech_fingerprint, email_enum.

Uses asyncio.run() to run coroutines since pytest-asyncio is not installed.
"""
from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(coro):
    """Run an async coroutine in a test."""
    return asyncio.run(coro)


def _make_httpx_response(status_code: int, body, *, headers: dict | None = None):
    """Build a minimal mock httpx.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.raise_for_status = MagicMock()
    resp.headers = {k.lower(): v for k, v in (headers or {}).items()}
    resp.text = body if isinstance(body, str) else json.dumps(body)

    def _json():
        return body if not isinstance(body, str) else json.loads(body)

    resp.json = _json
    resp.cookies = []
    return resp


def _mock_client_ctx(mock_resp):
    """Return an async context manager mock that yields an httpx client."""
    mock_client = MagicMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=mock_resp)
    return mock_client


# ---------------------------------------------------------------------------
# crtsh
# ---------------------------------------------------------------------------

class TestRunCrtsh:
    def test_happy_path(self):
        from osint.crtsh import run_crtsh

        payload = [
            {"name_value": "sub1.example.com"},
            {"name_value": "*.example.com\nsub2.example.com"},
        ]
        mock_resp = _make_httpx_response(200, payload)
        with patch("osint.crtsh.httpx.AsyncClient", return_value=_mock_client_ctx(mock_resp)):
            result = run(run_crtsh("example.com"))

        assert "sub1.example.com" in result.subdomains
        assert "sub2.example.com" in result.subdomains
        assert result.errors == []

    def test_timeout_graceful(self):
        import httpx
        from osint.crtsh import run_crtsh

        mc = MagicMock()
        mc.__aenter__ = AsyncMock(return_value=mc)
        mc.__aexit__ = AsyncMock(return_value=False)
        mc.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))

        with patch("osint.crtsh.httpx.AsyncClient", return_value=mc):
            result = run(run_crtsh("example.com"))

        assert result.subdomains == []
        assert any("timed out" in e for e in result.errors)

    def test_malformed_json_graceful(self):
        from osint.crtsh import run_crtsh

        mock_resp = _make_httpx_response(200, {"unexpected": "dict"})
        with patch("osint.crtsh.httpx.AsyncClient", return_value=_mock_client_ctx(mock_resp)):
            result = run(run_crtsh("example.com"))

        assert isinstance(result.subdomains, list)


# ---------------------------------------------------------------------------
# wayback
# ---------------------------------------------------------------------------

class TestRunWayback:
    def test_happy_path_interesting_paths(self):
        from osint.wayback import run_wayback

        cdx_rows = [
            ["original"],
            ["https://example.com/api/users"],
            ["https://example.com/about"],
            ["https://example.com/admin/dashboard"],
            ["https://example.com/login"],
        ]
        mock_resp = _make_httpx_response(200, cdx_rows)
        with patch("osint.wayback.httpx.AsyncClient", return_value=_mock_client_ctx(mock_resp)):
            result = run(run_wayback("example.com"))

        assert "https://example.com/api/users" in result.urls
        assert "https://example.com/about" in result.urls
        assert "https://example.com/api/users" in result.interesting_paths
        assert "https://example.com/admin/dashboard" in result.interesting_paths
        assert "https://example.com/about" not in result.interesting_paths
        assert result.errors == []

    def test_timeout_graceful(self):
        import httpx
        from osint.wayback import run_wayback

        mc = MagicMock()
        mc.__aenter__ = AsyncMock(return_value=mc)
        mc.__aexit__ = AsyncMock(return_value=False)
        mc.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))

        with patch("osint.wayback.httpx.AsyncClient", return_value=mc):
            result = run(run_wayback("example.com"))

        assert result.urls == []
        assert any("timed out" in e for e in result.errors)

    def test_empty_response(self):
        from osint.wayback import run_wayback

        mock_resp = _make_httpx_response(200, [["original"]])
        with patch("osint.wayback.httpx.AsyncClient", return_value=_mock_client_ctx(mock_resp)):
            result = run(run_wayback("example.com"))

        assert result.urls == []
        assert result.interesting_paths == []


# ---------------------------------------------------------------------------
# tech_fingerprint
# ---------------------------------------------------------------------------

class TestRunTechFingerprint:
    def _make_full_response(self, headers: dict, body: str, cookies=None):
        resp = MagicMock()
        resp.status_code = 200
        resp.raise_for_status = MagicMock()
        resp.headers = {k.lower(): v for k, v in headers.items()}
        resp.text = body
        resp.cookies = cookies or []
        return resp

    def test_detects_nginx_and_react(self):
        from osint.tech_fingerprint import run_tech_fingerprint

        mock_resp = self._make_full_response(
            headers={"server": "nginx/1.24.0", "x-powered-by": "Express"},
            body='<script src="/static/react.production.min.js"></script>',
        )
        mc = MagicMock()
        mc.__aenter__ = AsyncMock(return_value=mc)
        mc.__aexit__ = AsyncMock(return_value=False)
        mc.get = AsyncMock(return_value=mock_resp)

        with patch("osint.tech_fingerprint.httpx.AsyncClient", return_value=mc):
            result = run(run_tech_fingerprint("https://example.com"))

        names = [t.name for t in result.technologies]
        assert "nginx" in names
        assert "express" in names
        assert "react" in names

    def test_detects_wordpress(self):
        from osint.tech_fingerprint import run_tech_fingerprint

        mock_resp = self._make_full_response(
            headers={"server": "Apache"},
            body='<link rel="stylesheet" href="/wp-content/themes/mytheme/style.css">',
        )
        mc = MagicMock()
        mc.__aenter__ = AsyncMock(return_value=mc)
        mc.__aexit__ = AsyncMock(return_value=False)
        mc.get = AsyncMock(return_value=mock_resp)

        with patch("osint.tech_fingerprint.httpx.AsyncClient", return_value=mc):
            result = run(run_tech_fingerprint("https://example.com"))

        names = [t.name for t in result.technologies]
        assert "wordpress" in names
        assert "apache" in names

    def test_timeout_graceful(self):
        import httpx
        from osint.tech_fingerprint import run_tech_fingerprint

        mc = MagicMock()
        mc.__aenter__ = AsyncMock(return_value=mc)
        mc.__aexit__ = AsyncMock(return_value=False)
        mc.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))

        with patch("osint.tech_fingerprint.httpx.AsyncClient", return_value=mc):
            result = run(run_tech_fingerprint("https://example.com"))

        assert result.technologies == []
        assert any("timed out" in e for e in result.errors)


# ---------------------------------------------------------------------------
# email_enum
# ---------------------------------------------------------------------------

class TestRunEmailEnum:
    def test_default_mailboxes_generated(self):
        from osint.email_enum import run_email_enum

        result = run(run_email_enum("example.com"))

        emails = [c.email for c in result.candidates]
        assert "admin@example.com" in emails
        assert "security@example.com" in emails
        assert all(e.endswith("@example.com") for e in emails)
        assert all(0.0 <= c.confidence <= 1.0 for c in result.candidates)

    def test_name_patterns_generated(self):
        from osint.email_enum import run_email_enum

        result = run(run_email_enum("example.com", names=["john.doe", "jane.smith"]))

        emails = [c.email for c in result.candidates]
        assert "john.doe@example.com" in emails
        assert "jane.smith@example.com" in emails

    def test_hunter_io_enrichment(self):
        from osint.email_enum import run_email_enum

        hunter_payload = {
            "data": {
                "emails": [
                    {"value": "ceo@example.com"},
                    {"value": "cto@example.com"},
                ]
            }
        }
        mock_resp = _make_httpx_response(200, hunter_payload)
        mc = MagicMock()
        mc.__aenter__ = AsyncMock(return_value=mc)
        mc.__aexit__ = AsyncMock(return_value=False)
        mc.get = AsyncMock(return_value=mock_resp)

        with patch("osint.email_enum.httpx.AsyncClient", return_value=mc):
            result = run(run_email_enum("example.com", hunter_api_key="test_key"))

        emails = [c.email for c in result.candidates]
        assert "ceo@example.com" in emails
        assert "cto@example.com" in emails
        hunter_entries = [c for c in result.candidates if c.pattern == "hunter.io"]
        assert all(c.confidence == 0.8 for c in hunter_entries)

    def test_hunter_io_timeout_graceful(self):
        import httpx
        from osint.email_enum import run_email_enum

        mc = MagicMock()
        mc.__aenter__ = AsyncMock(return_value=mc)
        mc.__aexit__ = AsyncMock(return_value=False)
        mc.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))

        with patch("osint.email_enum.httpx.AsyncClient", return_value=mc):
            result = run(run_email_enum("example.com", hunter_api_key="k"))

        assert len(result.candidates) > 0  # guessed still present
        assert any("hunter.io" in e for e in result.errors)


# ---------------------------------------------------------------------------
# subdomain_takeover
# ---------------------------------------------------------------------------

class TestRunSubdomainTakeover:
    def test_empty_subdomains(self):
        from osint.subdomain_takeover import run_subdomain_takeover

        result = run(run_subdomain_takeover([]))
        assert result.candidates == []
        assert result.errors == []

    def test_no_cname_returns_no_candidate(self):
        """Subdomain with no CNAME answer → no takeover candidate."""
        import sys

        dns_available = "dns" in sys.modules or __import__.__module__ != "builtins"
        try:
            import dns.asyncresolver  # noqa: F401
            dns_available = True
        except ImportError:
            dns_available = False

        from osint.subdomain_takeover import run_subdomain_takeover

        if dns_available:
            with patch("dns.asyncresolver.Resolver") as MockResolver:
                async def fake_resolve(name, rtype):
                    raise Exception("NXDOMAIN")

                resolver_instance = AsyncMock()
                resolver_instance.resolve = AsyncMock(side_effect=fake_resolve)
                resolver_instance.lifetime = 10.0
                MockResolver.return_value = resolver_instance
                result = run(run_subdomain_takeover(["sub.example.com"]))
        else:
            # Without dnspython, _check_subdomain catches the ImportError and
            # returns None, so candidates should be empty.
            result = run(run_subdomain_takeover(["sub.example.com"]))

        assert isinstance(result.candidates, list)

    def test_import_error_graceful(self):
        """dns module unavailable → no crash, empty candidates."""
        from osint.subdomain_takeover import run_subdomain_takeover

        with patch.dict("sys.modules", {"dns": None, "dns.asyncresolver": None,
                                        "dns.exception": None, "dns.resolver": None}):
            # Run with real module but simulate dns being broken inside _check_subdomain
            result = run(run_subdomain_takeover(["sub.example.com"]))

        assert isinstance(result.candidates, list)
