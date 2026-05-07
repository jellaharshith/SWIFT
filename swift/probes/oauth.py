"""OAuth/OIDC attack surface probe (Module 2)."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import httpx

from audit.decorators import audit_logged
from sdk.base import BaseModule, Finding, Phase, Severity, VulnType
from sdk.decorators import roe_gated

_LIBRARY_PATTERNS = {
    "auth0": ["auth0.com", "auth0", ".auth0."],
    "okta": ["okta.com", "okta", ".okta."],
    "keycloak": ["keycloak", "/auth/realms/"],
    "cognito": ["cognito", "amazonaws.com/oauth2", "x-amzn-"],
}


@dataclass
class OAuthSurface:
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    jwks_uri: str = ""
    supported_grant_types: list[str] = field(default_factory=list)
    supported_response_types: list[str] = field(default_factory=list)
    library_fingerprint: str | None = None


class OAuthDiscovery:
    """Discover OAuth/OIDC endpoints and fingerprint the library."""

    async def discover(self, base_url: str, session=None) -> OAuthSurface | None:
        surface = OAuthSurface()
        # 1. Try OIDC discovery document
        oidc_url = base_url.rstrip("/") + "/.well-known/openid-configuration"
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                resp = await client.get(oidc_url)
                if resp.status_code == 200:
                    data = resp.json()
                    surface.authorization_endpoint = data.get("authorization_endpoint", "")
                    surface.token_endpoint = data.get("token_endpoint", "")
                    surface.jwks_uri = data.get("jwks_uri", "")
                    surface.supported_grant_types = data.get("grant_types_supported", [])
                    surface.supported_response_types = data.get("response_types_supported", [])
                    surface.library_fingerprint = self._fingerprint(resp.text, dict(resp.headers))
                    return surface
        except Exception:
            pass

        # 2. Crawl common paths
        candidates = ["/oauth/authorize", "/authorize", "/oauth/token", "/token", "/connect/authorize"]
        try:
            async with httpx.AsyncClient(timeout=10, verify=False,
                                         follow_redirects=False) as client:
                for path in candidates:
                    try:
                        r = await client.get(base_url.rstrip("/") + path)
                        if r.status_code in (200, 302, 400):
                            if not surface.authorization_endpoint and "authorize" in path:
                                surface.authorization_endpoint = base_url.rstrip("/") + path
                            if not surface.token_endpoint and "token" in path:
                                surface.token_endpoint = base_url.rstrip("/") + path
                            fp = self._fingerprint(r.text, dict(r.headers))
                            if fp:
                                surface.library_fingerprint = fp
                    except Exception:
                        pass
        except Exception:
            pass

        return surface if (surface.authorization_endpoint or surface.token_endpoint) else None

    @staticmethod
    def _fingerprint(body: str, headers: dict) -> str | None:
        combined = body.lower() + " ".join(f"{k}:{v}".lower() for k, v in headers.items())
        for lib, patterns in _LIBRARY_PATTERNS.items():
            if any(p.lower() in combined for p in patterns):
                return lib
        return None


class OAuthProbe(BaseModule):
    name = "oauth"
    phase = Phase.ACTIVE
    vuln_types = [VulnType.OAUTH]  # noqa: RUF012
    author = "swift-core"
    version = "1.0"

    @roe_gated("oauth_attack")
    @audit_logged("probe_executed")
    async def probe(self, target, session, roe) -> list[Finding]:
        base_url = str(target)
        findings: list[Finding] = []

        surface = await OAuthDiscovery().discover(base_url, session)
        if not surface:
            return []

        tasks = [
            self._pkce_downgrade(surface, base_url),
            self._token_leakage_recon(surface, base_url),
            self._client_credential_stuffing(surface, base_url, session),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)

        return findings

    async def _pkce_downgrade(self, surface: OAuthSurface, base_url: str) -> list[Finding]:
        """Attempt authorization without PKCE code_challenge."""
        if not surface.authorization_endpoint:
            return []
        findings = []
        try:
            async with httpx.AsyncClient(timeout=10, verify=False,
                                         follow_redirects=False) as client:
                params = {
                    "response_type": "code",
                    "client_id": "test",
                    "redirect_uri": base_url,
                    "scope": "openid",
                    # Intentionally omitting code_challenge
                }
                resp = await client.get(surface.authorization_endpoint, params=params)
                # If we get a redirect with code= and no PKCE error, it's vulnerable
                location = resp.headers.get("location", "")
                if ("code=" in location and "error" not in location
                        and resp.status_code in (302, 301)):
                    findings.append(Finding(
                        module=self.name,
                        vuln_type=VulnType.OAUTH,
                        severity=Severity.HIGH,
                        title="OAuth PKCE downgrade: authorization code issued without code_challenge",
                        description="Server accepted auth code flow without requiring PKCE code_challenge.",
                        target_url=surface.authorization_endpoint,
                        confidence=0.8,
                        cwe_id=287,
                        remediation="Enforce PKCE (RFC 7636) for all public clients.",
                        request_evidence=str(params),
                        response_evidence=f"Location: {location[:200]}",
                    ))
        except Exception:
            pass
        return findings

    async def _token_leakage_recon(self, surface: OAuthSurface, base_url: str) -> list[Finding]:
        """Check for implicit flow and token leakage in URLs/headers."""
        if not surface.authorization_endpoint:
            return []
        findings = []
        try:
            async with httpx.AsyncClient(timeout=10, verify=False,
                                         follow_redirects=False) as client:
                params = {
                    "response_type": "token",
                    "client_id": "test",
                    "redirect_uri": base_url,
                    "scope": "openid",
                }
                resp = await client.get(surface.authorization_endpoint, params=params)
                location = resp.headers.get("location", "")
                if "access_token=" in location:
                    findings.append(Finding(
                        module=self.name,
                        vuln_type=VulnType.OAUTH,
                        severity=Severity.HIGH,
                        title="OAuth implicit flow active: access_token in redirect URL",
                        description="Server returned access_token in URL fragment (implicit flow). Tokens exposed to browser history and referrer headers.",
                        target_url=surface.authorization_endpoint,
                        confidence=0.9,
                        cwe_id=522,
                        remediation="Disable implicit flow. Use authorization code flow with PKCE.",
                        request_evidence=str(params),
                        response_evidence=f"Location: {location[:200]}",
                    ))

            # Check Wayback for historical token leakage
            try:
                from osint.wayback import fetch_wayback_urls
                urls = await fetch_wayback_urls(base_url)
                leaked = [u for u in (urls or []) if "access_token=" in u or "id_token=" in u]
                if leaked:
                    findings.append(Finding(
                        module=self.name,
                        vuln_type=VulnType.OAUTH,
                        severity=Severity.MEDIUM,
                        title=f"Historical OAuth token leakage in {len(leaked)} archived URL(s)",
                        description=f"Wayback Machine has {len(leaked)} URLs with OAuth tokens in query strings.",
                        target_url=base_url,
                        confidence=0.7,
                        cwe_id=522,
                        remediation="Rotate all exposed tokens. Switch to POST-based token exchange.",
                        raw_metadata={"leaked_urls": leaked[:5]},
                    ))
            except Exception:
                pass
        except Exception:
            pass
        return findings

    async def _client_credential_stuffing(
        self, surface: OAuthSurface, base_url: str, session
    ) -> list[Finding]:
        """Try common client_id/secret pairs against token endpoint."""
        if not surface.token_endpoint:
            return []
        findings = []
        client_ids = ["admin", "test", "mobile", "api", "internal", "demo", "app"]
        secrets_list = ["secret", "password", "123456", "changeme", "client_secret", "admin"]
        attempts = 0
        max_attempts = 50
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                for cid in client_ids:
                    for sec in secrets_list:
                        if attempts >= max_attempts:
                            break
                        attempts += 1
                        try:
                            resp = await client.post(
                                surface.token_endpoint,
                                data={
                                    "grant_type": "client_credentials",
                                    "client_id": cid,
                                    "client_secret": sec,
                                },
                            )
                            if resp.status_code == 200:
                                data = resp.json()
                                if data.get("access_token"):
                                    if session:
                                        session.set_oauth_token(data["access_token"])
                                    findings.append(Finding(
                                        module=self.name,
                                        vuln_type=VulnType.OAUTH,
                                        severity=Severity.CRITICAL,
                                        title=f"OAuth client credential stuffing: valid token with client_id={cid!r}",
                                        description=f"Token endpoint accepted client_id={cid!r} with weak secret.",
                                        target_url=surface.token_endpoint,
                                        confidence=1.0,
                                        cwe_id=287,
                                        chain_primitive="oauth_token",
                                        remediation="Rotate all client credentials. Use strong random secrets.",
                                        request_evidence=f"client_id={cid}&client_secret=***",
                                    ))
                                    return findings
                        except Exception:
                            pass
                        await asyncio.sleep(2.0)  # rate limit: 1 req/2s
        except Exception:
            pass
        return findings
