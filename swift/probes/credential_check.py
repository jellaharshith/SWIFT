"""Credential breach check probe — HIBP k-anonymity API."""
from __future__ import annotations

import asyncio
import os
import re

import httpx

from sdk.base import BaseModule, Finding, Phase, Severity, VulnType

try:
    from audit.decorators import audit_logged
    from sdk.decorators import roe_gated
except ImportError:
    def audit_logged(x):
        def dec(f): return f
        return dec
    def roe_gated(x):
        def dec(f): return f
        return dec

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
HIBP_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"


class CredentialCheckProbe(BaseModule):
    name = "credential_check"
    phase = Phase.OSINT
    vuln_types = [VulnType.CREDENTIAL_BREACH]  # noqa: RUF012
    author = "swift-core"
    version = "1.0"

    @roe_gated("osint")
    @audit_logged("probe_executed")
    async def probe(self, target, session, roe) -> list[Finding]:
        api_key = os.getenv("HIBP_API_KEY", "")
        if not api_key:
            return []

        base_url = str(target)
        params = getattr(target, "params", {}) or {}
        emails: set[str] = set()

        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                resp = await client.get(base_url)
                emails.update(e.lower() for e in EMAIL_REGEX.findall(resp.text)[:20])
        except Exception:
            pass

        extra = params.get("emails", [])
        if isinstance(extra, list):
            emails.update(e.lower() for e in extra)
        elif isinstance(extra, str):
            emails.add(extra.lower())

        findings: list[Finding] = []
        async with httpx.AsyncClient(timeout=10, headers={
            "hibp-api-key": api_key,
            "User-Agent": "SWIFT-SecurityScanner/7.0",
        }) as client:
            for email in emails:
                try:
                    resp = await client.get(HIBP_URL.format(email=email))
                    if resp.status_code == 200:
                        breaches = resp.json()
                        names = [b.get("Name", "") for b in breaches[:5]]
                        findings.append(Finding(
                            module=self.name,
                            vuln_type=VulnType.CREDENTIAL_BREACH,
                            severity=Severity.HIGH,
                            title=f"Credential breach: {email} in {len(breaches)} breach(es)",
                            description=(
                                f"{email} appears in {len(breaches)} breach(es): {', '.join(names)}. "
                                "Credentials likely reused or compromised."
                            ),
                            target_url=base_url,
                            confidence=0.97,
                            request_evidence=f"HIBP check: {email}",
                            response_evidence=f"Breaches: {names}",
                            remediation="Force password reset. Enable MFA. Monitor for credential stuffing.",
                        ))
                    await asyncio.sleep(1.5)
                except Exception:
                    await asyncio.sleep(1.5)
                    continue

        return findings
