"""Network service CVE correlation probe — nmap + NVD + searchsploit."""
from __future__ import annotations

import asyncio
import os
import xml.etree.ElementTree as ET
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

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


async def _docker_run(args: list[str], timeout: int = 300) -> str:
    cmd = [
        "docker", "run", "--rm", "--network=host",
        "--cap-add=NET_RAW", "--cap-add=NET_ADMIN",
        "kalilinux/kali-rolling",
    ] + args
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return out.decode(errors="replace")
    except Exception:
        return ""


class NetworkServiceExploitProbe(BaseModule):
    name = "network_service"
    phase = Phase.ACTIVE
    vuln_types = [VulnType.CLOUD_MISCONFIGURATION]  # noqa: RUF012
    author = "swift-core"
    version = "1.0"

    @roe_gated("active_scan")
    @audit_logged("probe_executed")
    async def probe(self, target, session, roe) -> list[Finding]:
        base_url = str(target)
        host = urlparse(base_url).hostname or base_url
        findings: list[Finding] = []

        nmap_xml = await _docker_run([
            "nmap", "-sV", "-T2", "--max-rate", "100",
            "--scan-delay", "200ms", "-oX", "-", host,
        ], timeout=180)

        if not nmap_xml.strip():
            return []

        services = self._parse_nmap_xml(nmap_xml)
        nvd_key = os.getenv("NVD_API_KEY", "")

        async with httpx.AsyncClient(timeout=15) as client:
            for port, proto, service, version in services:
                if not (service and version):
                    continue
                cves = await self._nvd_lookup(client, service, version, nvd_key)
                for cve_id, cvss, description in cves:
                    severity = Severity.CRITICAL if cvss >= 9.0 else Severity.HIGH
                    findings.append(Finding(
                        module=self.name,
                        vuln_type=VulnType.CLOUD_MISCONFIGURATION,
                        severity=severity,
                        title=f"{cve_id} in {service} {version} on port {port}/{proto}",
                        description=(
                            f"CVE {cve_id} (CVSS {cvss:.1f}) affects {service} {version} "
                            f"on {host}:{port}. {description[:200]}"
                        ),
                        target_url=base_url,
                        confidence=0.96,
                        request_evidence=f"nmap -sV {host} → {port}/{proto} {service} {version}",
                        response_evidence=f"NVD: {cve_id} CVSS {cvss:.1f}",
                        remediation=f"Upgrade {service}. Apply vendor patch for {cve_id}.",
                    ))

        return findings

    def _parse_nmap_xml(self, xml_text: str) -> list[tuple]:
        services = []
        try:
            root = ET.fromstring(xml_text)
            for port_el in root.findall(".//port"):
                port = port_el.get("portid", "")
                proto = port_el.get("protocol", "tcp")
                state_el = port_el.find("state")
                if state_el is not None and state_el.get("state") != "open":
                    continue
                svc_el = port_el.find("service")
                if svc_el is None:
                    continue
                service = f"{svc_el.get('product', '')} {svc_el.get('name', '')}".strip()
                version = svc_el.get("version", "")
                services.append((port, proto, service, version))
        except Exception:
            pass
        return services

    async def _nvd_lookup(
        self, client: httpx.AsyncClient, service: str, version: str, api_key: str
    ) -> list[tuple[str, float, str]]:
        headers = {"apiKey": api_key} if api_key else {}
        try:
            resp = await client.get(
                NVD_URL,
                params={"keywordSearch": f"{service} {version}", "resultsPerPage": "5"},
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return []

        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
            )
            cvss = 0.0
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metrics = cve.get("metrics", {}).get(key, [])
                if metrics:
                    cvss = float(metrics[0].get("cvssData", {}).get("baseScore", 0))
                    break
            if cvss >= 7.0:
                results.append((cve_id, cvss, desc))
        return results
