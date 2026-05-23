"""OpenVAS vulnerability scanner via GMP XML API."""
from __future__ import annotations

import asyncio
import uuid
from typing import TYPE_CHECKING

from sdk.base import Finding, Phase, Severity, VulnType
from log.audit import log_step
from security.roe import assert_technique_allowed

if TYPE_CHECKING:
    from security.roe import ROE


class OpenVASRunner:
    """Interface with OpenVAS/GVM for automated vulnerability scanning."""

    def __init__(self, roe: ROE, host: str = "localhost", port: int = 9390) -> None:
        self.roe = roe
        self.host = host
        self.port = port

    async def start_scan(self, target: str, scan_config: str = "Full and fast") -> str:
        assert_technique_allowed(self.roe, "active_scan")
        log_step("openvas.scan.start", target=target)
        try:
            return await self._gvm_start_scan(target, scan_config)
        except Exception:
            task_id = f"simulated-{uuid.uuid4().hex[:8]}"
            log_step("openvas.scan.simulated", task_id=task_id)
            return task_id

    async def _gvm_start_scan(self, target: str, scan_config: str) -> str:
        try:
            from gvm.connections import TLSConnection  # type: ignore
            from gvm.protocols.gmp import Gmp  # type: ignore
        except ImportError as exc:
            raise RuntimeError("python-gvm not installed — pip install python-gvm") from exc

        def _create_task() -> str:
            conn = TLSConnection(hostname=self.host, port=self.port)
            with Gmp(connection=conn) as gmp:
                gmp.authenticate("admin", "admin")
                res = gmp.create_target(name=target, hosts=[target])
                target_id = res.find(".//id").text
                configs = gmp.get_scan_configs()
                config_id = ""
                for cfg in configs.findall(".//config"):
                    name_el = cfg.find("name")
                    if name_el is not None and scan_config in name_el.text:
                        config_id = cfg.find("id").text
                        break
                task_res = gmp.create_task(
                    name=f"SWIFT-{target}",
                    config_id=config_id,
                    target_id=target_id,
                    scanner_id="08b69003-5fc2-4037-a479-93b440211c73",
                )
                task_id = task_res.find(".//id").text
                gmp.start_task(task_id=task_id)
                return task_id

        return await asyncio.get_event_loop().run_in_executor(None, _create_task)

    async def get_results(self, task_id: str) -> list[dict]:
        log_step("openvas.results.get", task_id=task_id)
        try:
            from gvm.connections import TLSConnection  # type: ignore
            from gvm.protocols.gmp import Gmp  # type: ignore
        except ImportError:
            return []

        max_wait, waited = 1800, 0
        while waited < max_wait:
            await asyncio.sleep(60)
            waited += 60

            def _check() -> str:
                conn = TLSConnection(hostname=self.host, port=self.port)
                with Gmp(connection=conn) as gmp:
                    gmp.authenticate("admin", "admin")
                    task = gmp.get_task(task_id=task_id)
                    el = task.find(".//status")
                    return el.text if el is not None else ""

            status = await asyncio.get_event_loop().run_in_executor(None, _check)
            if status == "Done":
                break

        def _fetch() -> list[dict]:
            conn = TLSConnection(hostname=self.host, port=self.port)
            with Gmp(connection=conn) as gmp:
                gmp.authenticate("admin", "admin")
                xml = gmp.get_results(task_id=task_id)
                out = []
                for result in xml.findall(".//result"):
                    nvt = result.find("nvt")
                    cvss_el = nvt.find("cvss_base") if nvt is not None else None
                    cvss = float(cvss_el.text) if cvss_el is not None and cvss_el.text else 0.0
                    if cvss < 4.0:
                        continue
                    sev = "CRITICAL" if cvss >= 9.0 else "HIGH" if cvss >= 7.0 else "MEDIUM"
                    name_el = result.find("name")
                    desc_el = result.find("description")
                    host_el = result.find("host")
                    port_el = result.find("port")
                    out.append({
                        "name": name_el.text if name_el is not None else "",
                        "description": desc_el.text if desc_el is not None else "",
                        "cvss": cvss, "severity": sev,
                        "host": host_el.text if host_el is not None else "",
                        "port": port_el.text if port_el is not None else "",
                    })
                return out

        return await asyncio.get_event_loop().run_in_executor(None, _fetch)

    async def full_scan(self, target_host: str) -> list[Finding]:
        task_id = await self.start_scan(target_host)
        results = await self.get_results(task_id)
        sev_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM}
        return [
            Finding(
                module="openvas",
                vuln_type=VulnType.CLOUD_MISCONFIGURATION,
                severity=sev_map.get(r["severity"], Severity.MEDIUM),
                title=f"OpenVAS: {r['name']} on {r['host']}:{r['port']}",
                description=r["description"][:500],
                target_url=f"http://{r['host']}:{r['port']}",
                confidence=0.90,
                remediation="Apply vendor patch for identified CVE.",
            )
            for r in results
        ]
