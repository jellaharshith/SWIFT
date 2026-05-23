"""CrackMapExec runner — SMB/WinRM/LDAP/MSSQL via Kali Docker."""
from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING

from log.audit import log_step
from security.roe import assert_technique_allowed

if TYPE_CHECKING:
    from security.roe import ROE


async def _kali_cme(args: list[str], timeout: int = 120) -> str:
    cmd = ["docker", "run", "--rm", "--network=host", "kalilinux/kali-rolling", "crackmapexec"] + args
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return out.decode(errors="replace")
    except Exception as exc:
        log_step("cme.error", error=str(exc)[:100])
        return ""


class CrackMapExecRunner:
    """Run CrackMapExec in Kali Docker for network service enumeration."""

    def __init__(self, roe: ROE) -> None:
        self.roe = roe

    async def run_smb_enum(
        self,
        target: str,
        domain: str = "",
        username: str = "",
        password: str = "",
    ) -> dict:
        assert_technique_allowed(self.roe, "active_scan")
        log_step("cme.smb.start", target=target)
        args = ["smb", target, "--shares", "--sessions"]
        if domain:
            args += ["-d", domain]
        if username:
            args += ["-u", username, "-p", password]
        output = await _kali_cme(args)
        shares = re.findall(r"SHARE\s+(\S+)", output)
        users = re.findall(r"loggedon-users[^\n]*\n\s+(\S+)", output)
        log_step("cme.smb.done", shares=len(shares))
        return {"shares": shares, "users": users, "raw": output[:2000]}

    async def run_winrm_enum(self, target: str, username: str, password: str) -> dict:
        assert_technique_allowed(self.roe, "active_scan")
        log_step("cme.winrm.start", target=target)
        output = await _kali_cme(["winrm", target, "-u", username, "-p", password])
        return {"authenticated": "Pwn3d!" in output, "raw": output[:1000]}

    async def run_ldap_enum(self, target: str, domain: str) -> dict:
        assert_technique_allowed(self.roe, "active_scan")
        log_step("cme.ldap.start", target=target)
        output = await _kali_cme(["ldap", target, "-d", domain, "--users", "--groups"])
        users = re.findall(r"User:\s+(\S+)", output)
        groups = re.findall(r"Group:\s+(.+)", output)
        return {"users": users, "groups": groups, "raw": output[:2000]}
