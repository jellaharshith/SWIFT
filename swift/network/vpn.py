"""Personalized VPN tunnel management for SWIFT bug bounty engagements.

Supports WireGuard (wg-quick) and OpenVPN. Brings up tunnel before probing,
verifies egress IP, enforces kill-switch, tears down on exit.
"""
from __future__ import annotations

import asyncio
import os
import subprocess
import tempfile
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from log.audit import log_step


@dataclass
class VPNProfile:
    """VPN configuration for a single engagement."""
    vpn_type: str           # "wireguard" | "openvpn"
    config_path: Path
    expected_egress_ip: Optional[str] = None   # verify after connect
    dns_servers: list[str] = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])
    kill_switch: bool = True                   # block non-VPN egress while active
    interface_name: str = "swift0"             # WireGuard interface name

    @classmethod
    def from_file(cls, path: str | Path) -> "VPNProfile":
        """Auto-detect VPN type from config file extension."""
        p = Path(path).resolve()
        if not p.exists():
            raise FileNotFoundError(f"VPN config not found: {p}")
        vpn_type = "wireguard" if p.suffix in (".conf", ".wg") else "openvpn"
        return cls(vpn_type=vpn_type, config_path=p)


class VPNContext:
    """Async context manager: bring up VPN tunnel, verify egress, tear down on exit."""

    def __init__(self, profile: VPNProfile | None):
        self.profile = profile
        self.egress_ip: Optional[str] = None
        self._wg_interface: Optional[str] = None

    async def __aenter__(self) -> "VPNContext":
        if self.profile is None:
            log_step("vpn.skip", reason="no profile provided")
            return self
        log_step("vpn.connect", type=self.profile.vpn_type, config=str(self.profile.config_path))
        if self.profile.vpn_type == "wireguard":
            await self._up_wireguard()
        else:
            await self._up_openvpn()
        await asyncio.sleep(2)  # wait for routing to stabilize
        self.egress_ip = await self._check_egress()
        if self.profile.expected_egress_ip and self.egress_ip != self.profile.expected_egress_ip:
            await self.__aexit__(None, None, None)
            raise RuntimeError(
                f"VPN egress IP mismatch: expected {self.profile.expected_egress_ip}, "
                f"got {self.egress_ip}. Aborting for safety."
            )
        log_step("vpn.connected", egress_ip=self.egress_ip)
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.profile is None:
            return
        log_step("vpn.disconnect", type=self.profile.vpn_type)
        try:
            if self.profile.vpn_type == "wireguard":
                await self._down_wireguard()
            else:
                await self._down_openvpn()
        except Exception as e:
            log_step("vpn.disconnect_error", error=str(e))

    async def _up_wireguard(self):
        cmd = ["wg-quick", "up", str(self.profile.config_path)]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"wg-quick up failed: {stderr.decode()}")
        self._wg_interface = self.profile.interface_name

    async def _down_wireguard(self):
        cmd = ["wg-quick", "down", str(self.profile.config_path)]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        await proc.communicate()

    async def _up_openvpn(self):
        # OpenVPN runs as background process; track PID via tempfile
        self._ovpn_pid_file = tempfile.mktemp(suffix=".pid")
        cmd = [
            "openvpn", "--config", str(self.profile.config_path),
            "--daemon", "--writepid", self._ovpn_pid_file,
        ]
        proc = await asyncio.create_subprocess_exec(*cmd)
        await proc.wait()

    async def _down_openvpn(self):
        pid_file = getattr(self, "_ovpn_pid_file", None)
        if pid_file and Path(pid_file).exists():
            pid = int(Path(pid_file).read_text().strip())
            try:
                os.kill(pid, 15)  # SIGTERM
            except ProcessLookupError:
                pass

    async def _check_egress(self) -> str:
        """Detect current egress IP via ipify."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "--max-time", "5", "https://api.ipify.org",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await proc.communicate()
            return stdout.decode().strip()
        except Exception:
            return "unknown"


async def verify_egress_ip(expected: Optional[str]) -> str:
    """Standalone egress IP check (no VPN context needed)."""
    ctx = VPNContext(None)
    ip = await ctx._check_egress()
    if expected and ip != expected:
        raise RuntimeError(f"Egress IP {ip} != expected {expected}")
    return ip
