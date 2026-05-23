"""Metasploit framework runner via msfrpc API — simulate_only default."""
from __future__ import annotations

import asyncio
import subprocess
from typing import TYPE_CHECKING

from log.audit import log_step
from security.roe import assert_technique_allowed

if TYPE_CHECKING:
    from security.roe import ROE

MSF_CONTAINER = "swift-msf"
MSF_PORT = 55553
MSF_PASS = "swift"  # noqa: S105


class MetasploitRunner:
    """Run Metasploit modules via msfrpc. Default: simulate_only=True."""

    def __init__(self, roe: ROE, simulate_only: bool = True) -> None:
        self.roe = roe
        self.simulate_only = simulate_only

    async def run_module(self, module_path: str, options: dict, roe: ROE) -> dict:
        assert_technique_allowed(roe, "exploit")

        if self.simulate_only or getattr(roe, "simulate_only", True):
            log_step("metasploit.simulate", module=module_path)
            return {
                "simulated": True,
                "module": module_path,
                "options": options,
                "result": "Simulation only — set simulate_only=False in ROE and MetasploitRunner to execute",
            }

        log_step("metasploit.execute", module=module_path)
        try:
            return await self._live_run(module_path, options)
        finally:
            await self._cleanup()

    async def _live_run(self, module_path: str, options: dict) -> dict:
        try:
            from pymetasploit3.msfrpc import MsfRpcClient  # type: ignore
        except ImportError:
            return {"error": "pymetasploit3 not installed — pip install pymetasploit3"}

        subprocess.run(
            [
                "docker", "run", "-d", "--name", MSF_CONTAINER,
                "--network=host", "kalilinux/kali-rolling",
                "msfrpcd", "-P", MSF_PASS, "-a", "0.0.0.0", "-p", str(MSF_PORT), "-S",
            ],
            timeout=30, check=False, capture_output=True,
        )
        await asyncio.sleep(5)

        loop = asyncio.get_event_loop()

        def _run_sync() -> dict:
            client = MsfRpcClient(MSF_PASS, port=MSF_PORT)
            exploit = client.modules.use("exploit", module_path)
            for key, val in options.items():
                exploit[key] = val
            result = exploit.execute(payload="generic/shell_reverse_tcp")
            return {"job_id": result.get("job_id"), "uuid": result.get("uuid")}

        return await loop.run_in_executor(None, _run_sync)

    async def _cleanup(self) -> None:
        subprocess.run(
            ["docker", "stop", MSF_CONTAINER],
            timeout=10, check=False, capture_output=True,
        )

    async def check_module_exists(self, module_path: str) -> bool:
        output = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: subprocess.run(
                [
                    "docker", "run", "--rm", "kalilinux/kali-rolling",
                    "msfconsole", "-q", "-x", f"search {module_path}; exit",
                ],
                capture_output=True, text=True, timeout=60,
            ).stdout,
        )
        return module_path in output
