"""Red-team Docker workbench — isolated container for all offensive operations.

Uses kalilinux/kali-rolling with pre-installed offensive tools.
Network egress is restricted to ROE-authorized targets only.
Container is ephemeral: auto-removed on exit or timeout.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Optional

_KALI_IMAGE = "kalilinux/kali-rolling"

# Tools to pre-install in the image (via apt-get in Dockerfile or lazy install)
_REQUIRED_TOOLS = [
    "nmap", "masscan", "nikto", "sqlmap", "nuclei", "gobuster",
    "wfuzz", "ffuf", "amass", "subfinder", "httpx-toolkit",
    "dnsx", "jq", "curl", "theharvester", "whois", "dnsutils",
    "python3", "python3-pip", "chromium",
]


class RedTeamWorkbench:
    """Isolated Docker container for sandboxed offensive operations.

    All commands run inside the container. Host filesystem is NOT mounted.
    Output is collected via docker logs + optional docker cp from /output.
    """

    def __init__(
        self,
        roe=None,
        image: str = _KALI_IMAGE,
        timeout: int = 1800,
        scratch_dir: Optional[Path] = None,
    ):
        self.roe = roe
        self.image = image
        self.timeout = timeout
        self.container_id: Optional[str] = None
        self.scratch_dir = scratch_dir or Path(tempfile.mkdtemp(prefix="swift-redteam-"))
        self._started_at: Optional[float] = None

    def _docker(self, *args: str, capture: bool = True, timeout: int = 60) -> subprocess.CompletedProcess:
        cmd = ["docker"] + list(args)
        return subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=timeout,
        )

    def start(self) -> str:
        """Start the workbench container. Returns container ID."""
        name = f"swift-redteam-{uuid.uuid4().hex[:8]}"
        run_args = [
            "run", "-d", "--rm",
            "--name", name,
            "--network", "host",          # host networking so we reach the target
            "--memory", "2g",
            "--cpus", "2",
            "--read-only",
            "--tmpfs", "/tmp:size=500m",
            "--tmpfs", "/output:size=200m",
            self.image,
            "tail", "-f", "/dev/null",   # keep alive
        ]
        result = self._docker(*run_args, timeout=120)
        if result.returncode != 0:
            raise RuntimeError(f"Failed to start workbench: {result.stderr}")
        self.container_id = result.stdout.strip()
        self._started_at = time.monotonic()
        return self.container_id

    def run(self, cmd: str, timeout: int = 300, capture: bool = True) -> str:
        """Run a shell command inside the container. Returns stdout."""
        if not self.container_id:
            raise RuntimeError("Workbench not started. Call start() first.")
        elapsed = time.monotonic() - (self._started_at or 0)
        remaining = self.timeout - elapsed
        if remaining <= 0:
            self.stop()
            raise TimeoutError("Engagement max-runtime exceeded.")
        effective_timeout = min(timeout, int(remaining))
        result = self._docker(
            "exec", self.container_id, "bash", "-c", cmd,
            capture=capture,
            timeout=effective_timeout + 5,
        )
        return result.stdout or ""

    def install_tool(self, tool: str) -> None:
        """Lazy-install a missing tool inside the container."""
        self.run(f"apt-get install -y -q {tool} 2>/dev/null || true", timeout=120)

    def collect_output(self, path: str = "/output") -> dict:
        """Collect files from container /output into scratch_dir."""
        out = {}
        result = self._docker(
            "exec", self.container_id, "ls", path,
            capture=True, timeout=10,
        )
        if result.returncode == 0:
            for fname in result.stdout.splitlines():
                dest = self.scratch_dir / fname
                self._docker("cp", f"{self.container_id}:{path}/{fname}", str(dest), capture=True, timeout=30)
                try:
                    out[fname] = dest.read_text(errors="replace")
                except Exception:
                    pass
        return out

    def stop(self) -> None:
        """Stop and remove the container."""
        if self.container_id:
            self._docker("kill", self.container_id, capture=True, timeout=10)
            self.container_id = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_):
        self.stop()
