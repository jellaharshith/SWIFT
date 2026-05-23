"""Kali Linux container orchestration for SWIFT offensive security scanning."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Iterator

KALI_IMAGE = os.getenv("KALI_IMAGE_TAG", "swift-kali:latest")
CONTAINER_TIMEOUT = int(os.getenv("KALI_CONTAINER_TIMEOUT", "300"))

# MITRE ATT&CK technique mappings
MITRE_MAPPINGS: dict[str, dict] = {
    "nmap": {
        "technique_id": "T1046",
        "technique": "Network Service Discovery",
        "tactic": "Discovery",
    },
    "masscan": {
        "technique_id": "T1595",
        "technique": "Active Scanning",
        "tactic": "Reconnaissance",
    },
    "nikto": {
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "sqlmap": {
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing Application — SQL Injection",
        "tactic": "Initial Access",
    },
    "nuclei": {
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing Application — Template Scan",
        "tactic": "Initial Access",
    },
    "hydra": {
        "technique_id": "T1110",
        "technique": "Brute Force",
        "tactic": "Credential Access",
    },
    "gobuster": {
        "technique_id": "T1083",
        "technique": "File and Directory Discovery",
        "tactic": "Discovery",
    },
    "searchsploit": {
        "technique_id": "T1588.005",
        "technique": "Obtain Capabilities — Exploits",
        "tactic": "Resource Development",
    },
    "wfuzz": {
        "technique_id": "T1595.002",
        "technique": "Active Scanning: Vulnerability Scanning",
        "tactic": "Reconnaissance",
    },
    "ffuf": {
        "technique_id": "T1595.002",
        "technique": "Active Scanning: Vulnerability Scanning",
        "tactic": "Reconnaissance",
    },
    "httpx": {
        "technique_id": "T1595.001",
        "technique": "Active Scanning: Scanning IP Blocks",
        "tactic": "Reconnaissance",
    },
    "subfinder": {
        "technique_id": "T1590.001",
        "technique": "Gather Victim Network Info: Domain Properties",
        "tactic": "Reconnaissance",
    },
    "amass": {
        "technique_id": "T1590.001",
        "technique": "Gather Victim Network Info: Domain Properties",
        "tactic": "Reconnaissance",
    },
    "impacket": {
        "technique_id": "T1558.003",
        "technique": "Steal or Forge Kerberos Tickets: Kerberoasting",
        "tactic": "Credential Access",
    },
    "crackmapexec": {
        "technique_id": "T1021.002",
        "technique": "Remote Services: SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
    },
    "metasploit": {
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "openvas": {
        "technique_id": "T1595",
        "technique": "Active Scanning",
        "tactic": "Reconnaissance",
    },
    "semgrep": {
        "technique_id": "T1588.006",
        "technique": "Obtain Capabilities: Vulnerabilities",
        "tactic": "Resource Development",
    },
    "feroxbuster": {
        "technique_id": "T1595.002",
        "technique": "Active Scanning: Vulnerability Scanning",
        "tactic": "Reconnaissance",
    },
    "dalfox": {
        "technique_id": "T1059.007",
        "technique": "Command and Scripting Interpreter: JavaScript",
        "tactic": "Execution",
    },
    "zap": {
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "bloodhound-python": {
        "technique_id": "T1087.002",
        "technique": "Account Discovery: Domain Account",
        "tactic": "Discovery",
    },
}

ALL_TOOLS = [
    "nmap", "masscan", "nikto", "sqlmap", "nuclei", "gobuster", "searchsploit",
    "wfuzz", "ffuf", "httpx", "subfinder", "amass", "feroxbuster",
]


class KaliRunner:
    """Manages Kali Linux container for offensive security scanning."""

    def __init__(self, dockerfile_dir: str | None = None) -> None:
        self._dockerfile_dir = dockerfile_dir or str(Path(__file__).parent)

    def _check_docker(self) -> None:
        """Fail fast with clear message if docker daemon not running."""
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=5,
        )
        if result.returncode != 0:
            raise RuntimeError(
                "Docker daemon not running.\n"
                "  macOS: open Docker Desktop\n"
                "  Linux: sudo systemctl start docker"
            )

    def build_image(self, force: bool = False) -> None:
        """Build Kali container image from Dockerfile."""
        self._check_docker()
        if not force:
            check = subprocess.run(
                ["docker", "image", "inspect", KALI_IMAGE],
                capture_output=True
            )
            if check.returncode == 0:
                print(f"[*] Kali image {KALI_IMAGE} already exists. Use force=True to rebuild.")
                return

        print(f"[*] Building Kali container: {KALI_IMAGE} ...")
        proc = subprocess.run(
            ["docker", "build", "-t", KALI_IMAGE, self._dockerfile_dir],
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"docker build failed with exit code {proc.returncode}")
        print(f"[+] Kali image built: {KALI_IMAGE}")

    def _docker_exec(self, args: list[str], label: str) -> Iterator[str]:
        """Run command inside Kali container, stream stdout line by line."""
        import uuid
        container_name = f"swift-kali-{label.lower()}-{uuid.uuid4().hex[:8]}"
        cmd = [
            "docker", "run", "--rm",
            "--name", container_name,
            "--network=host",
            "--cap-add=NET_ADMIN",
            "--cap-add=NET_RAW",
            "--security-opt=no-new-privileges",
            "--entrypoint", "",
            KALI_IMAGE,
        ] + args
        print(f"\n[KALI/{label}] Running: {' '.join(args[:4])}...")
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        assert proc.stdout is not None
        timed_out = False

        def _kill_on_timeout() -> None:
            nonlocal timed_out
            timed_out = True
            subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
            proc.kill()

        timer = threading.Timer(CONTAINER_TIMEOUT, _kill_on_timeout)
        timer.start()
        exit_code = 0
        try:
            for line in proc.stdout:
                yield line.rstrip()
            exit_code = proc.wait()
        finally:
            timer.cancel()
        if timed_out:
            yield f"[KALI/{label}] TIMEOUT after {CONTAINER_TIMEOUT}s — container killed"
        elif exit_code != 0:
            yield f"[KALI/{label}] ERROR: docker exited with code {exit_code}"

    @staticmethod
    def _host_only(target: str) -> str:
        """Strip URL scheme/path so network tools receive a bare host/IP."""
        from urllib.parse import urlparse
        parsed = urlparse(target)
        return parsed.hostname or target

    def _run_nmap(self, target: str) -> dict:
        """T1046 — Network Service Discovery."""
        host = self._host_only(target)
        lines = list(self._docker_exec(
            ["nmap", "-sV", "-O", "--open", "-T2", "--max-rate", "100",
             "--scan-delay", "200ms", "-p", "1-10000", host],
            "NMAP",
        ))
        for line in lines:
            print(f"  {line}")
        return {
            "tool": "nmap",
            "target": target,
            "output": "\n".join(lines),
            **MITRE_MAPPINGS["nmap"],
        }

    def _run_masscan(self, target: str) -> dict:
        """T1595 — Active Scanning (fast port sweep)."""
        host = self._host_only(target)
        lines = list(self._docker_exec(
            ["masscan", host, "-p", "0-65535", "--rate=1000"],
            "MASSCAN",
        ))
        for line in lines:
            print(f"  {line}")
        return {
            "tool": "masscan",
            "target": target,
            "output": "\n".join(lines),
            **MITRE_MAPPINGS["masscan"],
        }

    def _run_nikto(self, target: str) -> dict:
        """T1190 — Web application vulnerability scan."""
        url = target if target.startswith("http") else f"http://{target}"
        lines = list(self._docker_exec(
            ["nikto", "-h", url, "-Format", "txt", "-evasion", "1"],
            "NIKTO",
        ))
        for line in lines:
            print(f"  {line}")
        return {
            "tool": "nikto",
            "target": url,
            "output": "\n".join(lines),
            **MITRE_MAPPINGS["nikto"],
        }

    def _run_sqlmap(self, target: str) -> dict:
        """T1190 — SQL injection detection."""
        url = target if target.startswith("http") else f"http://{target}"
        lines = list(self._docker_exec(
            ["sqlmap", "-u", url, "--batch", "--level=2", "--risk=1",
             "--output-dir=/tmp/sqlmap_out",
             "--random-agent", "--tamper=between,space2comment", "--delay=1"],
            "SQLMAP",
        ))
        for line in lines:
            print(f"  {line}")
        return {
            "tool": "sqlmap",
            "target": url,
            "output": "\n".join(lines),
            **MITRE_MAPPINGS["sqlmap"],
        }

    def _run_nuclei(self, target: str) -> dict:
        """T1190 — Template-based vulnerability scan."""
        url = target if target.startswith("http") else f"http://{target}"
        lines = list(self._docker_exec(
            ["nuclei", "-u", url, "-severity", "critical,high,medium",
             "-silent", "-json", "-rate-limit-minute", "30", "-timeout", "10"],
            "NUCLEI",
        ))
        findings = []
        raw_lines = []
        for line in lines:
            print(f"  {line}")
            raw_lines.append(line)
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return {
            "tool": "nuclei",
            "target": url,
            "output": "\n".join(raw_lines),
            "structured_findings": findings,
            **MITRE_MAPPINGS["nuclei"],
        }

    def _run_gobuster(self, target: str) -> dict:
        """T1083 — Directory and file discovery."""
        url = target if target.startswith("http") else f"http://{target}"
        lines = list(self._docker_exec(
            ["gobuster", "dir", "-u", url,
             "-w", "/usr/share/wordlists/dirb/common.txt",
             "-q", "-t", "20"],
            "GOBUSTER",
        ))
        for line in lines:
            print(f"  {line}")
        return {
            "tool": "gobuster",
            "target": url,
            "output": "\n".join(lines),
            **MITRE_MAPPINGS["gobuster"],
        }

    def _run_searchsploit(self, services: list[str]) -> dict:
        """T1588.005 — Match discovered services to known public exploits."""
        all_results: list[dict] = []
        raw_lines: list[str] = []
        for service in services[:5]:
            lines = list(self._docker_exec(
                ["searchsploit", "--json", service],
                "SEARCHSPLOIT",
            ))
            for line in lines:
                print(f"  {line}")
                raw_lines.append(line)
                try:
                    data = json.loads(line)
                    exploits = data.get("RESULTS_EXPLOIT", [])
                    for exp in exploits[:5]:
                        all_results.append({
                            "service": service,
                            "title": exp.get("Title", ""),
                            "edb_id": exp.get("EDB-ID", ""),
                            "type": exp.get("Type", ""),
                            "platform": exp.get("Platform", ""),
                        })
                except json.JSONDecodeError:
                    pass
        return {
            "tool": "searchsploit",
            "services_checked": services,
            "exploits_found": all_results,
            "output": "\n".join(raw_lines),
            **MITRE_MAPPINGS["searchsploit"],
        }

    def _run_wfuzz(self, target: str) -> dict:
        """T1595.002 — Fuzzing-based vulnerability scanning."""
        import time
        url = target if target.startswith("http") else f"http://{target}"
        timestamp = int(time.time())
        lines = list(self._docker_exec(
            ["wfuzz", "-u", f"{url}/FUZZ",
             "-w", "/usr/share/wordlists/dirb/common.txt",
             "--hc", "404", "-f", f"/tmp/wfuzz_{timestamp}.json,json"],
            "WFUZZ",
        ))
        for line in lines:
            print(f"  {line}")
        return {
            "tool": "wfuzz",
            "target": url,
            "output": "\n".join(lines),
            **MITRE_MAPPINGS["wfuzz"],
        }

    def _run_ffuf(self, target: str) -> dict:
        """T1595.002 — Fast web fuzzer with WAF evasion timing."""
        import time
        url = target if target.startswith("http") else f"http://{target}"
        timestamp = int(time.time())
        lines = list(self._docker_exec(
            ["ffuf", "-u", f"{url}/FUZZ",
             "-w", "/usr/share/wordlists/dirb/common.txt",
             "-p", "0.1-0.3",
             "-mc", "200,301,302,401,403",
             "-o", f"/tmp/ffuf_{timestamp}.json"],
            "FFUF",
        ))
        for line in lines:
            print(f"  {line}")
        return {
            "tool": "ffuf",
            "target": url,
            "output": "\n".join(lines),
            **MITRE_MAPPINGS["ffuf"],
        }

    def _run_httpx(self, target: str) -> dict:
        """T1595.001 — HTTP probe for live host discovery and tech fingerprint."""
        url = target if target.startswith("http") else f"http://{target}"
        lines = list(self._docker_exec(
            ["httpx", "-u", url, "-title", "-tech-detect", "-status-code",
             "-content-length", "-json"],
            "HTTPX",
        ))
        findings = []
        raw_lines = []
        for line in lines:
            print(f"  {line}")
            raw_lines.append(line)
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return {
            "tool": "httpx",
            "target": url,
            "output": "\n".join(raw_lines),
            "structured_findings": findings,
            **MITRE_MAPPINGS["httpx"],
        }

    def _run_subfinder(self, target: str) -> dict:
        """T1590.001 — Passive subdomain enumeration."""
        host = self._host_only(target)
        lines = list(self._docker_exec(
            ["subfinder", "-d", host, "-silent", "-json"],
            "SUBFINDER",
        ))
        subdomains = []
        raw_lines = []
        for line in lines:
            print(f"  {line}")
            raw_lines.append(line)
            try:
                subdomains.append(json.loads(line))
            except json.JSONDecodeError:
                if line.strip():
                    subdomains.append({"host": line.strip()})
        return {
            "tool": "subfinder",
            "target": host,
            "output": "\n".join(raw_lines),
            "subdomains": subdomains,
            **MITRE_MAPPINGS["subfinder"],
        }

    def _run_amass(self, target: str) -> dict:
        """T1590.001 — Active subdomain enumeration and ASN mapping."""
        host = self._host_only(target)
        lines = list(self._docker_exec(
            ["amass", "enum", "-passive", "-d", host, "-json",
             "/tmp/amass_out.json"],
            "AMASS",
        ))
        for line in lines:
            print(f"  {line}")
        return {
            "tool": "amass",
            "target": host,
            "output": "\n".join(lines),
            **MITRE_MAPPINGS["amass"],
        }

    def _run_feroxbuster(self, target: str) -> dict:
        """T1595.002 — Recursive content discovery with rate limiting."""
        url = target if target.startswith("http") else f"http://{target}"
        lines = list(self._docker_exec(
            ["feroxbuster", "-u", url, "--rate-limit", "50",
             "--timeout", "10", "-q"],
            "FEROXBUSTER",
        ))
        for line in lines:
            print(f"  {line}")
        return {
            "tool": "feroxbuster",
            "target": url,
            "output": "\n".join(lines),
            **MITRE_MAPPINGS["feroxbuster"],
        }

    def run_scan(
        self,
        target: str,
        tools: list[str] | None = None,
    ) -> dict:
        """Run all selected Kali tools against target, return mapped report."""
        tools = tools or ALL_TOOLS
        print(f"\n{'='*60}")
        print(f"[SWIFT-KALI] Target: {target}")
        print(f"[SWIFT-KALI] Tools:  {', '.join(tools)}")
        print(f"{'='*60}\n")

        results: list[dict] = []
        discovered_services: list[str] = []

        tool_dispatch = {
            "nmap": lambda: self._run_nmap(target),
            "masscan": lambda: self._run_masscan(target),
            "nikto": lambda: self._run_nikto(target),
            "sqlmap": lambda: self._run_sqlmap(target),
            "nuclei": lambda: self._run_nuclei(target),
            "gobuster": lambda: self._run_gobuster(target),
            "searchsploit": lambda: self._run_searchsploit(discovered_services or [target]),
            "wfuzz": lambda: self._run_wfuzz(target),
            "ffuf": lambda: self._run_ffuf(target),
            "httpx": lambda: self._run_httpx(target),
            "subfinder": lambda: self._run_subfinder(target),
            "amass": lambda: self._run_amass(target),
            "feroxbuster": lambda: self._run_feroxbuster(target),
        }

        for tool in tools:
            if tool not in tool_dispatch:
                print(f"[!] Unknown tool: {tool}, skipping")
                continue
            result = tool_dispatch[tool]()
            results.append(result)

            # Extract service names from nmap for searchsploit
            if tool == "nmap":
                output = result.get("output", "")
                for line in output.splitlines():
                    if "/tcp" in line and "open" in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            discovered_services.append(parts[2])

        return {
            "target": target,
            "scan_time": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
            "tools_run": tools,
            "results": results,
            "mitre_techniques": [
                {"id": r["technique_id"], "name": r["technique"], "tactic": r["tactic"]}
                for r in results
                if "technique_id" in r
            ],
        }
