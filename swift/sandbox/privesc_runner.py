"""Docker-based privilege-escalation tester.

Runs a hardened container against the target workspace and probes for
common privesc primitives: SUID binaries, sudo NOPASSWD, writable /etc,
capabilities, world-writable PATH dirs, kernel banner.

All steps logged via log.audit.log_step.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path

from log.audit import log_step


PRIVESC_PROBE_SCRIPT = r"""#!/bin/sh
set +e
echo "=== kernel ==="
uname -a
echo "=== id ==="
id
echo "=== suid_binaries ==="
find / -xdev -perm -4000 -type f 2>/dev/null | head -200
echo "=== sgid_binaries ==="
find / -xdev -perm -2000 -type f 2>/dev/null | head -200
echo "=== capabilities ==="
getcap -r / 2>/dev/null | head -100 || true
echo "=== sudo ==="
sudo -n -l 2>&1 | head -50 || true
echo "=== writable_etc ==="
find /etc -xdev -writable -type f 2>/dev/null | head -100
echo "=== world_writable_path ==="
for d in $(echo $PATH | tr ':' ' '); do
  find "$d" -maxdepth 1 -perm -0002 -type f 2>/dev/null
done
echo "=== cron ==="
ls -la /etc/cron* 2>/dev/null
echo "=== done ==="
"""


@dataclass
class PrivescResult:
    success: bool = False
    container_id: str | None = None
    exit_code: int = -1
    findings: list[dict] = field(default_factory=list)
    raw_output: str = ""
    errors: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _parse_findings(stdout: str) -> list[dict]:
    findings: list[dict] = []
    section = None
    buckets: dict[str, list[str]] = {}
    for line in stdout.splitlines():
        if line.startswith("=== ") and line.endswith(" ==="):
            section = line.strip("= ").strip()
            buckets[section] = []
            continue
        if section and line.strip():
            buckets[section].append(line.rstrip())

    suid = buckets.get("suid_binaries", [])
    dangerous_suid = [b for b in suid if any(x in b for x in (
        "/nmap", "/find", "/perl", "/python", "/bash", "/vim", "/less", "/awk",
        "/wget", "/curl", "/cp", "/mv", "/tar", "/zip", "/nano",
    ))]
    if dangerous_suid:
        findings.append({
            "kind": "dangerous_suid",
            "severity": "critical",
            "evidence": dangerous_suid[:20],
        })

    sudo_lines = buckets.get("sudo", [])
    if any("NOPASSWD" in l for l in sudo_lines):
        findings.append({
            "kind": "sudo_nopasswd",
            "severity": "critical",
            "evidence": [l for l in sudo_lines if "NOPASSWD" in l],
        })

    writable_etc = [l for l in buckets.get("writable_etc", []) if l]
    sensitive_etc = [l for l in writable_etc if any(p in l for p in (
        "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/cron",
    ))]
    if sensitive_etc:
        findings.append({
            "kind": "writable_sensitive_etc",
            "severity": "critical",
            "evidence": sensitive_etc,
        })

    caps = buckets.get("capabilities", [])
    risky_caps = [c for c in caps if any(x in c for x in (
        "cap_setuid", "cap_dac_override", "cap_sys_admin", "cap_sys_ptrace",
    ))]
    if risky_caps:
        findings.append({
            "kind": "risky_capabilities",
            "severity": "high",
            "evidence": risky_caps,
        })

    wpath = [l for l in buckets.get("world_writable_path", []) if l]
    if wpath:
        findings.append({
            "kind": "world_writable_path_entries",
            "severity": "high",
            "evidence": wpath,
        })

    return findings


def run_privesc_scan(
    repo_path: str,
    artifacts_root: str = ".swift-artifacts/privesc",
    image: str = "ubuntu:22.04",
    timeout: int = 120,
    allow_ptrace: bool = False,
) -> PrivescResult:
    result = PrivescResult()
    source = Path(repo_path).resolve()
    artifacts = Path(artifacts_root).resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    audit_log = artifacts / "audit.log.jsonl"

    if not source.exists():
        result.errors.append(f"repo not found: {source}")
        log_step("privesc.fail", reason="repo_missing", repo=str(source), audit_log=audit_log, level="error")
        return result

    container_name = f"swift-privesc-{uuid.uuid4().hex[:12]}"
    result.container_id = container_name

    with tempfile.TemporaryDirectory(prefix="swift_privesc_") as tmp:
        tmp_path = Path(tmp)
        ws = tmp_path / "workspace"
        shutil.copytree(source, ws)
        probe_path = tmp_path / "probe.sh"
        probe_path.write_text(PRIVESC_PROBE_SCRIPT, encoding="utf-8")

        cmd = [
            "docker", "run", "--rm",
            "--name", container_name,
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m",
            "--mount", f"type=bind,src={ws},dst=/workspace,readonly",
            "--mount", f"type=bind,src={probe_path},dst=/probe.sh,readonly",
            "--workdir", "/workspace",
            "--cpus", "1",
            "--memory", "1g",
            "--pids-limit", "256",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--network", "none",
        ]
        if allow_ptrace:
            cmd.extend(["--cap-add", "SYS_PTRACE"])
        cmd.extend([image, "sh", "/probe.sh"])

        log_step(
            "privesc.start",
            container=container_name,
            image=image,
            repo=str(source),
            allow_ptrace=allow_ptrace,
            command=" ".join(cmd),
            audit_log=audit_log,
        )

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            result.exit_code = proc.returncode
            result.raw_output = proc.stdout
            stdout_file = artifacts / f"{container_name}.stdout.log"
            stderr_file = artifacts / f"{container_name}.stderr.log"
            stdout_file.write_text(proc.stdout or "", encoding="utf-8")
            stderr_file.write_text(proc.stderr or "", encoding="utf-8")
            result.artifacts.extend([str(stdout_file), str(stderr_file)])
            result.findings = _parse_findings(proc.stdout)
            result.success = proc.returncode == 0
            findings_file = artifacts / f"{container_name}.findings.json"
            findings_file.write_text(json.dumps(result.findings, indent=2), encoding="utf-8")
            result.artifacts.append(str(findings_file))
            log_step(
                "privesc.finish",
                container=container_name,
                exit_code=proc.returncode,
                findings=len(result.findings),
                audit_log=audit_log,
            )
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
            result.errors.append(f"timeout after {timeout}s")
            log_step("privesc.timeout", container=container_name, timeout=timeout, audit_log=audit_log, level="error")
        except OSError as exc:
            result.errors.append(f"docker invocation failed: {exc}")
            log_step("privesc.error", container=container_name, err=str(exc), audit_log=audit_log, level="error")

    return result
