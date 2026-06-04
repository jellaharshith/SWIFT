"""Daily CVE auto-sync scheduler.

Installs an OS-level job that runs ``python -m swiftsec_ai.cli sync`` every morning
so the local NVD/CVE mirror stays fresh without manual intervention:

* macOS  → a launchd LaunchAgent (``~/Library/LaunchAgents``). launchd fires a
  missed ``StartCalendarInterval`` job once on wake, so an asleep laptop still
  syncs after it powers back on.
* Linux  → an idempotent crontab line tagged with a marker comment.

The job runs the *same* CLI a human would, in the *same* working directory, so it
reads the same ``.env`` and writes the same ``SWIFTSEC_CVE_DB``.
"""
from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

LABEL = "com.swiftsec.ai.cve-sync"
CRON_MARKER = "# swiftsec-ai-cve-sync"


def _python() -> str:
    return sys.executable or "python3"


def _workdir() -> str:
    return os.getcwd()


def _logfile(workdir: str) -> str:
    log_dir = Path(workdir) / "log"
    log_dir.mkdir(parents=True, exist_ok=True)
    return str(log_dir / "cve-sync.log")


# --------------------------------------------------------------------- macOS

def _plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def _render_plist(python: str, workdir: str, hour: int, minute: int, log: str) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{python}</string>
        <string>-m</string>
        <string>swiftsec_ai.cli</string>
        <string>sync</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{workdir}</string>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>{hour}</integer>
        <key>Minute</key>
        <integer>{minute}</integer>
    </dict>
    <key>RunAtLoad</key>
    <false/>
    <key>StandardOutPath</key>
    <string>{log}</string>
    <key>StandardErrorPath</key>
    <string>{log}</string>
</dict>
</plist>
"""


def _launchctl(*args: str) -> tuple[int, str]:
    proc = subprocess.run(
        ["launchctl", *args], capture_output=True, text=True
    )
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def _install_macos(hour: int, minute: int) -> dict[str, Any]:
    workdir = _workdir()
    log = _logfile(workdir)
    path = _plist_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_render_plist(_python(), workdir, hour, minute, log))
    # Reload (unload first so re-installs pick up changes); ignore unload errors.
    _launchctl("unload", str(path))
    code, out = _launchctl("load", str(path))
    return {
        "status": "ok" if code == 0 else "error",
        "scheduler": "launchd",
        "label": LABEL,
        "plist": str(path),
        "schedule": f"daily {hour:02d}:{minute:02d}",
        "command": f"{_python()} -m swiftsec_ai.cli sync",
        "workdir": workdir,
        "log": log,
        "detail": out or "loaded",
    }


def _uninstall_macos() -> dict[str, Any]:
    path = _plist_path()
    if path.exists():
        _launchctl("unload", str(path))
        path.unlink()
        return {"status": "ok", "scheduler": "launchd", "removed": str(path)}
    return {"status": "ok", "scheduler": "launchd", "removed": None, "detail": "not installed"}


def _status_macos() -> dict[str, Any]:
    path = _plist_path()
    installed = path.exists()
    code, _ = _launchctl("list", LABEL)
    return {
        "scheduler": "launchd",
        "installed": installed,
        "loaded": code == 0,
        "plist": str(path) if installed else None,
    }


# --------------------------------------------------------------------- Linux/cron

def _read_crontab() -> list[str]:
    proc = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    if proc.returncode != 0:
        return []
    return proc.stdout.splitlines()


def _write_crontab(lines: list[str]) -> tuple[int, str]:
    content = "\n".join(lines).rstrip("\n") + "\n"
    proc = subprocess.run(["crontab", "-"], input=content, capture_output=True, text=True)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def _install_cron(hour: int, minute: int) -> dict[str, Any]:
    workdir = _workdir()
    log = _logfile(workdir)
    line = (
        f"{minute} {hour} * * * cd {workdir} && {_python()} -m swiftsec_ai.cli sync "
        f">> {log} 2>&1 {CRON_MARKER}"
    )
    lines = [ln for ln in _read_crontab() if CRON_MARKER not in ln]
    lines.append(line)
    code, out = _write_crontab(lines)
    return {
        "status": "ok" if code == 0 else "error",
        "scheduler": "cron",
        "schedule": f"daily {hour:02d}:{minute:02d}",
        "command": f"{_python()} -m swiftsec_ai.cli sync",
        "workdir": workdir,
        "log": log,
        "detail": out or "crontab updated",
    }


def _uninstall_cron() -> dict[str, Any]:
    lines = _read_crontab()
    kept = [ln for ln in lines if CRON_MARKER not in ln]
    if len(kept) == len(lines):
        return {"status": "ok", "scheduler": "cron", "detail": "not installed"}
    code, out = _write_crontab(kept)
    return {"status": "ok" if code == 0 else "error", "scheduler": "cron", "detail": out or "removed"}


def _status_cron() -> dict[str, Any]:
    installed = any(CRON_MARKER in ln for ln in _read_crontab())
    return {"scheduler": "cron", "installed": installed}


# --------------------------------------------------------------------- dispatch

def install(hour: int = 7, minute: int = 0) -> dict[str, Any]:
    """Install the daily auto-sync job (default 07:00 local)."""
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        return {"status": "error", "detail": f"invalid time {hour:02d}:{minute:02d}"}
    if platform.system() == "Darwin":
        return _install_macos(hour, minute)
    return _install_cron(hour, minute)


def uninstall() -> dict[str, Any]:
    if platform.system() == "Darwin":
        return _uninstall_macos()
    return _uninstall_cron()


def status() -> dict[str, Any]:
    if platform.system() == "Darwin":
        return _status_macos()
    return _status_cron()
