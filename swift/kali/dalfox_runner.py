"""dalfox XSS scanner runner for SWIFT.

dalfox: Go-based XSS scanner by hahwul.
Install: go install github.com/hahwul/dalfox/v2@latest

MITRE ATT&CK: T1059.007 - Command and Scripting Interpreter: JavaScript
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

DALFOX_MITRE = {
    "technique_id": "T1059.007",
    "technique": "Command and Scripting Interpreter: JavaScript",
    "tactic": "Execution",
}


def _dalfox_available() -> bool:
    return shutil.which("dalfox") is not None


def run_dalfox_url(
    url: str,
    *,
    blind_url: str | None = None,
    custom_payload_file: str | None = None,
    timeout: int = 120,
    extra_args: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Scan a single URL for XSS using dalfox.

    Returns a list of finding dicts compatible with SWIFT's finding shape.
    """
    if not _dalfox_available():
        print(
            "[dalfox] Not found in PATH. Install: go install github.com/hahwul/dalfox/v2@latest",
            file=sys.stderr,
        )
        return []

    cmd = ["dalfox", "url", url, "--format", "json", "--silence"]
    if blind_url:
        cmd += ["--blind", blind_url]
    if custom_payload_file:
        cmd += ["--custom-payload", custom_payload_file]
    if extra_args:
        cmd += extra_args

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return _parse_dalfox_output(proc.stdout, url)
    except subprocess.TimeoutExpired:
        print(f"[dalfox] Timeout ({timeout}s) scanning {url}", file=sys.stderr)
        return []
    except Exception as exc:
        print(f"[dalfox] Error: {exc}", file=sys.stderr)
        return []


def run_dalfox_pipe(
    urls: list[str],
    *,
    blind_url: str | None = None,
    timeout: int = 300,
) -> list[dict[str, Any]]:
    """Scan multiple URLs via dalfox pipe mode (stdin)."""
    if not _dalfox_available():
        print("[dalfox] Not found. Install: go install github.com/hahwul/dalfox/v2@latest", file=sys.stderr)
        return []

    cmd = ["dalfox", "pipe", "--format", "json", "--silence"]
    if blind_url:
        cmd += ["--blind", blind_url]

    input_data = "\n".join(urls)
    try:
        proc = subprocess.run(
            cmd, input=input_data, capture_output=True, text=True, timeout=timeout
        )
        return _parse_dalfox_output(proc.stdout, "pipe")
    except subprocess.TimeoutExpired:
        print(f"[dalfox] Pipe timeout ({timeout}s)", file=sys.stderr)
        return []
    except Exception as exc:
        print(f"[dalfox] Error: {exc}", file=sys.stderr)
        return []


def _parse_dalfox_output(raw: str, target: str) -> list[dict[str, Any]]:
    findings = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            findings.append({
                "tool": "dalfox",
                "type": "XSS",
                "severity": "high",
                "confidence": 0.85,
                "url": obj.get("data", target),
                "param": obj.get("param", "?"),
                "payload": obj.get("poc", ""),
                "evidence": obj.get("data", ""),
                "mitre": DALFOX_MITRE,
            })
        except json.JSONDecodeError:
            # dalfox sometimes emits non-JSON lines even with --format json
            if "[V]" in line or "XSS" in line:
                findings.append({
                    "tool": "dalfox",
                    "type": "XSS",
                    "severity": "high",
                    "confidence": 0.75,
                    "url": target,
                    "param": "?",
                    "payload": line,
                    "evidence": line,
                    "mitre": DALFOX_MITRE,
                })
    return findings
