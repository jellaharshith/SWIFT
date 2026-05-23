"""OWASP ZAP scanner runner for SWIFT.

ZAP: OWASP Zed Attack Proxy — comprehensive web app scanner.

Two modes:
  1. API mode: ZAP running as daemon (zap-api-scan.py or via zapv2 Python lib)
  2. Docker mode: docker run -t owasp/zap2docker-stable zap-baseline.py ...

Install (Docker): docker pull owasp/zap2docker-stable
Install (API lib): pip install python-owasp-zap-v2.4

MITRE ATT&CK: T1190 - Exploit Public-Facing Application
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from typing import Any

ZAP_MITRE = {
    "technique_id": "T1190",
    "technique": "Exploit Public-Facing Application",
    "tactic": "Initial Access",
}

ZAP_DOCKER_IMAGE = os.getenv("ZAP_DOCKER_IMAGE", "owasp/zap2docker-stable")
ZAP_API_HOST = os.getenv("ZAP_API_HOST", "localhost")
ZAP_API_PORT = int(os.getenv("ZAP_API_PORT", "8080"))
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _zap_api_available() -> bool:
    try:
        import zapv2  # type: ignore[import]
        return True
    except ImportError:
        return False


def run_zap_baseline(url: str, *, timeout: int = 300, ajax: bool = False) -> list[dict[str, Any]]:
    """Run ZAP baseline scan via Docker.

    Baseline scan = passive scan only (no active probing). Safe for bug bounty.
    ajax=True enables AJAX spider (slower, finds JS-rendered routes).
    """
    if not _docker_available():
        print("[ZAP] Docker not found. Install Docker or use ZAP API mode.", file=sys.stderr)
        return []

    script = "zap-ajax-scan.py" if ajax else "zap-baseline.py"
    cmd = [
        "docker", "run", "--rm", "-t",
        ZAP_DOCKER_IMAGE,
        script,
        "-t", url,
        "-J", "/zap/wrk/report.json",
        "-I",  # don't fail on warnings
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return _parse_zap_json(proc.stdout)
    except subprocess.TimeoutExpired:
        print(f"[ZAP] Baseline scan timeout ({timeout}s)", file=sys.stderr)
        return []
    except Exception as exc:
        print(f"[ZAP] Error: {exc}", file=sys.stderr)
        return []


def run_zap_active(url: str, *, timeout: int = 600) -> list[dict[str, Any]]:
    """Run ZAP active scan via API (ZAP must be running as daemon).

    Active scan = full probing. Requires explicit ROE active_scan permission.
    ZAP must be started externally: zap.sh -daemon -port 8080 -config api.key=<key>
    """
    if not _zap_api_available():
        print("[ZAP] python-owasp-zap-v2.4 not installed. pip install python-owasp-zap-v2.4", file=sys.stderr)
        return []

    try:
        from zapv2 import ZAPv2  # type: ignore[import]
        zap = ZAPv2(apikey=ZAP_API_KEY, proxies={"http": f"http://{ZAP_API_HOST}:{ZAP_API_PORT}"})
        zap.urlopen(url)
        scan_id = zap.ascan.scan(url)
        import time
        start = time.time()
        while int(zap.ascan.status(scan_id)) < 100:
            if time.time() - start > timeout:
                print("[ZAP] Active scan timeout", file=sys.stderr)
                break
            time.sleep(5)
        alerts = zap.core.alerts(baseurl=url)
        return _parse_zap_alerts(alerts)
    except Exception as exc:
        print(f"[ZAP] Active scan error: {exc}", file=sys.stderr)
        return []


def _parse_zap_json(raw: str) -> list[dict[str, Any]]:
    findings = []
    for line in raw.splitlines():
        try:
            obj = json.loads(line)
            if isinstance(obj, list):
                for alert in obj:
                    findings.append(_alert_to_finding(alert))
            elif isinstance(obj, dict):
                findings.append(_alert_to_finding(obj))
        except json.JSONDecodeError:
            pass
    return [f for f in findings if f]


def _parse_zap_alerts(alerts: list) -> list[dict[str, Any]]:
    return [_alert_to_finding(a) for a in alerts if a]


def _alert_to_finding(alert: dict) -> dict[str, Any] | None:
    if not alert:
        return None
    risk = alert.get("risk", "Informational").lower()
    severity_map = {"high": "high", "medium": "medium", "low": "low", "informational": "info"}
    return {
        "tool": "zap",
        "type": alert.get("name", "Unknown"),
        "severity": severity_map.get(risk, "info"),
        "confidence": 0.70,
        "url": alert.get("url", ""),
        "param": alert.get("param", ""),
        "evidence": alert.get("evidence", ""),
        "description": alert.get("description", ""),
        "solution": alert.get("solution", ""),
        "cwe": alert.get("cweid", ""),
        "mitre": ZAP_MITRE,
    }
