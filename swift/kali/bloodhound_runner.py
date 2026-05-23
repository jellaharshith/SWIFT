"""BloodHound/SharpHound Active Directory attack path runner for SWIFT.

BloodHound: AD attack path analysis tool (BloodHound Community Edition).
Collector: bloodhound-python (pip install bloodhound) or SharpHound.exe (Windows).

Requires: Neo4j running (or can export to JSON files for offline analysis).
Install collector: pip install bloodhound
BloodHound CE: https://github.com/SpecterOps/BloodHound

MITRE ATT&CK:
  - T1087.002: Account Discovery: Domain Account
  - T1069.002: Permission Groups Discovery: Domain Groups
  - T1482: Domain Trust Discovery
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

BLOODHOUND_MITRE = [
    {"technique_id": "T1087.002", "technique": "Account Discovery: Domain Account", "tactic": "Discovery"},
    {"technique_id": "T1069.002", "technique": "Permission Groups Discovery: Domain Groups", "tactic": "Discovery"},
    {"technique_id": "T1482", "technique": "Domain Trust Discovery", "tactic": "Discovery"},
]


def _bh_collector_available() -> bool:
    return shutil.which("bloodhound-python") is not None or shutil.which("bloodhound") is not None


def run_bloodhound_collection(
    domain: str,
    dc: str,
    username: str,
    password: str,
    *,
    collection_method: str = "All",
    output_dir: str = "/tmp/bloodhound-out",
    timeout: int = 300,
) -> dict[str, Any]:
    """Run BloodHound data collection against an authorized AD domain.

    collection_method: All | DCOnly | Session | LoggedOn | Trusts | etc.
    Returns: {"status": "ok"|"error", "output_dir": ..., "files": [...], "mitre": [...]}

    ROE requirement: ad_enum must be authorized.
    """
    if not _bh_collector_available():
        print(
            "[BloodHound] bloodhound-python not found. Install: pip install bloodhound",
            file=sys.stderr,
        )
        return {"status": "error", "error": "bloodhound-python not installed", "mitre": BLOODHOUND_MITRE}

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    collector = shutil.which("bloodhound-python") or "bloodhound-python"
    cmd = [
        collector,
        "-d", domain,
        "-dc", dc,
        "-u", username,
        "-p", password,
        "-c", collection_method,
        "-o", output_dir,
        "--zip",
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        files = list(Path(output_dir).glob("*.json")) + list(Path(output_dir).glob("*.zip"))
        return {
            "status": "ok" if proc.returncode == 0 else "error",
            "output_dir": output_dir,
            "files": [str(f) for f in files],
            "stdout": proc.stdout[-2000:],
            "stderr": proc.stderr[-1000:],
            "mitre": BLOODHOUND_MITRE,
        }
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": f"timeout {timeout}s", "mitre": BLOODHOUND_MITRE}
    except Exception as exc:
        return {"status": "error", "error": str(exc), "mitre": BLOODHOUND_MITRE}


def parse_bloodhound_users(output_dir: str) -> list[dict[str, Any]]:
    """Parse BloodHound user JSON files to extract high-value targets."""
    users_file = Path(output_dir) / "users.json"
    if not users_file.exists():
        for f in Path(output_dir).glob("*_users.json"):
            users_file = f
            break

    if not users_file.exists():
        return []

    try:
        data = json.loads(users_file.read_text())
        users = data.get("data", [])
        findings = []
        for user in users:
            props = user.get("Properties", {})
            if props.get("admincount") or props.get("enabled"):
                findings.append({
                    "tool": "bloodhound",
                    "type": "Domain Account",
                    "severity": "info",
                    "name": props.get("name", "?"),
                    "enabled": props.get("enabled", False),
                    "admin_count": props.get("admincount", False),
                    "pwdlastset": props.get("pwdlastset", -1),
                    "mitre": BLOODHOUND_MITRE,
                })
        return findings
    except Exception as exc:
        print(f"[BloodHound] Parse error: {exc}", file=sys.stderr)
        return []


def find_attack_paths(output_dir: str, *, target_user: str = "Domain Admins") -> list[dict[str, Any]]:
    """Analyze BloodHound JSON data for attack paths to privileged groups.

    For full attack path analysis, import the zip into BloodHound CE with Neo4j
    and use Cypher queries. This function provides a lightweight local analysis.
    """
    paths = []
    for json_file in Path(output_dir).glob("*.json"):
        try:
            data = json.loads(json_file.read_text())
            # Look for adminTo / MemberOf / HasSession edges
            for item in data.get("data", []):
                rels = item.get("Aces", []) or item.get("Members", [])
                for rel in rels:
                    if "Admin" in str(rel) or target_user.lower() in str(rel).lower():
                        paths.append({
                            "tool": "bloodhound",
                            "type": "Attack Path",
                            "severity": "high",
                            "description": f"Potential path toward {target_user} via {json_file.name}",
                            "detail": str(rel)[:200],
                            "mitre": BLOODHOUND_MITRE,
                        })
        except Exception:
            pass
    return paths
