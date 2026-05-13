"""HackerOne scope JSON validation with fnmatch wildcard support."""
from __future__ import annotations

import fnmatch
import json
from pathlib import Path
from typing import Any


def load_scope(program_json: str) -> dict[str, Any]:
    """Load and validate a HackerOne program scope JSON file.

    Args:
        program_json: Path to the HackerOne program JSON file.

    Returns:
        Parsed JSON data as a dict.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the JSON is missing expected keys.
    """
    p = Path(program_json)
    if not p.exists():
        raise FileNotFoundError(f"Program JSON not found: {program_json}")
    data = json.loads(p.read_text(encoding="utf-8"))
    if "targets" not in data and "scope" not in data:
        raise ValueError("Invalid HackerOne program JSON: missing 'targets' or 'scope' key")
    return data


def extract_in_scope_domains(data: dict[str, Any]) -> list[str]:
    """Extract in-scope domains from HackerOne program JSON.

    Args:
        data: Parsed HackerOne program JSON data.

    Returns:
        List of in-scope domain/asset identifiers.
    """
    domains: list[str] = []
    targets = data.get("targets", {})
    in_scope = targets.get("in_scope", []) or data.get("scope", [])
    for entry in in_scope:
        asset = entry.get("asset_identifier", "") or entry.get("value", "")
        if asset:
            domains.append(asset)
    return domains


def validate_target(target: str, domains: list[str]) -> bool:
    """Check if target matches any in-scope domain (fnmatch wildcard support). Fail-closed.

    Args:
        target: The target to check.
        domains: List of in-scope domains (may include fnmatch wildcards).

    Returns:
        True if target is in scope, False otherwise (fail-closed).
    """
    for domain in domains:
        if fnmatch.fnmatch(target, domain):
            return True
    return False  # fail-closed: not in scope = deny
