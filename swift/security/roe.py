"""Rules-of-Engagement (ROE) gate for SWIFT red-team operations.

Every offensive command must load and validate an ROE before touching a target.
Fail-closed: missing ROE = SystemExit with [DENY] prefix.
"""
from __future__ import annotations

import hashlib
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore


@dataclass(frozen=True)
class ROE:
    engagement_id: str
    authorized_targets: list       # hostnames, IPs, CIDRs, URL prefixes
    allowed_techniques: set        # "osint", "active_scan", "exploit", "post_exploit"
    window_start: datetime
    window_end: datetime
    contact: str
    max_runtime_seconds: int = 1800
    simulate_only: bool = True
    roe_sha256: str = ""           # populated by load_roe()


def load_roe(path: Path | str) -> ROE:
    """Load and validate a ROE YAML file. Fail-closed on any error."""
    if yaml is None:
        _deny("PyYAML not installed. Run: pip install pyyaml")
    p = Path(path).resolve()
    if not p.exists():
        _deny(f"ROE file not found: {p}  --  create one with: swift --init-roe {p}")
    raw = p.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    try:
        data = yaml.safe_load(raw)
    except Exception as e:
        _deny(f"ROE parse error: {e}")

    required = ["engagement_id", "authorized_targets", "allowed_techniques",
                "window_start", "window_end", "contact"]
    for key in required:
        if key not in data:
            _deny(f"ROE missing required key: {key}")

    # Parse window as UTC-aware datetimes
    def _parse_dt(v) -> datetime:
        if isinstance(v, datetime):
            return v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v
        return datetime.fromisoformat(str(v)).replace(tzinfo=timezone.utc)

    return ROE(
        engagement_id=data["engagement_id"],
        authorized_targets=list(data["authorized_targets"]),
        allowed_techniques=set(data.get("allowed_techniques", ["osint", "active_scan"])),
        window_start=_parse_dt(data["window_start"]),
        window_end=_parse_dt(data["window_end"]),
        contact=data["contact"],
        max_runtime_seconds=int(data.get("max_runtime_seconds", 1800)),
        simulate_only=bool(data.get("simulate_only", True)),
        roe_sha256=sha,
    )


def assert_target_in_scope(roe: ROE, target: str) -> None:
    """Raise SystemExit if target is not in the authorized_targets list."""
    target_lower = target.lower()
    for authorized in roe.authorized_targets:
        auth = str(authorized).lower()
        if target_lower == auth or target_lower.startswith(auth) or auth in target_lower:
            return
    _deny(
        f"Target '{target}' is NOT in the authorized scope defined in engagement "
        f"'{roe.engagement_id}'.\n"
        f"Authorized targets: {roe.authorized_targets}\n"
        f"Add the target to the ROE file or obtain a new ROE."
    )


def assert_technique_allowed(roe: ROE, technique: str) -> None:
    """Raise SystemExit if technique is not in allowed_techniques."""
    if technique not in roe.allowed_techniques:
        _deny(
            f"Technique '{technique}' is NOT allowed by engagement '{roe.engagement_id}'.\n"
            f"Allowed: {sorted(roe.allowed_techniques)}"
        )


def assert_window_active(roe: ROE) -> None:
    """Raise SystemExit if the engagement window has expired or not started."""
    now = datetime.now(timezone.utc)
    if now < roe.window_start:
        _deny(f"Engagement window has not started yet. Start: {roe.window_start.isoformat()}")
    if now > roe.window_end:
        _deny(f"Engagement window has expired. End: {roe.window_end.isoformat()}")


def validate_all(roe: ROE, target: str, technique: str) -> None:
    """Run all three assertions. Call at every offensive entry point."""
    assert_window_active(roe)
    assert_target_in_scope(roe, target)
    assert_technique_allowed(roe, technique)


def _deny(message: str) -> None:
    print(f"[DENY] {message}", file=sys.stderr)
    sys.exit(2)
