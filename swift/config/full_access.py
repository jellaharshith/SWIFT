"""Full-access autonomous consent for SWIFT bug bounty engagements.

User reviews scope, ROE, VPN, and post-exploit list, then types 'I AUTHORIZE'
to unlock autonomous mode. Token saved per engagement_id (signed, time-bound).
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Optional

_CONSENT_DIR = Path.home() / ".swift" / "consent"


def _consent_path(engagement_id: str) -> Path:
    return _CONSENT_DIR / f"{engagement_id}.json"


def _sign(payload: dict) -> str:
    secret = os.getenv("SWIFT_CONSENT_SECRET", "swift-local-secret")
    data = json.dumps(payload, sort_keys=True)
    return hashlib.sha256(f"{secret}:{data}".encode()).hexdigest()


def save_consent(engagement_id: str, scope: dict, roe_window_end: float) -> Path:
    """Persist consent token. Returns path."""
    _CONSENT_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "engagement_id": engagement_id,
        "granted_at": time.time(),
        "roe_window_end": roe_window_end,
        "scope_hash": hashlib.sha256(json.dumps(scope, sort_keys=True).encode()).hexdigest(),
    }
    payload["sig"] = _sign({k: v for k, v in payload.items() if k != "sig"})
    path = _consent_path(engagement_id)
    path.write_text(json.dumps(payload, indent=2))
    return path


def check_consent(engagement_id: str) -> bool:
    """Return True if valid unexpired consent exists for this engagement."""
    path = _consent_path(engagement_id)
    if not path.exists():
        return False
    try:
        data = json.loads(path.read_text())
        sig = data.pop("sig", "")
        if _sign(data) != sig:
            return False
        if time.time() > data["roe_window_end"]:
            return False
        return True
    except Exception:
        return False


def require_full_access_consent(
    engagement_id: str,
    target: str,
    scope: dict,
    roe,
    vpn_profile_path: Optional[str],
    post_exploit: bool,
) -> bool:
    """Interactive consent flow. Returns True if user grants access."""
    if check_consent(engagement_id):
        return True

    print("\n" + "=" * 60)
    print("  SWIFT — FULL ACCESS AUTHORIZATION REQUIRED")
    print("=" * 60)
    print(f"\n  Target    : {target}")
    print(f"  Engagement: {engagement_id}")
    print(f"\n  Scope file     : {scope.get('scope_file', 'inline')}")
    print(f"  In-scope       : {', '.join(scope.get('in_scope', [target]))}")
    print(f"  Out-of-scope   : {', '.join(scope.get('out_of_scope', []))}")
    print(f"\n  ROE window     : {getattr(roe, 'window_start', '?')} → {getattr(roe, 'window_end', '?')}")
    print(f"  Allowed techniques: {', '.join(getattr(roe, 'allowed_techniques', []))}")
    print(f"  Simulate-only  : {getattr(roe, 'simulate_only', True)}")
    print(f"\n  VPN profile    : {vpn_profile_path or 'none (direct)'}")
    print(f"  Post-exploit   : {'ENABLED (sandboxed sim only)' if post_exploit else 'disabled'}")
    print(f"\n  SWIFT will run autonomously with no per-step prompts.")
    print(f"  All actions are logged to the audit trail.\n")
    print("  Type 'I AUTHORIZE' to grant full access, or press Enter to abort.")

    try:
        response = input("  > ").strip()
    except (EOFError, KeyboardInterrupt):
        response = ""

    if response != "I AUTHORIZE":
        print("\n  [DENY] Full access not granted. Use interactive mode (omit --yes).\n")
        return False

    roe_window_end = getattr(roe, 'window_end', None)
    roe_ts = roe_window_end.timestamp() if hasattr(roe_window_end, 'timestamp') else (time.time() + 3600)
    save_consent(engagement_id, scope, roe_ts)
    print(f"\n  [OK] Full access granted. Consent token saved.\n")
    return True


def revoke_consent(engagement_id: str):
    """Revoke consent for an engagement."""
    path = _consent_path(engagement_id)
    if path.exists():
        path.unlink()
        print(f"[OK] Consent revoked for {engagement_id}")
