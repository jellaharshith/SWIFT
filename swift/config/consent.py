"""Consent management for offensive scanning operations.

This module handles the one-time consent gate for Kali Linux-based
offensive scanning. Users must explicitly accept the warning before
running any full scans that include vulnerability probing.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


CONSENT_FILE = Path.home() / ".swift" / "consent.json"


def check_consent() -> bool:
    """Check if user has previously accepted the consent.

    Returns:
        True if consent file exists and is valid, False otherwise.
    """
    if not CONSENT_FILE.exists():
        return False

    try:
        with open(CONSENT_FILE, "r") as f:
            data = json.load(f)
            return data.get("accepted", False) is True
    except (json.JSONDecodeError, OSError):
        return False


def prompt_and_save_consent() -> bool:
    """Display consent warning and prompt user to accept.

    Prints a clear warning about offensive scanning, then requires the
    user to type exactly "I ACCEPT" to proceed. If accepted, saves
    consent to CONSENT_FILE for future runs.

    Returns:
        True if user accepted consent, False if declined.
    """
    print("\n" + "=" * 70)
    print("SWIFT OFFENSIVE SCANNING CONSENT AGREEMENT")
    print("=" * 70)
    print()
    print("This scan will execute Kali Linux security tools against the")
    print("target, including:")
    print("  - Network scanning and port enumeration")
    print("  - Vulnerability probing and exploitation")
    print("  - Payload testing and verification")
    print()
    print("These operations may disrupt services or trigger intrusion")
    print("detection systems. Only proceed if you have explicit permission")
    print("from the target owner.")
    print()
    print("=" * 70)
    print()

    response = input("Type 'I ACCEPT' to proceed: ").strip()

    if response == "I ACCEPT":
        # Ensure directory exists
        CONSENT_FILE.parent.mkdir(parents=True, exist_ok=True)

        # Save consent
        with open(CONSENT_FILE, "w") as f:
            json.dump({"accepted": True}, f, indent=2)

        print("✓ Consent recorded. You will not be prompted again.")
        print()
        return True
    else:
        print("✗ Consent declined. Scan cannot proceed.")
        print()
        return False


def require_consent(args=None) -> None:
    """Ensure user consent is given, raising SystemExit if declined.

    Auto-confirm (--yes / SWIFT_AUTO_CONFIRM=1) bypasses prompt and persists consent.
    """
    from config.auto_confirm import is_auto_confirmed
    try:
        from log.audit import log_step
    except ImportError:
        log_step = None  # type: ignore

    if check_consent():
        return

    if is_auto_confirmed(args):
        CONSENT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(CONSENT_FILE, "w") as f:
            json.dump({"accepted": True, "auto_confirmed": True}, f)
        if log_step:
            log_step("consent.auto_confirmed")
        return

    if not prompt_and_save_consent():
        sys.exit(1)
