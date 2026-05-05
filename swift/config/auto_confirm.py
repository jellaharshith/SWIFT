"""Auto-confirm flag/env handling. Skips interactive prompts when set."""
from __future__ import annotations

import os
from typing import Any


def is_auto_confirmed(args: Any = None) -> bool:
    """True if --yes flag set or SWIFT_AUTO_CONFIRM=1."""
    if args is not None and getattr(args, "yes", False):
        return True
    return os.environ.get("SWIFT_AUTO_CONFIRM", "").strip() in {"1", "true", "yes", "TRUE"}
