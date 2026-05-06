"""Payload uploader — validate, dedupe, and register custom payload files."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

from browser.payload_library import _library

_DEFAULT_ROOT = Path.home() / ".swift" / "payloads"


def _custom_file(vuln_type: str, dest_dir: Optional[str]) -> Path:
    if dest_dir:
        d = Path(dest_dir) / vuln_type
    else:
        d = _DEFAULT_ROOT / vuln_type
    d.mkdir(parents=True, exist_ok=True)
    return d / "custom.txt"


def upload_payloads(
    filepath: str,
    vuln_type: str,
    dest_dir: Optional[str] = None,
) -> dict:
    """Validate, dedupe, and register payloads from filepath into the library.

    Args:
        filepath: Source file — one payload per line.
        vuln_type: Vulnerability type key (e.g. "xss").
        dest_dir: Override destination root dir. Defaults to ~/.swift/payloads/.

    Returns:
        Dict with keys: added, skipped, total, path.

    Raises:
        FileNotFoundError: If filepath does not exist.
        ValueError: If filepath contains no valid payload lines.
    """
    vt = vuln_type.lower()
    source = Path(filepath)
    if not source.exists():
        raise FileNotFoundError(f"Payload file not found: {filepath}")

    lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
    candidates = [l.strip() for l in lines if l.strip()]
    if not candidates:
        raise ValueError(f"No valid payload lines in {filepath}")

    existing_set = set(_library.get_user_payloads(vt))
    dest = _custom_file(vt, dest_dir)
    if dest.exists():
        for line in dest.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip():
                existing_set.add(line.strip())

    new_payloads = [p for p in candidates if p not in existing_set]
    skipped = len(candidates) - len(new_payloads)

    if new_payloads:
        with dest.open("a", encoding="utf-8") as fh:
            for p in new_payloads:
                fh.write(p + "\n")

    # Invalidate cache so next read picks up new entries
    _library.invalidate(vt)

    return {
        "added": len(new_payloads),
        "skipped": skipped,
        "total": len(candidates),
        "path": str(dest),
    }


def list_payloads(vuln_type: Optional[str] = None) -> Dict[str, List[str]]:
    """Return all registered user payloads grouped by vuln_type.

    Args:
        vuln_type: If provided, only return payloads for that type.

    Returns:
        Dict mapping vuln_type -> list of payload strings.
    """
    if vuln_type:
        return {vuln_type.lower(): _library.get_user_payloads(vuln_type.lower())}

    result: Dict[str, List[str]] = {}
    root = _DEFAULT_ROOT
    if root.exists():
        for vt_dir in sorted(root.iterdir()):
            if vt_dir.is_dir():
                payloads = _library.get_user_payloads(vt_dir.name)
                if payloads:
                    result[vt_dir.name] = payloads
    return result


def remove_payloads(vuln_type: str, payload: str) -> bool:
    """Remove a specific payload from custom.txt.

    Args:
        vuln_type: Vulnerability type key.
        payload: Exact payload string to remove.

    Returns:
        True if the payload was found and removed, False otherwise.
    """
    vt = vuln_type.lower()
    dest = _custom_file(vt, None)
    if not dest.exists():
        return False

    lines = dest.read_text(encoding="utf-8", errors="replace").splitlines()
    kept = [l for l in lines if l.strip() != payload]
    if len(kept) == len(lines):
        return False

    dest.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
    _library.invalidate(vt)
    return True
