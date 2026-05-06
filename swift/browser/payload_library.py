"""User payload library — loads custom payloads from ~/.swift/payloads/ and ./payloads/."""
from __future__ import annotations

import glob
import os
from pathlib import Path
from typing import Dict, List, Optional


class PayloadLibrary:
    """Loads and caches user-supplied payloads from disk.

    Search order per vuln_type:
      1. ~/.swift/payloads/{vuln_type}/*.txt
      2. ./payloads/{vuln_type}/*.txt
    """

    def __init__(self) -> None:
        self._cache: Dict[str, List[dict]] = {}

    def _search_dirs(self, vuln_type: str) -> List[Path]:
        dirs = [
            Path.home() / ".swift" / "payloads" / vuln_type,
            Path("payloads") / vuln_type,
        ]
        files: List[Path] = []
        for d in dirs:
            if d.exists():
                files.extend(sorted(d.glob("*.txt")))
        return files

    def get_payloads(self, vuln_type: str) -> List[dict]:
        """Return payload entries for vuln_type, loaded from user payload files.

        Args:
            vuln_type: Vulnerability type key (e.g. "xss", "sqli").

        Returns:
            List of payload dicts with keys: vuln_type, payload, tags,
            waf_bypass, framework_hint, source. Empty if no files found.
        """
        vt = vuln_type.lower()
        if vt in self._cache:
            return self._cache[vt]

        files = self._search_dirs(vt)
        seen: set[str] = set()
        entries: List[dict] = []

        for filepath in files:
            try:
                for line in filepath.read_text(encoding="utf-8", errors="replace").splitlines():
                    payload = line.strip()
                    if payload and payload not in seen:
                        seen.add(payload)
                        entries.append({
                            "vuln_type": vt,
                            "payload": payload,
                            "tags": [],
                            "waf_bypass": False,
                            "framework_hint": None,
                            "source": "user",
                        })
            except OSError:
                pass

        self._cache[vt] = entries
        return entries

    def get_user_payloads(self, vuln_type: str) -> List[str]:
        """Return just the payload strings for vuln_type.

        Args:
            vuln_type: Vulnerability type key.

        Returns:
            List of payload strings. Empty if no user payloads found.
        """
        return [e["payload"] for e in self.get_payloads(vuln_type)]

    def invalidate(self, vuln_type: Optional[str] = None) -> None:
        """Invalidate cache so next call re-reads from disk.

        Args:
            vuln_type: If provided, only invalidate that type. None clears all.
        """
        if vuln_type is None:
            self._cache.clear()
        else:
            self._cache.pop(vuln_type.lower(), None)


_library = PayloadLibrary()


def get_user_payloads(vuln_type: str) -> List[str]:
    """Module-level convenience — delegates to the singleton PayloadLibrary.

    Args:
        vuln_type: Vulnerability type key.

    Returns:
        List of user payload strings.
    """
    return _library.get_user_payloads(vuln_type)
