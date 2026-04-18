"""Regex triage pre-filter — zero API calls, runs before Haiku."""
from __future__ import annotations

import os
import re
from typing import Dict, List, Set

# Patterns keyed by vulnerability category.
# Each pattern is tried against non-comment lines.
PATTERNS: Dict[str, re.Pattern] = {
    "sql_injection_fstring": re.compile(
        r'f["\'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP).*\{', re.IGNORECASE
    ),
    "sql_injection_concat": re.compile(
        r'(?:SELECT|INSERT|UPDATE|DELETE).*["\'\s]\s*\+', re.IGNORECASE
    ),
    "command_injection_os_system": re.compile(r'\bos\.system\s*\('),
    "command_injection_subprocess_shell": re.compile(
        r'\bsubprocess\.(?:run|call|Popen)\s*\(.*shell\s*=\s*True'
    ),
    "hardcoded_password": re.compile(
        r'\bpassword\s*=\s*["\'][^"\']{4,}["\']', re.IGNORECASE
    ),
    "hardcoded_api_key": re.compile(
        r'\bapi[_-]?key\s*=\s*["\'][^"\']{6,}["\']', re.IGNORECASE
    ),
    "weak_crypto_md5": re.compile(r'\bhashlib\.md5\s*\('),
    "unsafe_pickle": re.compile(r'\bpickle\.loads\s*\('),
}

_COMMENT_RE = re.compile(r'^\s*#')


def triage_file(file_path: str) -> Set[int]:
    """Return 1-indexed line numbers that match any PATTERNS entry.

    Skips lines that are pure comments (# ...).

    Args:
        file_path: Absolute or relative path to a Python source file.

    Returns:
        Set of 1-indexed line numbers with suspicious patterns.
    """
    flagged: Set[int] = set()
    with open(file_path, encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, start=1):
            if _COMMENT_RE.match(line):
                continue
            for pattern in PATTERNS.values():
                if pattern.search(line):
                    flagged.add(lineno)
                    break
    return flagged


def triage_codebase(repo_path: str) -> Dict[str, List[int]]:
    """Walk repo_path, triage every .py file (skip hidden dirs).

    Args:
        repo_path: Root directory to scan.

    Returns:
        Dict mapping file_path → sorted list of flagged line numbers.
        Files with zero flags are omitted.
    """
    results: Dict[str, List[int]] = {}
    for dirpath, dirnames, filenames in os.walk(repo_path):
        # Skip hidden directories in-place so os.walk won't descend
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for fname in filenames:
            if not fname.endswith(".py"):
                continue
            full_path = os.path.join(dirpath, fname)
            flagged = triage_file(full_path)
            if flagged:
                results[full_path] = sorted(flagged)
    return results


class TriageScanner:
    """Thin wrapper around triage_codebase for dependency injection."""

    def scan(self, repo_path: str) -> Dict[str, List[int]]:
        return triage_codebase(repo_path)
