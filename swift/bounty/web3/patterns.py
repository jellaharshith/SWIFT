"""Grep-able smart-contract bug patterns.

Lightweight regex pre-screen for Solidity sources -- catches the same
high-signal patterns the upstream claude-bug-bounty ``web3/03-grep-arsenal.md``
documents (reentrancy, low-level call, tx.origin, unbounded loop, signature
replay, ERC4626 share-inflation, oracle freshness, access control gaps).

For real auditing call :func:`bounty.web3.slither.analyze` /
:func:`bounty.web3.mythril.analyze` on top of these results.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable


PATTERNS: dict[str, re.Pattern[str]] = {
    "reentrancy_call":      re.compile(r"\.call\{value:\s*\w+\}\(\"\"\)"),
    "low_level_delegatecall": re.compile(r"\.delegatecall\("),
    "tx_origin_auth":       re.compile(r"tx\.origin\s*==\s*\w+"),
    "unbounded_loop":       re.compile(r"for\s*\([^)]*\b\w+\.length\b[^)]*\)"),
    "signature_replay":     re.compile(r"ecrecover\("),
    "erc4626_inflation":    re.compile(r"convertToShares\(.*\)"),
    "oracle_no_freshness":  re.compile(r"latestRoundData\(\)(?![^;]*updatedAt)"),
    "missing_access_control": re.compile(r"function\s+\w+\([^)]*\)\s+(public|external)\s*(?!view|pure)(?!.*onlyOwner)(?!.*nonReentrant).*\{"),
}


def scan(target: str | Path, *, exts: Iterable[str] = (".sol",)) -> list[dict[str, str]]:
    p = Path(target)
    files: list[Path] = []
    if p.is_file():
        files = [p]
    else:
        for ext in exts:
            files.extend(p.rglob(f"*{ext}"))
    findings: list[dict[str, str]] = []
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for name, pat in PATTERNS.items():
            for m in pat.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                findings.append({
                    "pattern": name,
                    "file": str(f),
                    "line": str(line),
                    "match": m.group(0)[:120],
                })
    return findings
