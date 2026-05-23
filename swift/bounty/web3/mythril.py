"""Mythril subprocess wrapper."""
from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any


def is_available() -> bool:
    return shutil.which("myth") is not None


def analyze(target: str, *, timeout: int = 900) -> dict[str, Any]:
    """Symbolically execute ``target`` (Solidity file, bytecode, or address)."""
    if not is_available():
        return {"error": "mythril not installed; pip install swiftsec[web3]"}
    args = ["myth", "analyze", target, "-o", "json"]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "target": target}
    out: dict[str, Any] = {"returncode": proc.returncode, "stderr_tail": proc.stderr[-2000:]}
    try:
        out["results"] = json.loads(proc.stdout)
    except json.JSONDecodeError:
        out["results_raw"] = proc.stdout[-4000:]
    return out
