"""Slither subprocess wrapper."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


def is_available() -> bool:
    return shutil.which("slither") is not None


def analyze(target: str, *, json_output: bool = True, timeout: int = 600) -> dict[str, Any]:
    """Run slither over ``target`` (a Solidity file or project directory)."""
    if not is_available():
        return {"error": "slither not installed; pip install swiftsec[web3]"}
    args = ["slither", target]
    if json_output:
        args += ["--json", "-"]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "target": target}
    out: dict[str, Any] = {"stderr_tail": proc.stderr[-2000:]}
    if json_output:
        try:
            out["results"] = json.loads(proc.stdout)
        except json.JSONDecodeError:
            out["results_raw"] = proc.stdout[-4000:]
    else:
        out["stdout"] = proc.stdout
    out["returncode"] = proc.returncode
    return out
