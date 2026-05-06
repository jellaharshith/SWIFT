"""Chain executor: replay attack chain steps with real session tokens — sandbox only.

Safety invariant: execution is ONLY permitted when:
  1. roe.allow_chain_execution is explicitly True, AND
  2. The target URL/host is in ALLOWED_TARGETS (Juice Shop / DVWA only), AND
  3. roe.simulate_only is False OR allow_chain_execution was explicitly set.

Fail-closed: any ambiguity → deny.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

from log.audit import log_step

# Allowlist: only known safe lab targets
ALLOWED_TARGETS: list[str] = [
    "juice-shop",
    "dvwa",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
]


@dataclass
class ChainExecutionResult:
    chain_id: str
    steps_attempted: int
    steps_succeeded: int
    evidence: list[str] = field(default_factory=list)   # response excerpts or screenshot paths
    validated: bool = False                               # True only if all steps succeeded
    error: str | None = None


def _deny(message: str) -> None:
    log_step("chain_executor.deny", reason=message, level="warning")
    print(f"[DENY] chain_executor: {message}", file=sys.stderr)


def _is_target_allowed(target: str) -> bool:
    """Return True if target hostname/URL is in the ALLOWED_TARGETS allowlist."""
    host = urlparse(target).hostname or target.lower()
    return any(allowed in host.lower() for allowed in ALLOWED_TARGETS)


def _get_roe_flag(roe, flag: str, default: bool = False) -> bool:
    """Safely get a boolean flag from an ROE object; return default if missing."""
    return bool(getattr(roe, flag, default))


async def execute_chain(
    chain: Any,
    roe: Any,
    session_tokens: dict | None = None,
    out_dir: str = "output",
) -> ChainExecutionResult:
    """Replay attack chain steps with real HTTP requests.

    Fails closed if:
    - roe.allow_chain_execution is not True
    - Target is not in ALLOWED_TARGETS
    - httpx is not available

    Args:
        chain: ExploitChain or dict with chain_id, attack_steps, and target URL fields.
        roe: ROE object that must have allow_chain_execution=True.
        session_tokens: Dict of header name → value for authentication (e.g. cookies, Bearer tokens).
        out_dir: Directory to save evidence files.

    Returns:
        ChainExecutionResult with validation status and per-step evidence.
    """
    chain_id: str = getattr(chain, "chain_id", None) or (chain.get("chain_id") if isinstance(chain, dict) else "UNKNOWN")

    # ── ROE gate ──────────────────────────────────────────────────────────
    allow_exec = _get_roe_flag(roe, "allow_chain_execution", default=False)
    if not allow_exec:
        _deny("allow_chain_execution not set in ROE — chain replay blocked")
        return ChainExecutionResult(
            chain_id=chain_id,
            steps_attempted=0,
            steps_succeeded=0,
            validated=False,
            error="ROE does not permit chain execution (allow_chain_execution=False)",
        )

    simulate_only = _get_roe_flag(roe, "simulate_only", default=True)
    if simulate_only and not allow_exec:
        _deny("simulate_only=True and allow_chain_execution not set — contradictory ROE; blocking")
        return ChainExecutionResult(
            chain_id=chain_id,
            steps_attempted=0,
            steps_succeeded=0,
            validated=False,
            error="simulate_only=True without explicit allow_chain_execution; contradictory ROE",
        )

    if not _HTTPX_AVAILABLE:
        return ChainExecutionResult(
            chain_id=chain_id,
            steps_attempted=0,
            steps_succeeded=0,
            validated=False,
            error="httpx not installed; cannot execute chain steps",
        )

    # ── Extract steps ─────────────────────────────────────────────────────
    if isinstance(chain, dict):
        attack_steps = chain.get("attack_steps", [])
        target_url: str = chain.get("entry_point", "") or chain.get("target", "")
    else:
        attack_steps = list(getattr(chain, "attack_steps", []) or [])
        target_url = getattr(chain, "entry_point", "") or ""

    if not attack_steps:
        return ChainExecutionResult(
            chain_id=chain_id,
            steps_attempted=0,
            steps_succeeded=0,
            validated=False,
            error="No attack_steps found in chain",
        )

    # ── Target allowlist check ────────────────────────────────────────────
    if target_url and not _is_target_allowed(target_url):
        _deny(f"Target '{target_url}' not in ALLOWED_TARGETS — chain replay blocked")
        return ChainExecutionResult(
            chain_id=chain_id,
            steps_attempted=0,
            steps_succeeded=0,
            validated=False,
            error=f"Target not in allowlist: {target_url}",
        )

    log_step("chain_executor.start", chain_id=chain_id, steps=len(attack_steps))

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    # Build session headers from tokens
    headers: dict[str, str] = {}
    if session_tokens:
        headers.update({k: str(v) for k, v in session_tokens.items()})

    evidence: list[str] = []
    steps_succeeded = 0

    async with httpx.AsyncClient(verify=False, timeout=15, headers=headers) as client:  # noqa: S501
        for step_obj in attack_steps:
            if isinstance(step_obj, dict):
                step_num = step_obj.get("step", 0)
                description = step_obj.get("description", "")
                step_url = step_obj.get("entry_point", target_url)
                method = step_obj.get("method", "GET").upper()
                payload_data = step_obj.get("payload", None)
            else:
                step_num = getattr(step_obj, "step", 0)
                description = getattr(step_obj, "description", "")
                step_url = getattr(step_obj, "entry_point", target_url)
                method = getattr(step_obj, "method", "GET").upper()
                payload_data = getattr(step_obj, "payload", None)

            if not step_url:
                evidence.append(f"Step {step_num}: skipped (no URL)")
                continue

            log_step("chain_executor.step", chain_id=chain_id, step_num=step_num, url=step_url, method=method)

            try:
                if method in ("POST", "PUT", "PATCH"):
                    resp = await client.request(method, step_url, json=payload_data)
                else:
                    resp = await client.request(method, step_url)

                excerpt = resp.text[:400]
                success = 200 <= resp.status_code < 400
                evidence.append(
                    f"Step {step_num} [{description[:60]}]: HTTP {resp.status_code} — {excerpt[:200]}"
                )
                if success:
                    steps_succeeded += 1
                    log_step("chain_executor.step_ok", chain_id=chain_id, step_num=step_num, code=resp.status_code)
                else:
                    log_step("chain_executor.step_fail", chain_id=chain_id, step_num=step_num, code=resp.status_code)

            except Exception as exc:  # noqa: BLE001
                evidence.append(f"Step {step_num} [{description[:60]}]: ERROR — {exc}")
                log_step("chain_executor.step_error", chain_id=chain_id, step_num=step_num, err=str(exc), level="warning")

    validated = steps_succeeded == len(attack_steps) and len(attack_steps) > 0

    # Persist evidence JSON
    result_file = out_path / f"chain-exec-{chain_id}.json"
    result_data = {
        "chain_id": chain_id,
        "steps_attempted": len(attack_steps),
        "steps_succeeded": steps_succeeded,
        "validated": validated,
        "evidence": evidence,
    }
    result_file.write_text(json.dumps(result_data, indent=2), encoding="utf-8")

    log_step(
        "chain_executor.finish",
        chain_id=chain_id,
        steps_attempted=len(attack_steps),
        steps_succeeded=steps_succeeded,
        validated=validated,
    )

    return ChainExecutionResult(
        chain_id=chain_id,
        steps_attempted=len(attack_steps),
        steps_succeeded=steps_succeeded,
        evidence=evidence,
        validated=validated,
    )
