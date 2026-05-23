"""Rules-of-Engagement (ROE) gate for SWIFT red-team operations.

Every offensive command must load and validate an ROE before touching a target.
Fail-closed: missing ROE = SystemExit with [DENY] prefix.

v6.0 Technique Strings
-----------------------
Existing (v5.x):
  - osint           : Passive reconnaissance (DNS, WHOIS, GitHub dorks, Shodan)
  - active_scan     : Active vulnerability probing (SQLi, XSS, SSRF, IDOR, JWT, etc.)
  - exploit         : Exploitation of discovered vulnerabilities
  - post_exploit    : Post-exploitation (data-exfil, persistence, C2 feasibility)

New in v6.0:
  - oob_ssrf        : Out-of-band SSRF probing using external callback infrastructure
  - oauth_attack    : OAuth/OIDC flow attacks (token leakage, redirect abuse, PKCE bypass)
  - websocket_attack: WebSocket protocol-level attacks and message tampering
  - bizlogic        : Business logic abuse (price manipulation, workflow bypass, race conditions)
  - agentic_loop    : Autonomous multi-step agentic attack loop execution
  - chain_execution : Replay of chained credential-reuse or multi-step attack sequences

New in v7.1:
  - research        : Claude-driven research over PUBLIC surface (docs, OSS repos, CVEs, papers).
                      No decompilation, no live exploitation. Produces hypothesis ledger + manual playbook.

New in v8.0 (Decepticon + claude-bug-bounty merge):
  - tmux_interactive    : Interactive tmux-managed tool sessions (msfconsole, sliver, evil-winrm).
  - vuln_pipeline       : 5-stage Scanner -> Detector -> Verifier -> Exploiter -> Patcher flow.
  - engagement_planning : Soundwave interview + OPPLAN + ConOps generation (no live probing).
  - web3_audit          : Smart contract static analysis (Solidity/EVM/Solana).
  - auth_chain          : Authenticated tool propagation (session tokens flow to httpx/katana/ffuf/nuclei).
  - hunt_memory_read    : Read cross-engagement hunt memory (audit.jsonl / patterns.jsonl).
  - hunt_memory_write   : Write/append to cross-engagement hunt memory.
  - langgraph_subagent  : Invoke a LangGraph specialist sub-graph (Decepticon-ported agents).
"""
from __future__ import annotations

import hashlib
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore

# All recognized technique strings (v5.x + v6.0 + v7.0 + v7.1 + v8.0)
KNOWN_TECHNIQUES: frozenset[str] = frozenset({
    # v5.x
    "osint", "active_scan", "exploit", "post_exploit",
    # v6.0
    "oob_ssrf", "oauth_attack", "websocket_attack", "bizlogic",
    "agentic_loop", "chain_execution",
    # v7.0 — Kali Linux tool phases
    "kali", "probe", "novel",
    # v7.0 — new techniques
    "cloud_recon", "ad_enum", "supply_chain_check", "intel_sync",
    # v7.1 — research
    "research",
    # v8.0 — Decepticon + claude-bug-bounty merge
    "tmux_interactive", "vuln_pipeline", "engagement_planning",
    "web3_audit", "auth_chain",
    "hunt_memory_read", "hunt_memory_write",
    "langgraph_subagent",
})


class ROEViolation(Exception):
    """Raised when an ROE gate is violated and raise_on_violation=True.

    Provides a programmatic alternative to the default sys.exit(2) behaviour
    so callers (agents, tests, async pipelines) can catch and handle denials
    without terminating the process.
    """


@dataclass(frozen=True)
class ROE:
    engagement_id: str
    authorized_targets: list       # hostnames, IPs, CIDRs, URL prefixes
    allowed_techniques: set        # "osint", "active_scan", "exploit", "post_exploit"
    window_start: datetime
    window_end: datetime
    contact: str
    max_runtime_seconds: int = 1800
    simulate_only: bool = True
    allow_chain_execution: bool = False  # must be True to replay live attack chains
    roe_sha256: str = ""           # populated by load_roe()
    # v7.1: per-engagement rate limit. None = caller MUST decide (fail-closed for web-scan).
    rate_limit_rps: Optional[float] = None
    rate_limit_burst: int = 1


def load_roe(path: Path | str) -> ROE:
    """Load and validate a ROE YAML file. Fail-closed on any error."""
    if yaml is None:
        _deny(
            "PyYAML not installed for this Python. "
            "If you use Homebrew Python: python3 -m pip install pyyaml "
            "(must match the interpreter that runs swiftsec)"
        )
    p = Path(path).resolve()
    if not p.exists():
        _deny(f"ROE file not found: {p}  --  create one with: swift --init-roe {p}")
    raw = p.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    try:
        data = yaml.safe_load(raw)
    except Exception as e:
        _deny(f"ROE parse error: {e}")

    required = ["engagement_id", "authorized_targets", "allowed_techniques",
                "window_start", "window_end", "contact"]
    for key in required:
        if key not in data:
            _deny(f"ROE missing required key: {key}")

    # Parse window as UTC-aware datetimes
    def _parse_dt(v) -> datetime:
        if isinstance(v, datetime):
            return v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v
        return datetime.fromisoformat(str(v)).replace(tzinfo=timezone.utc)

    allow_chain_exec = bool(data.get("allow_chain_execution", False))
    simulate_only = bool(data.get("simulate_only", True))
    if allow_chain_exec and simulate_only:
        import warnings
        warnings.warn(
            f"[ROE WARNING] engagement '{data['engagement_id']}': "
            "allow_chain_execution=True with simulate_only=True is contradictory. "
            "Chain execution will only proceed if allow_chain_execution is explicitly set.",
            stacklevel=2,
        )

    rps_raw = data.get("rate_limit_rps")
    rate_limit_rps = float(rps_raw) if rps_raw is not None else None
    if rate_limit_rps is not None and rate_limit_rps <= 0:
        _deny(f"rate_limit_rps must be > 0, got {rate_limit_rps}")

    return ROE(
        engagement_id=data["engagement_id"],
        authorized_targets=list(data["authorized_targets"]),
        allowed_techniques=set(data.get("allowed_techniques", ["osint", "active_scan"])),
        window_start=_parse_dt(data["window_start"]),
        window_end=_parse_dt(data["window_end"]),
        contact=data["contact"],
        max_runtime_seconds=int(data.get("max_runtime_seconds", 1800)),
        simulate_only=simulate_only,
        allow_chain_execution=allow_chain_exec,
        roe_sha256=sha,
        rate_limit_rps=rate_limit_rps,
        rate_limit_burst=int(data.get("rate_limit_burst", 1)),
    )


def assert_target_in_scope(roe: ROE, target: str) -> None:
    """Raise SystemExit if target is not in the authorized_targets list."""
    target_lower = target.lower()
    for authorized in roe.authorized_targets:
        auth = str(authorized).lower()
        if target_lower == auth or target_lower.startswith(auth) or auth in target_lower:
            return
    _deny(
        f"Target '{target}' is NOT in the authorized scope defined in engagement "
        f"'{roe.engagement_id}'.\n"
        f"Authorized targets: {roe.authorized_targets}\n"
        f"Add the target to the ROE file or obtain a new ROE."
    )


def assert_technique_allowed(
    roe: ROE,
    technique: str,
    raise_on_violation: bool = False,
) -> bool:
    """Check that *technique* is permitted by this ROE.

    Args:
        roe: The loaded ROE to check against.
        technique: Technique string to validate (see module docstring for the
            full list of recognised values, including v6.0 additions).
        raise_on_violation: When ``True``, raise :class:`ROEViolation` instead
            of calling :func:`_deny` (which prints and calls ``sys.exit(2)``).
            Defaults to ``False`` to preserve existing behaviour.

    Returns:
        ``True`` if the technique is allowed.

    Raises:
        ROEViolation: If *raise_on_violation* is ``True`` and the technique is
            not in ``roe.allowed_techniques``.
        SystemExit: (exit code 2) If *raise_on_violation* is ``False`` and the
            technique is not allowed — identical to the pre-v6.0 behaviour.
    """
    if technique not in roe.allowed_techniques:
        message = (
            f"Technique '{technique}' is NOT allowed by engagement '{roe.engagement_id}'.\n"
            f"Allowed: {sorted(roe.allowed_techniques)}"
        )
        if raise_on_violation:
            raise ROEViolation(message)
        _deny(message)
    return True


def assert_window_active(roe: ROE) -> None:
    """Raise SystemExit if the engagement window has expired or not started."""
    now = datetime.now(timezone.utc)
    if now < roe.window_start:
        _deny(f"Engagement window has not started yet. Start: {roe.window_start.isoformat()}")
    if now > roe.window_end:
        _deny(f"Engagement window has expired. End: {roe.window_end.isoformat()}")


def validate_all(roe: ROE, target: str, technique: str) -> None:
    """Run all three assertions. Call at every offensive entry point."""
    assert_window_active(roe)
    assert_target_in_scope(roe, target)
    assert_technique_allowed(roe, technique)


def _deny(message: str) -> None:
    print(f"[DENY] {message}", file=sys.stderr)
    sys.exit(2)


def load_scope(scope_path: str | Path | None) -> dict:
    """Load scope JSON file (HackerOne/Bugcrowd format).

    Expected format:
    {
      "in_scope": ["example.com", "*.example.com", "api.example.com"],
      "out_of_scope": ["staging.example.com", "admin.example.com"],
      "allowed_asset_types": ["URL", "WILDCARD"],
      "notes": "..."
    }

    Returns empty dict (allow-all) if scope_path is None.
    """
    if scope_path is None:
        return {}
    p = Path(scope_path).resolve()
    if not p.exists():
        _deny(f"Scope file not found: {p}")
    try:
        import json
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        _deny(f"Scope file parse error: {e}")
    if "in_scope" not in data:
        _deny("Scope file missing required key: 'in_scope'")
    return data


def assert_scope_file(scope: dict, target: str) -> None:
    """Verify target matches scope file. Fail-closed if not in scope."""
    if not scope:
        return  # no scope file = allow all (ROE is the gate)
    in_scope = scope.get("in_scope", [])
    out_of_scope = scope.get("out_of_scope", [])

    import fnmatch

    # Check out-of-scope first (deny wins)
    for pattern in out_of_scope:
        if fnmatch.fnmatch(target, pattern) or target.endswith(pattern.lstrip("*")):
            _deny(f"Target {target!r} matches out-of-scope pattern {pattern!r}")

    # Check in-scope
    for pattern in in_scope:
        if fnmatch.fnmatch(target, pattern) or target == pattern or target.endswith("." + pattern.lstrip("*.")):
            return

    _deny(f"Target {target!r} not found in scope. In-scope: {in_scope}")
