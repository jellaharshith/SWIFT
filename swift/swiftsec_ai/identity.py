"""Scoped sub-agent identity + signed append-only action log.

Each sub-agent spawned during a run gets a role-scoped ``SubAgentIdentity``. A
sub-agent must call ``assert_can(tool)`` before dispatching any tool — calling
outside its role's allowlist raises ``PermissionError`` and is never silently
allowed, even if a parent agent requested it.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

PERMISSION_SETS = {
    "recon": {"allowed": ["cve_lookup", "scope_check", "run_recon"], "network": "passive"},
    "enum": {"allowed": ["scope_check", "run_scan"], "network": "active_safe"},
    "exploit": {"allowed": ["scope_check", "run_scan", "ai_asm", "redteam"], "network": "active_targeted"},
    "report": {"allowed": ["draft_h1_report"], "network": "none"},
}


class SubAgentIdentity:
    """A scoped, signed identity for one sub-agent within one engagement."""

    def __init__(self, agent_role: str, engagement_id: str, log_dir: str | Path = "logs") -> None:
        if agent_role not in PERMISSION_SETS:
            raise ValueError(f"unknown agent_role {agent_role!r} (expected one of {list(PERMISSION_SETS)})")
        self.role = agent_role
        self.engagement_id = engagement_id
        self.token = self._mint_token()
        self.log_dir = Path(log_dir)
        self.log_path = self.log_dir / f"agent-{agent_role}-{engagement_id}.jsonl"

    def _mint_token(self) -> str:
        payload = f"{self.role}:{self.engagement_id}:{time.time()}"
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    def can(self, tool_name: str) -> bool:
        return tool_name in PERMISSION_SETS.get(self.role, {}).get("allowed", [])

    def assert_can(self, tool_name: str) -> None:
        if not self.can(tool_name):
            raise PermissionError(f"SubAgent [{self.role}:{self.token}] not permitted to call {tool_name!r}")

    def log_action(self, tool_name: str, args: dict, result_hash: str) -> None:
        """Append-only signed log entry. Never edit, only append."""
        self.log_dir.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts": time.time(),
            "agent": self.role,
            "token": self.token,
            "tool": tool_name,
            "args_hash": hashlib.sha256(json.dumps(args, sort_keys=True, default=str).encode()).hexdigest()[:12],
            "result_hash": result_hash,
        }
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")


def write_agent_manifest(identities: list[SubAgentIdentity], out_path: str | Path = "AGENT_MANIFEST.md") -> Path:
    """Write the audit-trail manifest listing every agent spawned this run."""
    lines = ["# AGENT_MANIFEST", ""]
    for ident in identities:
        lines.append(f"## {ident.role} ({ident.token})")
        lines.append(f"- engagement: {ident.engagement_id}")
        lines.append(f"- allowed tools: {PERMISSION_SETS[ident.role]['allowed']}")
        lines.append(f"- action log: {ident.log_path}")
        lines.append("")
    path = Path(out_path)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
