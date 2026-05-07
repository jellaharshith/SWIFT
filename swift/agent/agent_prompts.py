"""Agent system prompt and model constants for the agentic red-team loop."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

# Model IDs
MODELS = {
    "haiku": "claude-haiku-4-5-20251001",
    "sonnet": "claude-sonnet-4-6",
    "opus": "claude-opus-4-7",
}

# Embed verbatim from spec
AGENT_SYSTEM_PROMPT = """You are an expert red-team operator with OSCP and CISSP certifications conducting an authorized penetration test. Your mission: systematically compromise the target by chaining vulnerabilities. Think like an attacker, operate like an engineer.

STRATEGY:
1. Start by reviewing the full attack surface (call get_attack_surface for all categories)
2. Form hypotheses about most likely vulnerability classes based on tech stack
3. Run targeted probes starting with highest-confidence hypotheses
4. When a probe finds something: immediately reason about what it enables (SQLi → credentials → auth bypass → IDOR → privesc)
5. Update hypotheses based on results. Failed probes are information too.
6. Mark vectors exhausted when: 3+ failed attempts, consistent 404/403, no injection points found
7. Stop when: budget exhausted, all high-confidence vectors tried, or you are confident no further progress is possible

CHAIN PRIORITY (highest first):
- auth_bypass → idor, privesc, data_exfil
- sqli → credential_dump, auth_bypass
- oauth_weakness → token_theft, api_access, idor
- ssrf → cloud_metadata, internal_network_pivot
- github_leak → credential_stuffing, secret_extraction

Always explain your reasoning using update_hypothesis before each probe call."""


@dataclass
class AgentBudget:
    max_probe_calls: int = 50
    max_sonnet_calls: int = 20
    max_time_seconds: int = 3600
    probe_calls_used: int = 0
    sonnet_calls_used: int = 0
    started_at: float = field(default_factory=lambda: __import__("time").time())

    def probe_remaining(self) -> int:
        return self.max_probe_calls - self.probe_calls_used

    def sonnet_remaining(self) -> int:
        return self.max_sonnet_calls - self.sonnet_calls_used

    def time_remaining(self) -> float:
        import time
        return self.max_time_seconds - (time.time() - self.started_at)

    def is_exhausted(self) -> bool:
        return (self.probe_calls_used >= self.max_probe_calls
                or self.sonnet_calls_used >= self.max_sonnet_calls
                or self.time_remaining() <= 0)


@dataclass
class AgentHypothesis:
    text: str
    confidence: float
    evidence: str
    created_at: float = field(default_factory=lambda: __import__("time").time())
    outcome: Optional[str] = None


@dataclass
class EngagementResult:
    findings: list = field(default_factory=list)
    hypotheses: list = field(default_factory=list)
    iterations: int = 0
    budget_consumed: Optional[AgentBudget] = None
    agent_log_path: Optional[Path] = None
