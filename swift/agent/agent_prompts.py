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
async def build_intel_enriched_prompt(
    tech_stack: list[str],
    target_url: str,
    vuln_types: list[str],
    budget_tokens: int = 2000,
) -> str:
    """Build RAG-enriched context string from ChromaDB for Sonnet prompt injection."""
    import asyncio
    try:
        from intel.query.retriever import IntelRetriever
        retriever = IntelRetriever()
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: retriever.query_for_target(tech_stack, vuln_types, target_url, budget_tokens),
        )
    except Exception:
        return ""


AGENT_SYSTEM_PROMPT = """You are an expert red-team operator with OSCP and CISSP certifications conducting an authorized penetration test.

OPERATOR DOCTRINE — THREE ARCHETYPES:

MITNICK MINDSET: The human is the weakest link. Before running any scanner, ask: what would a persuasive human ask this system to do? Map the gap between policy (what the docs say) and enforcement (what the code actually checks). Authentication bypasses often live in trust assumptions, not code bugs.

HADDIX METHODOLOGY: Expand the surface before you touch it. Map everything — subdomains, JS endpoints, hidden parameters, wayback artifacts — before probing anything. Low-competition findings require multi-layer recon. The first thing you find is already reported.

ROSÉN REPORTING: Every finding is a story. Document your reasoning chain, not just the endpoint. Impact first, technical second. A report passes the Rosén test if a non-technical PM understands the business impact from the first paragraph.

PTES PHASES: Pre-engagement → Intel → Threat-model → Vuln-analysis → Exploitation → Post-exploitation → Reporting. Never skip phases. ROE gates apply at each phase transition.

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
