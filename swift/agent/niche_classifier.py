"""Niche classifier — Sonnet ranks attack niches for a target based on OSINT context."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Optional

from agent.pentester_persona import build_persona_preamble

_VALID_NICHES = [
    "api_security", "auth_bypass", "idor", "xss", "sqli", "ssrf", "ssti",
    "xxe", "jwt", "graphql", "race_condition", "nosql", "prototype_pollution",
    "file_upload", "deserialization",
]

_DEFAULT_PROFILE_NICHES = ["xss", "sqli", "idor"]

_SYSTEM_PROMPT = (
    build_persona_preamble(passive=False)
    + "\n\nYou are also a seasoned bug bounty hunter with CISSP and OSCP credentials. "
    "Given attack surface context, identify which OWASP/CWE vulnerability niches are "
    "most likely to yield high-impact, valid findings on this specific target."
)


@dataclass
class NicheProfile:
    """Attack niche profile produced by the niche classifier."""

    primary_niches: list[str] = field(default_factory=lambda: list(_DEFAULT_PROFILE_NICHES))
    focus_payloads: list[str] = field(default_factory=lambda: list(_DEFAULT_PROFILE_NICHES))
    bounty_tier: str = "medium"
    reasoning: str = "default"
    confidence: float = 0.3

    def to_dict(self) -> dict:
        return {
            "primary_niches": self.primary_niches,
            "focus_payloads": self.focus_payloads,
            "bounty_tier": self.bounty_tier,
            "reasoning": self.reasoning,
            "confidence": self.confidence,
        }


def _default_profile() -> NicheProfile:
    return NicheProfile(
        primary_niches=list(_DEFAULT_PROFILE_NICHES),
        focus_payloads=list(_DEFAULT_PROFILE_NICHES),
        bounty_tier="medium",
        reasoning="default",
        confidence=0.3,
    )


def _build_prompt(target: str, attack_surface) -> str:
    tech = ", ".join(getattr(attack_surface, "tech_stack", []) or []) or "unknown"
    endpoints_sample = (getattr(attack_surface, "endpoints", []) or [])[:10]
    ports = getattr(attack_surface, "open_ports", []) or []
    has_github_leaks = bool(getattr(attack_surface, "github_leaks", []))
    subdomains_count = len(getattr(attack_surface, "subdomains", []) or [])

    valid_niches_str = ", ".join(_VALID_NICHES)

    return f"""Target: {target}
Tech stack: {tech}
Open ports: {ports or 'unknown'}
Subdomains discovered: {subdomains_count}
GitHub leaks present: {has_github_leaks}
Sample endpoints: {endpoints_sample}

Based on the above attack surface context, rank the top 3-5 vulnerability niches most
likely to yield confirmed, high-impact findings on this target.

Valid niches: {valid_niches_str}

Respond with ONLY valid JSON, no markdown, no explanation:
{{
  "primary_niches": ["<niche1>", "<niche2>", "..."],
  "focus_payloads": ["<vuln_type1>", "<vuln_type2>", "..."],
  "bounty_tier": "<high|medium|low>",
  "reasoning": "<1-2 sentence rationale>",
  "confidence": <float 0.0-1.0>
}}

Rules:
- primary_niches: 3-5 items from the valid niches list only
- focus_payloads: vuln_type strings matching SWIFT probe types (xss, sqli, idor, ssrf, ssti, jwt, graphql, race_condition, etc.)
- bounty_tier: "high" if API-heavy or auth-heavy target, "low" for static/informational only
- confidence: your confidence in the niche classification (not vulnerability confidence)"""


def _parse_response(raw: str) -> Optional[NicheProfile]:
    try:
        data = json.loads(raw.strip())
        niches = [n for n in data.get("primary_niches", []) if n in _VALID_NICHES]
        if not niches:
            return None
        payloads = data.get("focus_payloads", niches)
        tier = data.get("bounty_tier", "medium")
        if tier not in ("high", "medium", "low"):
            tier = "medium"
        return NicheProfile(
            primary_niches=niches,
            focus_payloads=list(payloads) if payloads else niches,
            bounty_tier=tier,
            reasoning=str(data.get("reasoning", ""))[:500],
            confidence=float(data.get("confidence", 0.5)),
        )
    except Exception:
        return None


async def classify_niches(
    target: str,
    attack_surface,
    anthropic_client,
    model: str = "claude-sonnet-4-6",
) -> NicheProfile:
    """Classify attack niches for a target using Sonnet.

    Args:
        target: Primary domain being assessed.
        attack_surface: AttackSurface dataclass instance with tech_stack, endpoints, etc.
        anthropic_client: Initialized anthropic.Anthropic client.
        model: Model to use for classification.

    Returns:
        NicheProfile with ranked attack niches. Never raises — returns default on any error.
    """
    if anthropic_client is None:
        return _default_profile()

    try:
        response = anthropic_client.messages.create(
            model=model,
            max_tokens=512,
            system=[
                {
                    "type": "text",
                    "text": _SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[
                {"role": "user", "content": _build_prompt(target, attack_surface)}
            ],
        )
        raw = response.content[0].text
        profile = _parse_response(raw)
        if profile is not None:
            return profile
    except Exception:
        pass

    return _default_profile()
