"""ATT&CK-annotated exploit chain reasoning via Claude Sonnet."""
from __future__ import annotations

import asyncio
import json
import os
import re
from dataclasses import dataclass, field

from sdk.base import Finding, Severity
from log.audit import log_step

SONNET_MODEL = "claude-sonnet-4-6"

CHAIN_SYSTEM = (
    "You are an ATT&CK expert red team analyst. Given security findings, identify exploit chains. "
    "For each chain provide: steps (ordered attack steps), techniques (MITRE ATT&CK IDs), "
    "impact, prerequisites, confidence (0.0-1.0). "
    "Return ONLY a JSON array of chain objects. No prose."
)


@dataclass
class ExploitChain:
    steps: list[str]
    techniques: list[str]
    impact: str
    prerequisites: list[str]
    confidence: float
    source_finding_ids: list[str] = field(default_factory=list)


class AttackGraphReasoner:
    """Use Sonnet to reason about exploit chains from findings + RAG context."""

    def __init__(self) -> None:
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                import anthropic
                api_key = os.getenv("ANTHROPIC_API_KEY", "")
                if api_key:
                    self._client = anthropic.Anthropic(api_key=api_key)
            except Exception:
                pass
        return self._client

    def _build_summary(self, findings: list[Finding]) -> str:
        by_sev: dict[str, list[str]] = {}
        for f in findings:
            by_sev.setdefault(f.severity.value, []).append(
                f"[{f.vuln_type.value}] {f.title} @ {f.target_url}"
            )
        lines = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if sev in by_sev:
                lines.append(f"\n{sev}:")
                lines.extend(f"  - {item}" for item in by_sev[sev])
        return "\n".join(lines)

    def _parse_chains(self, text: str, finding_ids: list[str]) -> list[ExploitChain]:
        text = text.strip()
        if text.startswith("```"):
            text = re.sub(r"^```[a-z]*\n?", "", text)
            text = re.sub(r"\n?```$", "", text.strip())
        try:
            data = json.loads(text)
            chains = []
            for item in data:
                if not isinstance(item, dict):
                    continue
                chain = ExploitChain(
                    steps=item.get("steps", []),
                    techniques=item.get("techniques", []),
                    impact=item.get("impact", ""),
                    prerequisites=item.get("prerequisites", []),
                    confidence=float(item.get("confidence", 0.0)),
                    source_finding_ids=finding_ids,
                )
                if chain.confidence >= 0.7:
                    chains.append(chain)
            return chains
        except Exception:
            return []

    async def reason_chains(
        self, findings: list[Finding], intel_context: str = ""
    ) -> list[ExploitChain]:
        client = self._get_client()
        if not client or not findings:
            return []

        summary = self._build_summary(findings)
        user_msg = f"Security findings:\n{summary}"
        if intel_context:
            user_msg += f"\n\nThreat intel context:\n{intel_context[:1000]}"

        finding_ids = [f.id for f in findings]
        loop = asyncio.get_event_loop()

        def _call() -> str:
            try:
                msg = client.messages.create(
                    model=SONNET_MODEL, max_tokens=3000,
                    system=CHAIN_SYSTEM,
                    messages=[{"role": "user", "content": user_msg}],
                )
                return msg.content[0].text
            except Exception:
                return "[]"

        raw = await loop.run_in_executor(None, _call)
        chains = self._parse_chains(raw, finding_ids)
        log_step("attack_graph.chains", count=len(chains), findings=len(findings))
        return chains
