"""LLM-based payload mutation — Haiku bulk variants + Sonnet WAF-bypass."""
from __future__ import annotations

import asyncio
import json
import os
import re

from log.audit import log_step

HAIKU_MODEL = "claude-haiku-4-5-20251001"
SONNET_MODEL = "claude-sonnet-4-6"

BULK_SYSTEM = (
    "You are a security payload mutator. Generate 10 variants of each payload that "
    "evade common WAFs. Return a JSON array of strings only, no prose, no markdown."
)

WAF_BYPASS_SYSTEM = (
    "You are an expert WAF bypass researcher. Generate 20 WAF bypass variants of the "
    "given payload for the specified technology stack. Return a JSON array of strings only."
)


def _parse_json_array(text: str) -> list[str]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text.strip())
    try:
        result = json.loads(text)
        if isinstance(result, list):
            return [str(x) for x in result]
    except Exception:
        pass
    return []


class LLMPayloadMutator:
    """Generate WAF-evasion payload variants using Claude."""

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

    async def mutate_bulk(self, payloads: list[str], context: str = "") -> list[str]:
        client = self._get_client()
        if not client:
            return payloads

        all_variants: list[str] = []
        loop = asyncio.get_event_loop()

        for i in range(0, len(payloads), 50):
            batch = payloads[i:i + 50]
            prompt = json.dumps(batch)
            if context:
                prompt = f"Context: {context}\n\nPayloads: {prompt}"

            def _call(p=prompt) -> str:
                try:
                    msg = client.messages.create(
                        model=HAIKU_MODEL, max_tokens=4096,
                        system=BULK_SYSTEM,
                        messages=[{"role": "user", "content": p}],
                    )
                    return msg.content[0].text
                except Exception:
                    return "[]"

            raw = await loop.run_in_executor(None, _call)
            variants = _parse_json_array(raw)
            all_variants.extend(variants)
            log_step("payload_mutator.bulk", batch=i, variants=len(variants))

        return all_variants if all_variants else payloads

    async def mutate_waf_bypass(self, payload: str, tech_stack: list[str]) -> list[str]:
        client = self._get_client()
        if not client:
            return [payload]

        tech = ", ".join(tech_stack) if tech_stack else "generic"
        user_msg = f"Technology stack: {tech}\n\nPayload: {payload}"
        loop = asyncio.get_event_loop()

        def _call() -> str:
            try:
                msg = client.messages.create(
                    model=SONNET_MODEL, max_tokens=2048,
                    system=WAF_BYPASS_SYSTEM,
                    messages=[{"role": "user", "content": user_msg}],
                )
                return msg.content[0].text
            except Exception:
                return "[]"

        raw = await loop.run_in_executor(None, _call)
        variants = _parse_json_array(raw)
        log_step("payload_mutator.waf_bypass", tech=tech, variants=len(variants))
        return variants if variants else [payload]
