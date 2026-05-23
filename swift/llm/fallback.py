"""Tier-based provider fallback for SWIFT LLM calls.

Mirrors Decepticon's ModelFallbackMiddleware idea but stays neutral on the
agent framework (works for plain ``LLMClient.messages_create`` callers as well
as LangGraph nodes).

Tiers:
    HIGH  -- claude-3-5-sonnet, gpt-4o, gemini-1.5-pro       (deep reasoning)
    MID   -- claude-3-5-haiku, deepseek-chat, gemini-1.5-flash (triage)
    LOW   -- mistral-small, ollama/llama3.2, xai/grok-mini    (offline / cheap)

When LiteLLM is active the model name is passed straight through; LiteLLM does
its own provider routing. When in direct anthropic mode only the ``claude-*``
entries in the chain are reachable, and the rest are silently skipped.
"""
from __future__ import annotations

import logging
import time
from collections.abc import Callable
from enum import Enum
from typing import Any

from llm.client import LLMClient, ProviderError, get_client

log = logging.getLogger(__name__)


class Tier(str, Enum):
    HIGH = "high"
    MID = "mid"
    LOW = "low"


_TIER_CHAINS: dict[Tier, list[str]] = {
    Tier.HIGH: [
        "claude-sonnet-4-6",
        "claude-3-5-sonnet-latest",
        "gpt-4o",
        "gemini-1.5-pro",
    ],
    Tier.MID: [
        "claude-haiku-4-5",
        "claude-3-5-haiku-latest",
        "deepseek-chat",
        "gemini-1.5-flash",
    ],
    Tier.LOW: [
        "mistral-small-latest",
        "ollama/llama3.2",
        "xai/grok-3-mini",
    ],
}


def _is_anthropic_model(name: str) -> bool:
    return name.startswith("claude")


def fallback_chain(
    tier: Tier,
    *,
    call: Callable[[str], Any] | None = None,
    client: LLMClient | None = None,
    max_attempts: int = 3,
    backoff: float = 1.5,
) -> Any:
    """Execute ``call(model)`` against each model in ``tier`` until one returns.

    If ``call`` is omitted this function only returns the first reachable model
    name for the active client mode (useful for dry-runs).
    """
    client = client or get_client()
    chain = _TIER_CHAINS[tier]
    if client.mode == "anthropic":
        chain = [m for m in chain if _is_anthropic_model(m)]
    if not chain:
        raise ProviderError(f"no models in tier {tier.value} reachable in mode={client.mode}")

    if call is None:
        return chain[0]

    last_exc: Exception | None = None
    attempts = 0
    for model in chain:
        attempts += 1
        try:
            return call(model)
        except ProviderError as e:
            last_exc = e
            log.warning("llm.fallback: %s failed (%s); next in chain", model, e)
            if attempts >= max_attempts:
                break
            time.sleep(backoff ** attempts)
    raise ProviderError(
        f"all models in tier {tier.value} exhausted after {attempts} attempts; "
        f"last error: {last_exc}"
    )
