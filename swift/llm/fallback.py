"""Tier enum and fallback stub — Claude API features removed.

The Tier enum is retained for import compatibility with the optional
LangGraph layer (v8 optional feature). fallback_chain() raises ProviderError
unless an LLM client is explicitly configured.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from enum import Enum
from typing import Any

from llm.client import LLMClient, ProviderError, get_client

log = logging.getLogger(__name__)


class Tier(str, Enum):
    HIGH = "high"
    MID = "mid"
    LOW = "low"


def fallback_chain(
    tier: Tier,
    *,
    call: Callable[[str], Any] | None = None,
    client: LLMClient | None = None,
    max_attempts: int = 3,
    backoff: float = 1.5,
) -> Any:
    """Execute ``call(model)`` if an LLM client is configured.

    Raises ProviderError when no client is available (OWASP-only mode).
    """
    client = client or get_client()
    if client.mode == "disabled":
        raise ProviderError(
            "LLM fallback chain not available — SWIFT is running in OWASP-tools-only mode."
        )
    if call is None:
        return tier.value
    return call(tier.value)
