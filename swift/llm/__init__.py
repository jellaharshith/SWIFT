"""Unified LLM client for SWIFT v8.0.

Default path: direct Anthropic SDK (byte-identical to v7.x behavior).
Optional path: LiteLLM proxy when ``LITELLM_BASE_URL`` env is set (enabled by
``swiftsec lab up``). Same call signature either way.

Public surface:
    from llm import get_client, LLMClient, Tier, ProviderError
"""
from llm.client import LLMClient, ProviderError, get_client
from llm.fallback import Tier, fallback_chain

__all__ = ["LLMClient", "ProviderError", "Tier", "fallback_chain", "get_client"]
