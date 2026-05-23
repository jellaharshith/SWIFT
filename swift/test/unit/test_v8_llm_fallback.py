"""v8.0 -- Tier enum + fallback stub (LLM optional, OWASP-first mode)."""
from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from llm.client import LLMClient, ProviderError
from llm.fallback import Tier, fallback_chain


def _disabled_client() -> LLMClient:
    """Build a client with no keys in env → mode=disabled."""
    clean_env = {k: v for k, v in os.environ.items()
                 if k not in ("ANTHROPIC_API_KEY", "LITELLM_BASE_URL")}
    with patch.dict(os.environ, clean_env, clear=True):
        return LLMClient()


def test_tier_enum_values_exist():
    assert Tier.HIGH == "high"
    assert Tier.MID == "mid"
    assert Tier.LOW == "low"


def test_fallback_chain_raises_in_owasp_only_mode():
    """No client configured → OWASP-only mode → ProviderError."""
    client = _disabled_client()
    assert client.mode == "disabled"
    with pytest.raises(ProviderError, match="OWASP"):
        fallback_chain(Tier.HIGH, client=client)


def test_fallback_chain_no_call_raises_in_disabled_mode():
    client = _disabled_client()
    with pytest.raises(ProviderError):
        fallback_chain(Tier.HIGH, client=client, call=None)


def test_provider_error_importable():
    from llm.client import ProviderError as PE
    assert issubclass(PE, RuntimeError)
