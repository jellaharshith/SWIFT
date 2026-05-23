"""v8.0 -- tier-based LLM fallback (no real API calls)."""
from __future__ import annotations

import pytest

from llm.client import LLMClient, ProviderError
from llm.fallback import Tier, fallback_chain


class _FakeAnthropicClient(LLMClient):
    """Test double that records the model and lets us raise on demand."""

    def __init__(self, fail_on: set[str] | None = None) -> None:  # noqa: D401
        # Intentionally do not call super().__init__ -- no real SDK needed.
        self.litellm_base_url = None
        self.api_key = "fake"
        self._mode = "anthropic"
        self.fail_on = fail_on or set()
        self.calls: list[str] = []

    def messages_create(self, **kw):  # type: ignore[override]
        model = kw["model"]
        self.calls.append(model)
        if model in self.fail_on:
            raise ProviderError(f"forced fail on {model}")
        return {"ok": True, "model": model}


def test_chain_returns_first_model_when_no_call():
    c = _FakeAnthropicClient()
    name = fallback_chain(Tier.HIGH, client=c)
    assert name.startswith("claude")


def test_chain_skips_failing_models():
    c = _FakeAnthropicClient(fail_on={"claude-sonnet-4-6"})
    res = fallback_chain(
        Tier.HIGH,
        client=c,
        call=lambda m: c.messages_create(model=m, messages=[], max_tokens=1),
    )
    assert res["model"] != "claude-sonnet-4-6"


def test_chain_exhaustion_raises():
    c = _FakeAnthropicClient(fail_on={"claude-sonnet-4-6", "claude-3-5-sonnet-latest"})
    with pytest.raises(ProviderError):
        fallback_chain(
            Tier.HIGH,
            client=c,
            call=lambda m: c.messages_create(model=m, messages=[], max_tokens=1),
            max_attempts=2,
            backoff=1.0,
        )
