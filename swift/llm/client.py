"""LLM client stub — Claude API features removed.

SWIFT now uses OWASP tools (semgrep, bandit, nuclei, nikto, zap) for all
scanning. This module is retained for import compatibility with v8 optional
features (langgraph layer, research agent) that still accept an optional
LLM client. When no API key is set those features degrade gracefully.
"""
from __future__ import annotations

import os
from typing import Any


class ProviderError(RuntimeError):
    """Raised when an LLM provider call is attempted without configuration."""


class LLMClient:
    """No-op LLM client.  All methods raise ProviderError unless an API key
    is explicitly provided and the ``anthropic`` SDK is installed.
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        litellm_base_url: str | None = None,
    ) -> None:
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.litellm_base_url = litellm_base_url or os.getenv("LITELLM_BASE_URL")
        self._mode = "disabled"
        self._client: Any = None

        if self.litellm_base_url:
            try:
                from openai import OpenAI
                self._mode = "litellm"
                self._client = OpenAI(
                    base_url=self.litellm_base_url,
                    api_key=self.api_key or "sk-litellm-passthrough",
                )
            except ImportError:
                pass
        elif self.api_key:
            try:
                import anthropic
                self._mode = "anthropic"
                self._client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                pass

    @property
    def mode(self) -> str:
        return self._mode

    def messages_create(self, **kwargs: Any) -> Any:
        if self._client is None:
            raise ProviderError(
                "LLM features are disabled. SWIFT uses OWASP tools for scanning. "
                "Set ANTHROPIC_API_KEY only if you need optional LLM features."
            )
        return self._client.messages.create(**kwargs)


_singleton: LLMClient | None = None


def get_client(*, force_new: bool = False) -> LLMClient:
    global _singleton
    if force_new or _singleton is None:
        _singleton = LLMClient()
    return _singleton
