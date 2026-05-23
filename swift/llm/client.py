"""Uniform LLM client.

Two backends, one interface:

* ``anthropic`` direct SDK   -- default; used when ``LITELLM_BASE_URL`` is unset.
* LiteLLM OpenAI-compatible  -- used when ``LITELLM_BASE_URL`` is set.

Both expose :meth:`messages_create` returning the same shape as
``anthropic.Anthropic().messages.create(...)`` (an object with ``.content``,
``.stop_reason``, ``.usage`` attributes). LiteLLM's OpenAI-compat response is
adapted to that shape so callers do not branch.

Fallback across providers is implemented in :mod:`llm.fallback`; this module
intentionally does not retry on its own.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

try:
    import anthropic
except ImportError as exc:  # pragma: no cover -- anthropic is a hard dep
    raise RuntimeError("anthropic SDK missing; pip install anthropic") from exc


class ProviderError(RuntimeError):
    """Raised when an LLM provider call fails after the client has done its
    best to translate the underlying SDK exception."""


@dataclass
class _AnthropicResponse:
    """Minimal adapter object so LiteLLM responses match anthropic SDK shape."""

    content: list
    stop_reason: str
    usage: Any = None
    model: str = ""
    raw: Any = field(default=None, repr=False)


class LLMClient:
    """Single entry-point for LLM calls.

    Resolution order at construction:

    1. ``LITELLM_BASE_URL`` env present -> LiteLLM mode (multi-provider).
    2. otherwise                        -> direct ``anthropic.Anthropic()``.
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        litellm_base_url: str | None = None,
    ) -> None:
        self.litellm_base_url = litellm_base_url or os.getenv("LITELLM_BASE_URL")
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")

        if self.litellm_base_url:
            try:
                from openai import OpenAI  # litellm exposes OpenAI-compat
            except ImportError as exc:
                raise RuntimeError(
                    "LITELLM_BASE_URL set but `openai` not installed; "
                    "pip install swiftsec[litellm]"
                ) from exc
            # LiteLLM accepts any non-empty key; use Anthropic key if present.
            self._mode = "litellm"
            self._client = OpenAI(
                base_url=self.litellm_base_url,
                api_key=self.api_key or "sk-litellm-passthrough",
            )
        else:
            self._mode = "anthropic"
            self._client = anthropic.Anthropic(api_key=self.api_key) if self.api_key else anthropic.Anthropic()

    @property
    def mode(self) -> str:
        return self._mode

    def messages_create(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        max_tokens: int = 4096,
        system: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        temperature: float | None = None,
        **extra: Any,
    ) -> Any:
        """Direct passthrough to the underlying SDK.

        Returns an anthropic-shaped response object. Caller code that already
        works with ``anthropic.messages.create`` does not need to change.
        """
        if self._mode == "anthropic":
            kwargs = dict(model=model, messages=messages, max_tokens=max_tokens)
            if system is not None:
                kwargs["system"] = system
            if tools is not None:
                kwargs["tools"] = tools
            if temperature is not None:
                kwargs["temperature"] = temperature
            kwargs.update(extra)
            try:
                return self._client.messages.create(**kwargs)
            except anthropic.APIError as e:
                raise ProviderError(f"anthropic: {e}") from e

        # litellm OpenAI-compat
        oai_messages = list(messages)
        if system:
            oai_messages = [{"role": "system", "content": system}] + oai_messages
        kwargs = dict(model=model, messages=oai_messages, max_tokens=max_tokens)
        if tools is not None:
            kwargs["tools"] = tools
        if temperature is not None:
            kwargs["temperature"] = temperature
        kwargs.update(extra)
        try:
            resp = self._client.chat.completions.create(**kwargs)
        except Exception as e:  # OpenAI SDK raises a hierarchy; flatten here
            raise ProviderError(f"litellm[{model}]: {e}") from e

        choice = resp.choices[0]
        msg = choice.message
        content_blocks: list[dict[str, Any]] = []
        if msg.content:
            content_blocks.append({"type": "text", "text": msg.content})
        for tc in (getattr(msg, "tool_calls", None) or []):
            content_blocks.append({
                "type": "tool_use",
                "id": tc.id,
                "name": tc.function.name,
                "input": tc.function.arguments,
            })
        return _AnthropicResponse(
            content=content_blocks,
            stop_reason=choice.finish_reason or "end_turn",
            usage=getattr(resp, "usage", None),
            model=resp.model,
            raw=resp,
        )


_singleton: LLMClient | None = None


def get_client(*, force_new: bool = False) -> LLMClient:
    """Return a process-wide :class:`LLMClient` (constructed lazily).

    Callers should prefer this over instantiating their own so the LiteLLM
    routing decision is made once per process.
    """
    global _singleton
    if force_new or _singleton is None:
        _singleton = LLMClient()
    return _singleton
