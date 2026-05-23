"""Multi-model AI client — Claude → GPT-4o → Gemini fallback."""
from __future__ import annotations

import asyncio
import os
from typing import Any

from log.audit import log_step


class MultiModelClient:
    """Route AI completions across providers with automatic fallback on rate limits."""

    def __init__(
        self,
        primary: str = "claude",
        fallback_order: list[str] | None = None,
    ) -> None:
        self.primary = os.getenv("SWIFT_AI_MODEL", primary)
        self.fallback_order = fallback_order or ["openai", "gemini"]

    async def complete(
        self,
        messages: list[dict[str, Any]],
        system: str = "",
        max_tokens: int = 2048,
        model_override: str = "",
    ) -> str:
        providers = [model_override or self.primary] + [
            p for p in self.fallback_order if p != (model_override or self.primary)
        ]
        last_exc: Exception = RuntimeError("No providers configured")
        for provider in providers:
            try:
                result = await self._dispatch(provider, messages, system, max_tokens)
                log_step("multi_model.success", provider=provider)
                return result
            except Exception as exc:
                log_step("multi_model.fallback", from_provider=provider, error=str(exc)[:100])
                last_exc = exc
        raise last_exc

    async def _dispatch(
        self, provider: str, messages: list[dict], system: str, max_tokens: int
    ) -> str:
        if provider == "claude":
            return await self._call_claude(messages, system, max_tokens)
        elif provider == "openai":
            return await self._call_openai(messages, system, max_tokens)
        elif provider == "gemini":
            return await self._call_gemini(messages, system, max_tokens)
        raise ValueError(f"Unknown provider: {provider}")

    async def _call_claude(self, messages: list[dict], system: str, max_tokens: int) -> str:
        import anthropic
        client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY", ""))

        def _sync() -> str:
            kwargs: dict[str, Any] = {
                "model": "claude-sonnet-4-6",
                "max_tokens": max_tokens,
                "messages": messages,
            }
            if system:
                kwargs["system"] = system
            msg = client.messages.create(**kwargs)
            return msg.content[0].text

        return await asyncio.get_event_loop().run_in_executor(None, _sync)

    async def _call_openai(self, messages: list[dict], system: str, max_tokens: int) -> str:
        try:
            import openai
        except ImportError as exc:
            raise RuntimeError("openai package not installed") from exc
        api_key = os.getenv("OPENAI_API_KEY", "")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY not set")
        client = openai.AsyncOpenAI(api_key=api_key)
        all_msgs = ([{"role": "system", "content": system}] if system else []) + messages
        resp = await client.chat.completions.create(
            model="gpt-4o", messages=all_msgs, max_tokens=max_tokens,
        )
        return resp.choices[0].message.content or ""

    async def _call_gemini(self, messages: list[dict], system: str, max_tokens: int) -> str:
        try:
            import google.generativeai as genai  # type: ignore
        except ImportError as exc:
            raise RuntimeError("google-generativeai package not installed") from exc
        api_key = os.getenv("GEMINI_API_KEY", "")
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY not set")
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-1.5-pro")
        parts = ([system] if system else []) + [
            f"{m.get('role', 'user')}: {m.get('content', '')}" for m in messages
        ]
        prompt = "\n\n".join(parts)

        def _sync() -> str:
            return model.generate_content(prompt).text

        return await asyncio.get_event_loop().run_in_executor(None, _sync)
