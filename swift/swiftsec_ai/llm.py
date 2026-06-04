"""Pluggable LLM backends — no SDKs, just `requests`.

Both backends share one entry point::

    backend.run(system, user_message, tools, executor, max_iterations, on_tool) -> str

`tools` is a list of *neutral* schemas (see tools.py: ``to_neutral_schema``)::

    {"name": str, "description": str, "parameters": {<json-schema object>}}

Each backend translates that neutral schema into its own wire format
(Anthropic ``input_schema`` / Ollama ``function.parameters``) and runs a
tool-calling loop, calling ``executor(name, args) -> str`` for each tool the
model invokes and feeding the result back until the model stops calling tools
or ``max_iterations`` is hit.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from .config import Settings

Executor = Callable[[str, dict], str]
OnTool = Callable[[str, dict, str], None] | None
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"


class BackendError(RuntimeError):
    """Raised when a backend cannot complete a request."""


# ----------------------------------------------------------- schema translation

def to_anthropic_tools(neutral: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Neutral schema → Anthropic ``input_schema`` form."""
    return [
        {
            "name": t["name"],
            "description": t.get("description", ""),
            "input_schema": t.get("parameters", {"type": "object", "properties": {}}),
        }
        for t in neutral
    ]


def to_ollama_tools(neutral: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Neutral schema → OpenAI/Ollama ``function.parameters`` form."""
    return [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t.get("description", ""),
                "parameters": t.get("parameters", {"type": "object", "properties": {}}),
            },
        }
        for t in neutral
    ]


# --------------------------------------------------------------------- backends

class OllamaBackend:
    name = "ollama"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.model = settings.ollama_model
        self.host = settings.ollama_host.rstrip("/")
        self.timeout = settings.ollama_timeout

    def run(
        self,
        system: str,
        user_message: str,
        tools: list[dict[str, Any]],
        executor: Executor,
        max_iterations: int = 6,
        on_tool: OnTool = None,
    ) -> str:
        import requests

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system},
            {"role": "user", "content": user_message},
        ]
        wire_tools = to_ollama_tools(tools)

        for _ in range(max_iterations):
            body = {
                "model": self.model,
                "messages": messages,
                "tools": wire_tools,
                "stream": False,
            }
            try:
                resp = requests.post(
                    f"{self.host}/api/chat", json=body, timeout=self.timeout
                )
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                raise BackendError(f"ollama request failed: {e}") from e

            msg = data.get("message", {}) or {}
            messages.append(msg)
            tool_calls = msg.get("tool_calls") or []
            if not tool_calls:
                return msg.get("content", "") or ""

            for call in tool_calls:
                fn = call.get("function", {}) or {}
                name = fn.get("name", "")
                args = fn.get("arguments", {})
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        args = {}
                result = executor(name, args if isinstance(args, dict) else {})
                if on_tool:
                    on_tool(name, args if isinstance(args, dict) else {}, result)
                messages.append({"role": "tool", "name": name, "content": result})

        return "[swiftsec_ai] stopped: reached max tool iterations without a final answer."


class AnthropicBackend:
    name = "anthropic"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.model = settings.anthropic_model
        self.api_key = settings.anthropic_api_key
        self.max_tokens = settings.anthropic_max_tokens

    def run(
        self,
        system: str,
        user_message: str,
        tools: list[dict[str, Any]],
        executor: Executor,
        max_iterations: int = 6,
        on_tool: OnTool = None,
    ) -> str:
        import requests

        if not self.api_key:
            raise BackendError(
                "ANTHROPIC_API_KEY is not set — cannot use the anthropic backend."
            )

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        }
        wire_tools = to_anthropic_tools(tools)
        messages: list[dict[str, Any]] = [
            {"role": "user", "content": user_message}
        ]

        for _ in range(max_iterations):
            body = {
                "model": self.model,
                "max_tokens": self.max_tokens,
                "system": system,
                "messages": messages,
                "tools": wire_tools,
            }
            try:
                resp = requests.post(
                    ANTHROPIC_API_URL, json=body, headers=headers, timeout=120
                )
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                raise BackendError(f"anthropic request failed: {e}") from e

            content_blocks = data.get("content", []) or []
            # Echo the assistant turn back verbatim so tool_use ids line up.
            messages.append({"role": "assistant", "content": content_blocks})

            if data.get("stop_reason") != "tool_use":
                return _anthropic_text(content_blocks)

            tool_results = []
            for block in content_blocks:
                if block.get("type") != "tool_use":
                    continue
                name = block.get("name", "")
                args = block.get("input", {}) or {}
                result = executor(name, args if isinstance(args, dict) else {})
                if on_tool:
                    on_tool(name, args if isinstance(args, dict) else {}, result)
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.get("id"),
                        "content": result,
                    }
                )
            messages.append({"role": "user", "content": tool_results})

        return "[swiftsec_ai] stopped: reached max tool iterations without a final answer."


def _anthropic_text(blocks: list[dict[str, Any]]) -> str:
    return "\n".join(b.get("text", "") for b in blocks if b.get("type") == "text").strip()


def build_backend(settings: Settings):
    """Factory: resolve ``auto`` and return the matching backend instance.

    Construction never performs network I/O, so a backend can be built even when
    nothing is configured (``info`` relies on this).
    """
    backend = settings.resolved_backend
    if backend == "anthropic":
        return AnthropicBackend(settings)
    if backend == "ollama":
        return OllamaBackend(settings)
    raise BackendError(f"unknown backend: {backend!r}")
