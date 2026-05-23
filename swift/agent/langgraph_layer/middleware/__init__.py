"""Cross-cutting concerns for specialist agent invocation.

These wrap every agent call, in order:

1. :func:`engagement_context_middleware` -- attaches engagement metadata
   (engagement_id, target list, RoE summary) to the state.
2. :func:`opplan_middleware`             -- injects MITRE ATT&CK phase
   hints from the active OPPLAN.
3. :func:`model_fallback_middleware`     -- routes LLM calls through the
   tier-based :func:`llm.fallback.fallback_chain` so a provider hiccup
   does not abort the graph.

These are plain decorator functions to keep the layer framework-neutral.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from llm.client import LLMClient, ProviderError
from llm.fallback import Tier, fallback_chain
from log.audit import log_step

AgentCall = Callable[[dict[str, Any]], dict[str, Any]]


def engagement_context_middleware(state: dict[str, Any]) -> dict[str, Any]:
    """Read state['engagement'] (already loaded ROE) and project a compact
    summary string into state['engagement_summary'] for prompt injection."""
    eng = state.get("engagement") or {}
    if not eng:
        return state
    summary_lines = [
        f"engagement_id: {eng.get('engagement_id', '?')}",
        f"contact: {eng.get('contact', '?')}",
        f"targets: {', '.join(map(str, eng.get('authorized_targets', [])))}",
        f"techniques: {', '.join(sorted(eng.get('allowed_techniques', [])))}",
        f"simulate_only: {eng.get('simulate_only', True)}",
    ]
    state["engagement_summary"] = "\n".join(summary_lines)
    return state


def opplan_middleware(state: dict[str, Any]) -> dict[str, Any]:
    opplan = state.get("opplan")
    if not opplan:
        return state
    state["opplan_summary"] = (
        f"Active OPPLAN phase: {opplan.get('phase', 'recon')}; "
        f"objectives: {', '.join(opplan.get('objectives', []))}"
    )
    return state


def run_with_fallback(
    client: LLMClient,
    *,
    tier: Tier,
    messages: list[dict[str, Any]],
    system: str,
    tools: list[dict[str, Any]] | None = None,
    max_tokens: int = 4096,
) -> Any:
    """Tier-fallback wrapper around :meth:`LLMClient.messages_create`.

    Treats ``ProviderError`` as a retry signal; bubbles other exceptions.
    """
    def _call(model: str) -> Any:
        try:
            return client.messages_create(
                model=model,
                messages=messages,
                system=system,
                tools=tools,
                max_tokens=max_tokens,
            )
        except ProviderError:
            log_step("llm.provider_error", model=model)
            raise

    return fallback_chain(tier, call=_call, client=client)
