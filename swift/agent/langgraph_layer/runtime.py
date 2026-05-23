"""Specialist agent runtime.

One function -- :func:`run_specialist` -- runs a Claude tool-use loop for a
:class:`agent.langgraph_layer.specialists.Specialist` against the shared
state dict, with ROE assertion + audit logging on every external tool call.

This is the substrate that the graph runner (:mod:`agent.langgraph_layer.graphs`)
calls per-node, regardless of whether the topology is driven by real LangGraph
or by the fallback :class:`MiniGraph`.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from agent.langgraph_layer.middleware import (
    engagement_context_middleware,
    opplan_middleware,
    run_with_fallback,
)
from agent.langgraph_layer.specialists import Specialist
from agent.langgraph_layer.tools import dispatch as tool_dispatch
from agent.langgraph_layer.tools import tool_specs
from llm.client import get_client
from log.audit import log_step
from security.roe import ROE, ROEViolation

log = logging.getLogger("swift.langgraph_layer.runtime")

# Hard limit on tool-use iterations per specialist to bound cost / runtime.
MAX_TURNS = 12


def _assert_roe_for_tool(tool_name: str, roe: ROE | None) -> None:
    """Translate tool name -> technique string and enforce ROE."""
    if roe is None:
        return
    technique = _TOOL_TO_TECHNIQUE.get(tool_name)
    if technique is None:
        return  # bookkeeping tools (classify/summarize/etc.) need no gate
    if technique not in roe.allowed_techniques:
        raise ROEViolation(
            f"langgraph specialist attempted tool '{tool_name}' "
            f"requiring technique '{technique}', not in ROE allow-list"
        )


_TOOL_TO_TECHNIQUE: dict[str, str] = {
    "kali_run": "kali",
    "probe_run": "probe",
    "tmux_send": "tmux_interactive",
    "osint_dns": "osint",
    "osint_shodan": "osint",
    "semgrep_run": "kali",
    "impacket_run": "ad_enum",
    "cme_run": "ad_enum",
    "cloud_probe": "cloud_recon",
    "slither_run": "web3_audit",
    "mythril_run": "web3_audit",
    "static_analyze": "probe",
    "write_doc": "engagement_planning",
    "ask_user": "engagement_planning",
    # kg_* are bookkeeping, no live network
    # delegate / classify / suggest_patch / summarize are bookkeeping
}


def run_specialist(spec: Specialist, state: dict[str, Any]) -> dict[str, Any]:
    """Run one Claude tool-use loop and return the updated state.

    ``state`` is mutated in place (findings, transcripts, knowledge-graph
    side-effects) and also returned so callers can use it as a value.
    """
    state = engagement_context_middleware(state)
    state = opplan_middleware(state)

    roe: ROE | None = state.get("roe")
    client = state.get("llm_client") or get_client()
    tools = tool_specs(spec.tool_names)

    system = spec.system_prompt
    if state.get("engagement_summary"):
        system += "\n\nEngagement:\n" + state["engagement_summary"]
    if state.get("opplan_summary"):
        system += "\n\n" + state["opplan_summary"]

    user_goal = state.get("goal") or "Execute your role for the active phase."
    messages: list[dict[str, Any]] = [{"role": "user", "content": user_goal}]

    transcript: list[dict[str, Any]] = state.setdefault("transcripts", {}).setdefault(spec.name, [])
    log_step("specialist.start", name=spec.name, phase=spec.phase)

    for turn in range(MAX_TURNS):
        resp = run_with_fallback(
            client,
            tier=spec.tier,
            messages=messages,
            system=system,
            tools=tools,
            max_tokens=4096,
        )

        content = getattr(resp, "content", []) or []
        # Append assistant message to running transcript
        transcript.append({"turn": turn, "content": _serialize_content(content)})

        tool_uses = [b for b in content if _block_type(b) == "tool_use"]
        if not tool_uses:
            # No tools requested => specialist is done.
            log_step("specialist.done", name=spec.name, turns=turn + 1)
            break

        # Echo assistant message back as required by Anthropic tool-use protocol
        messages.append({"role": "assistant", "content": _serialize_content(content)})

        tool_results: list[dict[str, Any]] = []
        for tu in tool_uses:
            tname = _block_attr(tu, "name")
            tinput = _block_attr(tu, "input") or {}
            tuid = _block_attr(tu, "id")

            # ROE gate per tool call
            try:
                _assert_roe_for_tool(tname, roe)
            except ROEViolation as exc:
                log_step("specialist.roe_deny", name=spec.name, tool=tname, reason=str(exc))
                tool_results.append({
                    "type": "tool_result", "tool_use_id": tuid,
                    "content": json.dumps({"error": "ROE deny", "reason": str(exc)}),
                    "is_error": True,
                })
                continue

            # If input arrived as JSON string (LiteLLM path), parse it
            if isinstance(tinput, str):
                try:
                    tinput = json.loads(tinput)
                except json.JSONDecodeError:
                    tinput = {"raw": tinput}

            result = tool_dispatch(tname, tinput, state)
            tool_results.append({
                "type": "tool_result", "tool_use_id": tuid,
                "content": json.dumps(result, default=str),
            })

        messages.append({"role": "user", "content": tool_results})
    else:
        log_step("specialist.max_turns", name=spec.name, max_turns=MAX_TURNS)

    return state


def _block_type(b: Any) -> str:
    if isinstance(b, dict):
        return b.get("type", "")
    return getattr(b, "type", "")


def _block_attr(b: Any, attr: str) -> Any:
    if isinstance(b, dict):
        return b.get(attr)
    return getattr(b, attr, None)


def _serialize_content(content: list[Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for b in content:
        t = _block_type(b)
        if t == "text":
            out.append({"type": "text", "text": _block_attr(b, "text") or ""})
        elif t == "tool_use":
            out.append({
                "type": "tool_use",
                "id": _block_attr(b, "id"),
                "name": _block_attr(b, "name"),
                "input": _block_attr(b, "input") or {},
            })
        else:
            out.append({"type": t, "raw": str(b)})
    return out
