"""Tool registry — one neutral schema + handler per tool.

Tools are defined once in a backend-neutral schema (``to_neutral_schema``) and
translated per-backend in llm.py. Handlers wrap the *real* SWIFTSEC callables and
catch every exception, so a malformed tool call can never crash the agent loop.

``build_registry`` takes the real callables discovered in the codebase:

* ``cve``     — a :class:`~swiftsec_ai.cve.CVEStore` (always present).
* ``roe``     — callable ``(target, technique="active_scan") -> dict`` or ``None``.
                When ``None``, ``scope_check`` returns an UNVERIFIED warning and
                active tools refuse to touch the target.
* ``recon``   — ``run_osint(target)`` (sync or async) or ``None``.
* ``scanner`` — ``scan_url(target)`` (sync) or ``None``.
* ``h1``      — ``(fields: dict) -> str`` markdown report formatter or ``None``.
"""
from __future__ import annotations

import asyncio
import inspect
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

Handler = Callable[[dict], str]


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict[str, Any]
    handler: Handler


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(
        self,
        name: str,
        description: str,
        parameters: dict[str, Any],
        handler: Handler,
    ) -> None:
        self._tools[name] = Tool(name, description, parameters, handler)

    def names(self) -> list[str]:
        return list(self._tools)

    def to_neutral_schema(self) -> list[dict[str, Any]]:
        return [
            {"name": t.name, "description": t.description, "parameters": t.parameters}
            for t in self._tools.values()
        ]

    def execute(self, name: str, args: dict[str, Any]) -> str:
        tool = self._tools.get(name)
        if tool is None:
            return f"[error] unknown tool: {name!r} (available: {', '.join(self.names())})"
        try:
            return tool.handler(args or {})
        except Exception as e:
            return f"[error] tool {name!r} failed: {e}"


# ----------------------------------------------------------------- helpers

def _run_maybe_async(fn: Callable, *args, **kwargs):
    """Call ``fn``; if it returns a coroutine (or is async), run it to completion."""
    if inspect.iscoroutinefunction(fn):
        return asyncio.run(fn(*args, **kwargs))
    result = fn(*args, **kwargs)
    if inspect.isawaitable(result):
        return asyncio.run(result)
    return result


def _summarize(obj: Any, limit: int = 4000) -> str:
    """Render an arbitrary tool result as compact text."""
    if obj is None:
        return "(no result)"
    if isinstance(obj, str):
        text = obj
    elif hasattr(obj, "to_dict"):
        try:
            text = json.dumps(obj.to_dict(), indent=2, default=str)
        except Exception:
            text = str(obj)
    elif isinstance(obj, (dict, list)):
        text = json.dumps(obj, indent=2, default=str)
    else:
        text = str(obj)
    return text if len(text) <= limit else text[: limit - 3] + "..."


# ----------------------------------------------------------------- registry

def build_registry(
    cve_store,
    roe: Callable[..., Any] | None = None,
    recon: Callable[..., Any] | None = None,
    scanner: Callable[..., Any] | None = None,
    h1: Callable[[dict], str] | None = None,
) -> ToolRegistry:
    reg = ToolRegistry()

    # --- cve_lookup ------------------------------------------------------
    def _cve_lookup(args: dict) -> str:
        query = str(args.get("query", "")).strip()
        if not query:
            return "[error] cve_lookup requires a 'query' string."
        limit = int(args.get("limit", 5) or 5)
        ctx = cve_store.retrieve_context(query, limit=limit)
        if not ctx:
            return (
                f"No CVEs in the local store match {query!r}. "
                "The store may be empty — run a sync first. Do NOT fabricate CVE IDs."
            )
        return ctx

    reg.register(
        "cve_lookup",
        "Search the local NVD/CVE mirror for vulnerabilities relevant to a "
        "technology, product, or keyword. KEV-flagged and high-CVSS CVEs first. "
        "Use this instead of recalling CVEs from memory.",
        {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "product / tech / keyword"},
                "limit": {"type": "integer", "description": "max results (default 5)"},
            },
            "required": ["query"],
        },
        _cve_lookup,
    )

    # --- scope_check -----------------------------------------------------
    def _scope_verdict(target: str, technique: str) -> dict | None:
        if roe is None:
            return None
        out = _run_maybe_async(roe, target, technique)
        if isinstance(out, dict):
            return out
        # Tolerate a bare bool / string verdict from a simpler roe callable.
        return {"in_scope": bool(out), "reason": str(out)}

    def _scope_check(args: dict) -> str:
        target = str(args.get("target", "")).strip()
        technique = str(args.get("technique", "active_scan")).strip() or "active_scan"
        if not target:
            return "[error] scope_check requires a 'target'."
        verdict = _scope_verdict(target, technique)
        if verdict is None:
            return (
                f"UNVERIFIED: no ROE/scope configured, cannot confirm {target!r} is "
                "authorized. Treat as OUT OF SCOPE — do not run active tools until an "
                "ROE is supplied."
            )
        in_scope = bool(verdict.get("in_scope"))
        reason = verdict.get("reason", "")
        tag = "IN SCOPE" if in_scope else "OUT OF SCOPE"
        return f"{tag}: target={target} technique={technique}. {reason}".strip()

    reg.register(
        "scope_check",
        "Verify a target is within authorized engagement scope (ROE). REQUIRED "
        "before any active reconnaissance, scanning, or exploitation.",
        {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "host or URL"},
                "technique": {
                    "type": "string",
                    "description": "e.g. osint, active_scan, exploit",
                },
            },
            "required": ["target"],
        },
        _scope_check,
    )

    # --- run_recon -------------------------------------------------------
    def _run_recon(args: dict) -> str:
        target = str(args.get("target", "")).strip()
        if not target:
            return "[error] run_recon requires a 'target'."
        verdict = _scope_verdict(target, "osint")
        if verdict is not None and not verdict.get("in_scope"):
            return f"REFUSED: {target} is out of scope. {verdict.get('reason', '')}".strip()
        prefix = ""
        if verdict is None:
            prefix = "[UNVERIFIED SCOPE — passive recon only] "
        if recon is None:
            return "[error] recon backend not wired in."
        result = _run_maybe_async(recon, target)
        return prefix + _summarize(result)

    reg.register(
        "run_recon",
        "Run passive/OSINT reconnaissance (DNS, subdomains, tech fingerprint, "
        "leaked artifacts) against an in-scope target.",
        {
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
        },
        _run_recon,
    )

    # --- run_scan --------------------------------------------------------
    def _run_scan(args: dict) -> str:
        target = str(args.get("target", "")).strip()
        if not target:
            return "[error] run_scan requires a 'target'."
        verdict = _scope_verdict(target, "active_scan")
        if verdict is None:
            return (
                f"REFUSED: cannot verify {target} is in scope (no ROE). Active scanning "
                "requires confirmed authorization — supply an ROE and retry."
            )
        if not verdict.get("in_scope"):
            return f"REFUSED: {target} is out of scope. {verdict.get('reason', '')}".strip()
        if scanner is None:
            return "[error] scanner backend not wired in."
        result = _run_maybe_async(scanner, target)
        return _summarize(result)

    reg.register(
        "run_scan",
        "Run an active web vulnerability scan against an in-scope target. Requires "
        "confirmed scope (will refuse otherwise).",
        {
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
        },
        _run_scan,
    )

    # --- draft_h1_report -------------------------------------------------
    def _draft_h1_report(args: dict) -> str:
        if h1 is None:
            return "[error] report formatter not wired in."
        fields = args.get("fields")
        if not isinstance(fields, dict):
            # Allow flat args too (title=, severity=, ...).
            fields = {k: v for k, v in args.items() if k != "fields"}
        if not fields:
            return "[error] draft_h1_report requires report 'fields'."
        report = h1(fields)
        return (
            f"{report}\n\n---\n"
            "[DRAFT ONLY — not submitted. Submission is a human decision.]"
        )

    reg.register(
        "draft_h1_report",
        "Render a HackerOne-style report (Title / Severity+CVSS / Summary / Steps / "
        "Impact / Remediation) from structured fields. DRAFTS ONLY — never submits.",
        {
            "type": "object",
            "properties": {
                "fields": {
                    "type": "object",
                    "description": (
                        "report fields: title, target_url, bug_class, severity, cwe, "
                        "cvss, summary, steps, impact_summary, remediation"
                    ),
                }
            },
            "required": ["fields"],
        },
        _draft_h1_report,
    )

    return reg
