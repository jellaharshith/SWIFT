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
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .guardrail import PROMPT_INJECTION_PATTERNS, SENSITIVE_OUTPUT_PATTERNS

Handler = Callable[[dict], str]


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict[str, Any]
    handler: Handler


class MCPValidator:
    """Security gateway for every tool invocation: schema, credential, injection,
    and scope checks before dispatch; sensitive-data masking after.

    ``scope_targets`` is an optional ``set[str]`` of in-scope hosts/targets — when
    given, args named ``target``/``url``/``host`` are checked against it for tools
    whose name suggests network activity (``run_recon``, ``run_scan``, anything not
    ``cve_lookup``/``scope_check``/``draft_h1_report``).
    """

    _NETWORK_TOOL_PREFIXES = ("run_", "ai_asm", "redteam")
    _CREDENTIAL_RE = re.compile(
        r"\b(?:password|passwd|secret|api[_\-]?key|token|bearer)\s*[:=]\s*\S+",
        re.IGNORECASE,
    )

    def __init__(self, scope_targets: set[str] | None = None) -> None:
        self.scope_targets = scope_targets
        self._injection_re = [re.compile(p, re.IGNORECASE) for p in PROMPT_INJECTION_PATTERNS]
        self._sensitive_re = [re.compile(p, re.IGNORECASE) for p in SENSITIVE_OUTPUT_PATTERNS]

    def validate_tool_call(self, tool_name: str, args: dict, schema: dict) -> dict:
        if not isinstance(args, dict):
            return {"valid": False, "reason": f"args for {tool_name!r} must be an object"}

        required = schema.get("required", []) if isinstance(schema, dict) else []
        missing = [k for k in required if k not in args]
        if missing:
            return {"valid": False, "reason": f"missing required args: {missing}"}

        for key, val in args.items():
            if isinstance(val, str) and self._CREDENTIAL_RE.search(val):
                return {"valid": False, "reason": f"credential-shaped value in arg {key!r}"}
            if isinstance(val, str):
                for pattern in self._injection_re:
                    if pattern.search(val):
                        return {
                            "valid": False,
                            "reason": f"prompt-injection pattern in arg {key!r}: {pattern.pattern}",
                        }

        if self.scope_targets is not None and tool_name.startswith(self._NETWORK_TOOL_PREFIXES):
            target = str(args.get("target") or args.get("url") or args.get("host") or "")
            if target and target not in self.scope_targets:
                return {"valid": False, "reason": f"{target!r} not in scope.yaml"}

        return {"valid": True, "reason": ""}

    def validate_tool_output(self, tool_name: str, output: str) -> dict:
        text = output or ""
        flags: list[str] = []
        masked = text
        for pattern in self._sensitive_re:
            if pattern.search(masked):
                flags.append(pattern.pattern)
                masked = pattern.sub("[REDACTED]", masked)
        return {"clean": not flags, "output": masked, "flags": flags}


class ToolRegistry:
    def __init__(self, validator: MCPValidator | None = None) -> None:
        self._tools: dict[str, Tool] = {}
        self.validator = validator or MCPValidator()

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

        gate = self.validator.validate_tool_call(name, args or {}, tool.parameters)
        if not gate["valid"]:
            return f"[error] tool {name!r} blocked by MCPValidator: {gate['reason']}"

        try:
            result = tool.handler(args or {})
        except Exception as e:
            return f"[error] tool {name!r} failed: {e}"

        scan = self.validator.validate_tool_output(name, result)
        return scan["output"]


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
    validator: MCPValidator | None = None,
) -> ToolRegistry:
    reg = ToolRegistry(validator=validator)

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

    # --- ai_asm ------------------------------------------------------------
    def _ai_asm(args: dict) -> str:
        target = str(args.get("target", "")).strip()
        if not target:
            return "[error] ai_asm requires a 'target'."
        verdict = _scope_verdict(target, "active_scan")
        if verdict is None:
            return (
                f"REFUSED: cannot verify {target!r} is in scope (no ROE). AI ASM "
                "performs light-active probes — supply an ROE and retry."
            )
        if not verdict.get("in_scope"):
            return f"REFUSED: {target} is out of scope. {verdict.get('reason', '')}".strip()
        from .ai_asm import run_ai_asm
        return _summarize(run_ai_asm(target))

    reg.register(
        "ai_asm",
        "Run the AI Attack Surface Mapper against an in-scope target: discover "
        "LLM endpoints, inference servers, vector DBs, MCP servers, and leaked AI "
        "API keys. Run this BEFORE standard recon on any target with AI features.",
        {
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
        },
        _ai_asm,
    )

    # --- redteam -------------------------------------------------------------
    def _redteam(args: dict) -> str:
        endpoint = str(args.get("endpoint", "")).strip()
        if not endpoint:
            return "[error] redteam requires an 'endpoint'."
        verdict = _scope_verdict(endpoint, "exploit")
        if verdict is None or not verdict.get("in_scope"):
            return (
                f"REFUSED: {endpoint!r} must be confirmed in scope (technique=exploit) "
                "before red teaming. Run scope_check first."
            )
        if not bool(args.get("confirmed")):
            return (
                "REFUSED: redteam requires confirmed=true — operator must explicitly "
                "opt in to sending attack payloads to this endpoint."
            )
        from .redteam import AIRedTeamer
        category = str(args.get("category", "all"))
        result = AIRedTeamer().run(endpoint, category=category, confirmed=True)
        return _summarize(result)

    reg.register(
        "redteam",
        "Send crafted prompt-injection / jailbreak / data-exfil attack payloads to "
        "an in-scope, operator-confirmed LLM endpoint and score responses for "
        "compromise. Requires confirmed=true.",
        {
            "type": "object",
            "properties": {
                "endpoint": {"type": "string"},
                "category": {
                    "type": "string",
                    "description": "prompt_injection|jailbreak|data_exfil|indirect_injection|model_dos|hallucination_abuse|all",
                },
                "confirmed": {"type": "boolean"},
            },
            "required": ["endpoint", "confirmed"],
        },
        _redteam,
    )

    return reg
