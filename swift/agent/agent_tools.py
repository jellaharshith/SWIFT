"""Anthropic tool_use schemas and dispatcher for the agentic red-team loop."""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .redteam_agent import RedTeamAgent

# ── Tool schemas (Anthropic tool_use format) ─────────────────────────────────

TOOL_SCHEMAS = [
    {
        "name": "run_probe",
        "description": (
            "Execute a security probe against the target. Returns a list of findings "
            "or empty list. Each probe call costs budget."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "probe_name": {
                    "type": "string",
                    "enum": [
                        "ssrf", "oob_ssrf", "sqli", "xss", "oauth", "websocket",
                        "idor", "graphql", "race_condition", "bizlogic", "jwt", "api_key",
                        "cloud_aws", "supply_chain", "credential_check",
                        "mobile_static", "active_directory", "network_service",
                    ],
                    "description": "Name of the probe to run",
                },
                "target": {
                    "type": "string",
                    "description": "Target URL to probe",
                },
                "params": {
                    "type": "object",
                    "description": "Additional probe parameters (optional)",
                },
            },
            "required": ["probe_name", "target"],
        },
    },
    {
        "name": "get_findings",
        "description": "Retrieve findings collected so far, optionally filtered.",
        "input_schema": {
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                    "description": "Filter by severity (optional)",
                },
                "confirmed_only": {
                    "type": "boolean",
                    "description": "Only return OOB-confirmed findings",
                },
            },
        },
    },
    {
        "name": "get_attack_surface",
        "description": "Retrieve OSINT and recon data already collected about the target.",
        "input_schema": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "enum": ["endpoints", "technologies", "credentials", "open_ports", "github_leaks"],
                    "description": "Category of attack surface data to retrieve",
                },
            },
            "required": ["category"],
        },
    },
    {
        "name": "update_hypothesis",
        "description": "Log an attack hypothesis and reasoning to the audit trail.",
        "input_schema": {
            "type": "object",
            "properties": {
                "hypothesis": {"type": "string", "description": "Attack hypothesis text"},
                "confidence": {
                    "type": "number",
                    "description": "Confidence 0.0-1.0",
                },
                "evidence": {"type": "string", "description": "Evidence supporting hypothesis"},
            },
            "required": ["hypothesis", "confidence", "evidence"],
        },
    },
    {
        "name": "mark_exhausted",
        "description": "Mark an attack vector as exhausted to prevent infinite loops.",
        "input_schema": {
            "type": "object",
            "properties": {
                "attack_vector": {"type": "string", "description": "Vector identifier"},
                "reason": {"type": "string", "description": "Why this vector is exhausted"},
            },
            "required": ["attack_vector", "reason"],
        },
    },
]


async def dispatch_tool(
    tool_name: str, tool_input: dict[str, Any], agent: RedTeamAgent
) -> Any:
    """Dispatch a tool call from the agent loop to the appropriate handler."""
    if tool_name == "run_probe":
        return await _run_probe(tool_input, agent)
    elif tool_name == "get_findings":
        return _get_findings(tool_input, agent)
    elif tool_name == "get_attack_surface":
        return _get_attack_surface(tool_input, agent)
    elif tool_name == "update_hypothesis":
        return _update_hypothesis(tool_input, agent)
    elif tool_name == "mark_exhausted":
        return _mark_exhausted(tool_input, agent)
    else:
        return {"error": f"Unknown tool: {tool_name}"}


def _target_in_scope(requested: str, authorized: str) -> bool:
    """Prevent prompt-injected Sonnet from redirecting probes off-scope."""
    from urllib.parse import urlparse
    try:
        req_host = urlparse(requested).netloc.lower().split(":")[0]
        auth_host = urlparse(authorized).netloc.lower().split(":")[0]
        # Allow exact match or subdomain of authorized host
        return req_host == auth_host or req_host.endswith("." + auth_host)
    except Exception:
        return False


async def _run_probe(inp: dict, agent: RedTeamAgent) -> list:
    probe_name = inp.get("probe_name", "")
    target = inp.get("target", "")
    agent.budget.probe_calls_used += 1

    if not _target_in_scope(target, agent.target):
        return {"error": f"Target '{target}' outside authorized scope '{agent.target}'. Probe blocked."}

    try:
        from sdk.registry import PluginRegistry
        reg = PluginRegistry()
        reg.discover()
        module = reg.get(probe_name)
        findings = await module.probe(target, None, agent.roe)
        serialized = []
        for f in findings:
            serialized.append({
                "id": f.id,
                "module": f.module,
                "vuln_type": f.vuln_type.value,
                "severity": f.severity.value,
                "title": f.title,
                "confidence": f.confidence,
                "oob_confirmed": f.oob_confirmed,
                "target_url": f.target_url,
            })
        agent.findings_store.extend(findings)
        return serialized
    except Exception as exc:
        return {"error": str(exc)}


def _get_findings(inp: dict, agent: RedTeamAgent) -> list:
    findings = agent.findings_store
    severity_filter = inp.get("severity")
    confirmed_only = inp.get("confirmed_only", False)
    if severity_filter:
        findings = [f for f in findings if f.severity.value == severity_filter]
    if confirmed_only:
        findings = [f for f in findings if f.oob_confirmed]
    return [{"id": f.id, "vuln_type": f.vuln_type.value, "severity": f.severity.value,
             "title": f.title, "confidence": f.confidence} for f in findings]


def _get_attack_surface(inp: dict, agent: RedTeamAgent) -> dict:
    category = inp.get("category", "endpoints")
    surface = getattr(agent, "attack_surface", {})
    return surface.get(category, {})


def _update_hypothesis(inp: dict, agent: RedTeamAgent) -> dict:
    from .agent_prompts import AgentHypothesis
    h = AgentHypothesis(
        text=inp["hypothesis"],
        confidence=inp["confidence"],
        evidence=inp["evidence"],
    )
    agent.hypotheses.append(h)
    return {"logged": True, "hypothesis_count": len(agent.hypotheses)}


def _mark_exhausted(inp: dict, agent: RedTeamAgent) -> dict:
    vector = inp.get("attack_vector", "")
    agent.exhausted_vectors.add(vector)
    return {"exhausted": vector}
