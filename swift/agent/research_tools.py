"""Anthropic tool_use schemas + dispatcher for the `swiftsec research` agent.

Tools deliberately scope-limited to PUBLIC surface:
  - fetch_url:   only whitelisted vendor/research hosts
  - search_github / read_github_file: public repos only
  - query_cve:   NVD REST API
  - note_hypothesis: in-memory ledger
  - run_sandbox_test: hardcoded whitelist of documented-behavior scenarios
  - mark_done:   exit loop with verdict

No tool can decompile, exploit, or generate live traffic to the target.
"""
from __future__ import annotations

import json
import subprocess
import urllib.parse
import urllib.request
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .research_agent import ResearchAgent


# Whitelist of hosts fetch_url may contact. Keeps the agent on PUBLIC,
# vendor-authoritative or research-authoritative sources only.
_ALLOWED_FETCH_HOSTS: frozenset[str] = frozenset({
    "portswigger.net", "www.portswigger.net",
    "hackerone.com", "www.hackerone.com", "docs.hackerone.com",
    "nvd.nist.gov", "services.nvd.nist.gov",
    "cve.mitre.org", "www.cve.org",
    "github.com", "raw.githubusercontent.com", "api.github.com",
    "owasp.org", "cheatsheetseries.owasp.org",
    "cwe.mitre.org",
    "research.checkpoint.com", "googleprojectzero.blogspot.com",
})


# Whitelist of scenario IDs run_sandbox_test will accept. Adding scenarios
# here is a code change — Claude cannot invent new scenarios.
_SANDBOX_SCENARIOS: frozenset[str] = frozenset({
    "burp_project_file_minimal",       # generate minimal .burp file, check parser behavior
    "burp_project_file_malformed_length",  # length-prefix corruption
    "collaborator_protocol_dns_format",    # parse documented DNS-tunneled message format
    "extender_api_signature_check",        # diff public BApp SDK headers vs documented spec
})


TOOL_SCHEMAS = [
    {
        "name": "get_focus",
        "description": "Retrieve the current research focus (target + focus areas + budget).",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "fetch_url",
        "description": (
            "Fetch HTML/text from a PUBLIC documentation or research URL and return the "
            "first 8KB of its text content. Hosts are whitelisted — see error message "
            "if rejected. Never contacts the target product or its operator's "
            "auth/login surface."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full https URL"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "search_github",
        "description": "Search public GitHub repos via `gh search repos`. Returns top 10 hits.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "read_github_file",
        "description": "Read a file from a public GitHub repo via the GitHub API.",
        "input_schema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string", "description": "owner/repo"},
                "path": {"type": "string", "description": "file path"},
                "ref": {"type": "string", "description": "branch/tag (optional, default main)"},
            },
            "required": ["repo", "path"],
        },
    },
    {
        "name": "query_cve",
        "description": "Query NVD for CVEs matching a keyword. Returns top 10.",
        "input_schema": {
            "type": "object",
            "properties": {
                "keyword": {"type": "string", "description": "Search keyword (e.g. 'Burp Suite')"},
            },
            "required": ["keyword"],
        },
    },
    {
        "name": "note_hypothesis",
        "description": "Add a hypothesis to the research ledger. Must include evidence URLs.",
        "input_schema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Hypothesis text"},
                "confidence": {"type": "number", "description": "0.0-1.0"},
                "evidence_urls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Citing URLs (must be non-empty)",
                },
                "category": {
                    "type": "string",
                    "description": "Vulnerability class (e.g. 'parser_crash', 'auth_bypass')",
                },
            },
            "required": ["text", "confidence", "evidence_urls"],
        },
    },
    {
        "name": "run_sandbox_test",
        "description": (
            "Execute a hardcoded sandbox scenario. ONLY whitelisted scenario_ids are "
            "permitted. Anything else returns 'scenario not whitelisted' — there is no "
            "way to invent new scenarios from this tool."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "scenario_id": {"type": "string", "description": "Whitelisted scenario id"},
                "params": {"type": "object", "description": "Scenario-specific params"},
            },
            "required": ["scenario_id"],
        },
    },
    {
        "name": "mark_done",
        "description": "End the research session with a verdict.",
        "input_schema": {
            "type": "object",
            "properties": {
                "verdict": {
                    "type": "string",
                    "enum": ["worth_pursuing", "not_promising", "blocked_by_eula"],
                },
                "summary": {"type": "string"},
            },
            "required": ["verdict", "summary"],
        },
    },
]


# ── Tool implementations ─────────────────────────────────────────────────────


def _get_focus(_inp: dict, agent: "ResearchAgent") -> dict:
    return {
        "target": agent.target,
        "focus": agent.focus,
        "max_iterations": agent.max_iterations,
        "iterations_remaining": agent.max_iterations - agent.iteration,
    }


def _fetch_url(inp: dict, agent: "ResearchAgent") -> dict:
    url = inp.get("url", "")
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as exc:
        return {"error": f"invalid url: {exc}"}
    host = (parsed.hostname or "").lower()
    if host not in _ALLOWED_FETCH_HOSTS:
        return {
            "error": "host not whitelisted",
            "host": host,
            "allowed": sorted(_ALLOWED_FETCH_HOSTS),
        }
    if parsed.scheme != "https":
        return {"error": "only https permitted"}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "swiftsec-research/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
            data = resp.read(16384).decode("utf-8", errors="replace")
    except Exception as exc:
        return {"error": str(exc), "url": url}
    return {"url": url, "host": host, "content_truncated": data[:8192]}


def _search_github(inp: dict, _agent: "ResearchAgent") -> dict:
    query = inp.get("query", "")
    if not query:
        return {"error": "query required"}
    try:
        out = subprocess.run(
            ["gh", "search", "repos", query, "--limit", "10", "--json",
             "fullName,description,stargazersCount,url"],
            capture_output=True, text=True, timeout=30, check=False,
        )
    except FileNotFoundError:
        return {"error": "gh CLI not installed"}
    if out.returncode != 0:
        return {"error": out.stderr.strip() or "gh search failed"}
    try:
        return {"results": json.loads(out.stdout or "[]")}
    except Exception:
        return {"results": [], "raw": out.stdout[:2000]}


def _read_github_file(inp: dict, _agent: "ResearchAgent") -> dict:
    repo = inp.get("repo", "")
    path = inp.get("path", "")
    ref = inp.get("ref", "")
    if "/" not in repo or not path:
        return {"error": "repo (owner/name) and path required"}
    api_path = f"repos/{repo}/contents/{path}"
    cmd = ["gh", "api", api_path, "-H", "Accept: application/vnd.github.raw"]
    if ref:
        cmd += ["-X", "GET", "-F", f"ref={ref}"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=20, check=False)
    except FileNotFoundError:
        return {"error": "gh CLI not installed"}
    if out.returncode != 0:
        return {"error": out.stderr.strip() or "gh api failed"}
    return {"repo": repo, "path": path, "content_truncated": out.stdout[:8192]}


def _query_cve(inp: dict, _agent: "ResearchAgent") -> dict:
    keyword = inp.get("keyword", "")
    if not keyword:
        return {"error": "keyword required"}
    qs = urllib.parse.urlencode({"keywordSearch": keyword, "resultsPerPage": 10})
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{qs}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "swiftsec-research/1.0"})
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        return {"error": str(exc)}
    cves = []
    for item in data.get("vulnerabilities", [])[:10]:
        cve = item.get("cve", {})
        cves.append({
            "id": cve.get("id"),
            "published": cve.get("published"),
            "descriptions": [d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"][:1],
        })
    return {"keyword": keyword, "cves": cves}


def _note_hypothesis(inp: dict, agent: "ResearchAgent") -> dict:
    text = inp.get("text", "").strip()
    confidence = float(inp.get("confidence", 0.0))
    evidence_urls = inp.get("evidence_urls") or []
    category = inp.get("category", "uncategorized")
    if not text:
        return {"error": "text required"}
    if not isinstance(evidence_urls, list) or len(evidence_urls) == 0:
        return {"error": "at least one evidence_url required"}
    entry = {
        "text": text,
        "confidence": confidence,
        "evidence_urls": list(evidence_urls),
        "category": category,
    }
    agent.hypotheses.append(entry)
    return {"recorded": True, "total_hypotheses": len(agent.hypotheses)}


def _run_sandbox_test(inp: dict, _agent: "ResearchAgent") -> dict:
    scenario_id = inp.get("scenario_id", "")
    if scenario_id not in _SANDBOX_SCENARIOS:
        return {
            "error": "scenario not whitelisted",
            "scenario_id": scenario_id,
            "whitelisted": sorted(_SANDBOX_SCENARIOS),
        }
    # Stub: scenarios are designed but not yet implemented — they live as
    # documented test plans rather than executable code. The agent learns from
    # this output that the scenario exists and what it would prove.
    return {
        "scenario_id": scenario_id,
        "status": "stub",
        "note": (
            "Scenario is whitelisted but not yet implemented. Treat as a "
            "follow-up action item for the manual playbook."
        ),
    }


def _mark_done(inp: dict, agent: "ResearchAgent") -> dict:
    agent.done = True
    agent.verdict = inp.get("verdict", "unknown")
    agent.summary = inp.get("summary", "")
    return {"acknowledged": True}


# ── Dispatcher ───────────────────────────────────────────────────────────────

_DISPATCH = {
    "get_focus": _get_focus,
    "fetch_url": _fetch_url,
    "search_github": _search_github,
    "read_github_file": _read_github_file,
    "query_cve": _query_cve,
    "note_hypothesis": _note_hypothesis,
    "run_sandbox_test": _run_sandbox_test,
    "mark_done": _mark_done,
}


def dispatch_tool(tool_name: str, tool_input: dict[str, Any], agent: "ResearchAgent") -> Any:
    fn = _DISPATCH.get(tool_name)
    if fn is None:
        return {"error": f"unknown tool: {tool_name}"}
    try:
        return fn(tool_input, agent)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"tool {tool_name} crashed: {exc}"}
