"""Tool wrappers exposed to LangGraph specialist agents.

Each entry in :data:`TOOL_REGISTRY` is the JSON-schema Anthropic tool-use
declaration plus a Python callable. The callable receives the parsed tool
input dict + the shared :class:`agent.langgraph_layer.graphs.State` and
returns a JSON-serializable result.

All tool calls go through the SWIFT ROE gate + audit log; see
:func:`_invoke` in :mod:`agent.langgraph_layer.runtime`.
"""
from __future__ import annotations

import json
from typing import Any, Callable

from graph import open_kg
from log.audit import log_step

# Each tool: (json_schema, python_impl)
ToolImpl = Callable[[dict[str, Any], dict[str, Any]], Any]
ToolEntry = tuple[dict[str, Any], ToolImpl]


def _kg_add_host(args: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    kg = open_kg()
    nid = kg.add_host(args["host"], **(args.get("attrs") or {}))
    log_step("kg.add_host", host=args["host"], node_id=nid)
    return {"node_id": nid}


def _kg_add_service(args: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    kg = open_kg()
    nid = kg.add_service(args["host_id"], int(args["port"]), args["service"], **(args.get("attrs") or {}))
    log_step("kg.add_service", host_id=args["host_id"], port=args["port"], service=args["service"], node_id=nid)
    return {"node_id": nid}


def _kg_add_vuln(args: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    kg = open_kg()
    finding = args.get("finding") or {}
    nid = kg.add_vuln(args["target_id"], args.get("cve"), finding)
    state.setdefault("findings", []).append({"node_id": nid, **finding})
    log_step("kg.add_vuln", target_id=args["target_id"], cve=args.get("cve"))
    return {"node_id": nid}


def _kg_add_credential(args: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    kg = open_kg()
    nid = kg.add_credential(args["target_id"], args["username"], **(args.get("attrs") or {}))
    log_step("kg.add_credential", target_id=args["target_id"], username=args["username"])
    return {"node_id": nid}


def _kg_add_edge(args: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    kg = open_kg()
    kg.add_edge(args["src"], args["dst"], args["relation"], **(args.get("attrs") or {}))
    log_step("kg.add_edge", src=args["src"], dst=args["dst"], relation=args["relation"])
    return {"ok": True}


def _kg_query(args: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    kg = open_kg()
    fmt = args.get("format", "json")
    return {"export": kg.export(fmt)}


def _kali_run(args: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    """Delegate to existing :class:`kali.runner.KaliRunner` if present."""
    try:
        from kali.runner import KaliRunner  # type: ignore
    except Exception as e:
        return {"error": f"kali.runner unavailable: {e}"}
    r = KaliRunner()
    tool = args["tool"]
    cmd_args = args.get("args") or []
    log_step("kali.run", tool=tool, args=cmd_args)
    try:
        out = r.run(tool, cmd_args)  # type: ignore[attr-defined]
    except AttributeError:
        # KaliRunner may expose .execute() or another method depending on version
        out = getattr(r, "execute", lambda *a, **kw: {"error": "no runner method"})(tool, cmd_args)
    return {"output": out if isinstance(out, (dict, str)) else str(out)}


def _probe_run(args: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    """Dispatch to a registered :class:`probes.base.Probe`."""
    probe_name = args["probe"]
    target = args["target"]
    try:
        from probes.base import load_probe  # type: ignore
    except Exception:
        load_probe = None  # type: ignore
    if load_probe is None:
        return {"error": "probes.base.load_probe not available"}
    log_step("probe.run", probe=probe_name, target=target)
    probe = load_probe(probe_name)
    return {"output": probe.run(target, **(args.get("kwargs") or {}))}


def _tmux_send(args: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    from sandbox.tmux_session import TmuxSession
    sess = TmuxSession(args["session"])
    res = sess.send(args["command"], timeout=args.get("timeout"), expect=args.get("expect"))
    log_step("tmux.send", session=args["session"], stalled=res.stalled, background=res.background)
    return {
        "output": res.output,
        "completed": res.completed,
        "stalled": res.stalled,
        "background": res.background,
        "elapsed": res.elapsed,
    }


def _osint_dns(args: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    try:
        from osint import dns_recon  # type: ignore
    except Exception as e:
        return {"error": f"osint.dns_recon unavailable: {e}"}
    log_step("osint.dns", domain=args["domain"])
    return {"output": dns_recon.lookup(args["domain"])}


def _osint_shodan(args: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    try:
        from osint import shodan as sho  # type: ignore
    except Exception as e:
        return {"error": f"osint.shodan unavailable: {e}"}
    log_step("osint.shodan", query=args["query"])
    return {"output": sho.search(args["query"])}


def _classify(args: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    """Stub: detector calls this with finding+confidence; we trust caller."""
    return {"label": args.get("label", "needs-verification")}


def _suggest_patch(args: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    """Stub: returns the agent's diff verbatim so the orchestrator surfaces it."""
    return {"diff": args.get("diff", "")}


def _summarize(args: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    return {"summary": args.get("summary", "")}


def _ask_user(args: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    """In CLI mode this prompts on stdin; in non-interactive runs it returns
    the pre-staged answer from ``state['answers']`` keyed by question."""
    q = args["question"]
    answers = state.get("answers") or {}
    if q in answers:
        return {"answer": answers[q]}
    try:
        ans = input(f"[soundwave] {q}\n> ")
    except EOFError:
        ans = ""
    return {"answer": ans}


def _write_doc(args: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    from pathlib import Path
    p = Path(args["path"])
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(args["content"], encoding="utf-8")
    log_step("engagement.write_doc", path=str(p), bytes=len(args["content"]))
    return {"path": str(p)}


def _delegate(args: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    """Orchestrator -> specialist hop. Looked up in runtime."""
    return {"delegated_to": args.get("specialist"), "input": args.get("input")}


def _semgrep_run(args: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    try:
        from kali import semgrep_rules_sync as srs  # type: ignore
    except Exception as e:
        return {"error": f"semgrep wrapper unavailable: {e}"}
    log_step("kali.semgrep", target=args["target"])
    return {"output": srs.scan(args["target"], rules=args.get("rules"))}


def _impacket_run(args: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    try:
        from kali import impacket_runner as ir  # type: ignore
    except Exception as e:
        return {"error": f"impacket wrapper unavailable: {e}"}
    log_step("kali.impacket", op=args["op"])
    return {"output": ir.run(args["op"], args.get("args") or [])}


def _cme_run(args: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    try:
        from kali import crackmapexec_runner as cme  # type: ignore
    except Exception as e:
        return {"error": f"crackmapexec wrapper unavailable: {e}"}
    log_step("kali.cme", proto=args["protocol"])
    return {"output": cme.run(args["protocol"], args.get("args") or [])}


def _cloud_probe(args: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    try:
        from probes import cloud_aws  # type: ignore
    except Exception as e:
        return {"error": f"cloud probe unavailable: {e}"}
    log_step("probe.cloud_aws", target=args["target"])
    return {"output": cloud_aws.probe(args["target"])}


def _slither_run(args: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    from bounty.web3 import slither as sl
    log_step("web3.slither", target=args["target"])
    return {"output": sl.analyze(args["target"])}


def _mythril_run(args: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    from bounty.web3 import mythril as my
    log_step("web3.mythril", target=args["target"])
    return {"output": my.analyze(args["target"])}


def _static_analyze(args: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    try:
        from probes import mobile_static  # type: ignore
    except Exception as e:
        return {"error": f"mobile_static unavailable: {e}"}
    log_step("probe.static", target=args["target"])
    return {"output": mobile_static.scan(args["target"])}


TOOL_REGISTRY: dict[str, ToolEntry] = {
    "kg_add_host": (
        {"name": "kg_add_host",
         "description": "Add a host node to the attack knowledge graph.",
         "input_schema": {"type": "object", "properties": {
             "host": {"type": "string"},
             "attrs": {"type": "object"},
         }, "required": ["host"]}},
        _kg_add_host,
    ),
    "kg_add_service": (
        {"name": "kg_add_service",
         "description": "Add a service exposure under a host.",
         "input_schema": {"type": "object", "properties": {
             "host_id": {"type": "string"}, "port": {"type": "integer"},
             "service": {"type": "string"}, "attrs": {"type": "object"},
         }, "required": ["host_id", "port", "service"]}},
        _kg_add_service,
    ),
    "kg_add_vuln": (
        {"name": "kg_add_vuln",
         "description": "Record a vulnerability finding bound to a target.",
         "input_schema": {"type": "object", "properties": {
             "target_id": {"type": "string"}, "cve": {"type": ["string", "null"]},
             "finding": {"type": "object"},
         }, "required": ["target_id", "finding"]}},
        _kg_add_vuln,
    ),
    "kg_add_credential": (
        {"name": "kg_add_credential",
         "description": "Record a credential captured from a target.",
         "input_schema": {"type": "object", "properties": {
             "target_id": {"type": "string"}, "username": {"type": "string"},
             "attrs": {"type": "object"},
         }, "required": ["target_id", "username"]}},
        _kg_add_credential,
    ),
    "kg_add_edge": (
        {"name": "kg_add_edge",
         "description": "Add a typed edge between two graph nodes.",
         "input_schema": {"type": "object", "properties": {
             "src": {"type": "string"}, "dst": {"type": "string"},
             "relation": {"type": "string"}, "attrs": {"type": "object"},
         }, "required": ["src", "dst", "relation"]}},
        _kg_add_edge,
    ),
    "kg_query": (
        {"name": "kg_query",
         "description": "Export the knowledge graph in json/cypher/graphml.",
         "input_schema": {"type": "object", "properties": {
             "format": {"type": "string", "enum": ["json", "cypher", "graphml"]},
         }}},
        _kg_query,
    ),
    "kali_run": (
        {"name": "kali_run",
         "description": "Run an authorized Kali tool via the existing KaliRunner.",
         "input_schema": {"type": "object", "properties": {
             "tool": {"type": "string"}, "args": {"type": "array", "items": {"type": "string"}},
         }, "required": ["tool"]}},
        _kali_run,
    ),
    "probe_run": (
        {"name": "probe_run",
         "description": "Invoke a registered SWIFT Probe by name.",
         "input_schema": {"type": "object", "properties": {
             "probe": {"type": "string"}, "target": {"type": "string"}, "kwargs": {"type": "object"},
         }, "required": ["probe", "target"]}},
        _probe_run,
    ),
    "tmux_send": (
        {"name": "tmux_send",
         "description": "Send a command to an interactive tmux session (msfconsole, sliver, evil-winrm).",
         "input_schema": {"type": "object", "properties": {
             "session": {"type": "string"}, "command": {"type": "string"},
             "timeout": {"type": "number"}, "expect": {"type": "string"},
         }, "required": ["session", "command"]}},
        _tmux_send,
    ),
    "osint_dns": (
        {"name": "osint_dns",
         "description": "DNS reconnaissance via osint.dns_recon.",
         "input_schema": {"type": "object", "properties": {
             "domain": {"type": "string"},
         }, "required": ["domain"]}},
        _osint_dns,
    ),
    "osint_shodan": (
        {"name": "osint_shodan",
         "description": "Shodan search.",
         "input_schema": {"type": "object", "properties": {
             "query": {"type": "string"},
         }, "required": ["query"]}},
        _osint_shodan,
    ),
    "classify": (
        {"name": "classify", "description": "Label a finding (TP/FP/needs-verification).",
         "input_schema": {"type": "object", "properties": {"label": {"type": "string"}}, "required": ["label"]}},
        _classify,
    ),
    "suggest_patch": (
        {"name": "suggest_patch", "description": "Return a unified-diff patch suggestion.",
         "input_schema": {"type": "object", "properties": {"diff": {"type": "string"}}, "required": ["diff"]}},
        _suggest_patch,
    ),
    "summarize": (
        {"name": "summarize", "description": "Persist an analyst summary.",
         "input_schema": {"type": "object", "properties": {"summary": {"type": "string"}}, "required": ["summary"]}},
        _summarize,
    ),
    "ask_user": (
        {"name": "ask_user", "description": "Ask the operator an engagement-planning question.",
         "input_schema": {"type": "object", "properties": {"question": {"type": "string"}}, "required": ["question"]}},
        _ask_user,
    ),
    "write_doc": (
        {"name": "write_doc", "description": "Write an engagement document (RoE.yaml, OPPLAN.md, ConOps.md).",
         "input_schema": {"type": "object", "properties": {
             "path": {"type": "string"}, "content": {"type": "string"},
         }, "required": ["path", "content"]}},
        _write_doc,
    ),
    "delegate": (
        {"name": "delegate", "description": "Delegate work to a specialist sub-agent by name.",
         "input_schema": {"type": "object", "properties": {
             "specialist": {"type": "string"}, "input": {"type": "object"},
         }, "required": ["specialist"]}},
        _delegate,
    ),
    "semgrep_run": (
        {"name": "semgrep_run", "description": "Run semgrep over a target source tree.",
         "input_schema": {"type": "object", "properties": {
             "target": {"type": "string"}, "rules": {"type": "string"},
         }, "required": ["target"]}},
        _semgrep_run,
    ),
    "impacket_run": (
        {"name": "impacket_run", "description": "Run an Impacket operation (kerberoast, gpp, etc.).",
         "input_schema": {"type": "object", "properties": {
             "op": {"type": "string"}, "args": {"type": "array", "items": {"type": "string"}},
         }, "required": ["op"]}},
        _impacket_run,
    ),
    "cme_run": (
        {"name": "cme_run", "description": "Run CrackMapExec by protocol.",
         "input_schema": {"type": "object", "properties": {
             "protocol": {"type": "string"}, "args": {"type": "array", "items": {"type": "string"}},
         }, "required": ["protocol"]}},
        _cme_run,
    ),
    "cloud_probe": (
        {"name": "cloud_probe", "description": "Run the cloud AWS probe (IMDS SSRF, etc.).",
         "input_schema": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]}},
        _cloud_probe,
    ),
    "slither_run": (
        {"name": "slither_run", "description": "Slither static analysis for Solidity.",
         "input_schema": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]}},
        _slither_run,
    ),
    "mythril_run": (
        {"name": "mythril_run", "description": "Mythril symbolic execution for EVM bytecode.",
         "input_schema": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]}},
        _mythril_run,
    ),
    "static_analyze": (
        {"name": "static_analyze", "description": "Mobile / binary static analysis.",
         "input_schema": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]}},
        _static_analyze,
    ),
}


def tool_specs(names: tuple[str, ...]) -> list[dict[str, Any]]:
    return [TOOL_REGISTRY[n][0] for n in names if n in TOOL_REGISTRY]


def dispatch(name: str, args: dict[str, Any], state: dict[str, Any]) -> Any:
    if name not in TOOL_REGISTRY:
        return {"error": f"unknown tool: {name}"}
    try:
        return TOOL_REGISTRY[name][1](args, state)
    except Exception as exc:  # surface to the agent; do not crash the graph
        return {"error": f"{name}: {exc}", "type": type(exc).__name__}
