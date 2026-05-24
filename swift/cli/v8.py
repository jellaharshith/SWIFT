"""SWIFT v8 CLI subcommands.

Kept in its own module so :mod:`swift_cli` stays readable. Registered by
:func:`register` in build_parser() and dispatched via :data:`HANDLERS`.

Subcommands (all eleven described in the v8 plan):

* ``engage``         -- Soundwave engagement workflow
* ``redteam-full``   -- Decepticon main kill-chain via LangGraph layer
                        (separate verb to avoid clobbering existing ``redteam``)
* ``vuln-pipeline``  -- 5-stage Scanner->Detector->Verifier->Exploiter->Patcher
* ``hunt``           -- bug-bounty workflow with hunt memory
* ``validate``       -- 7-question + 4-gate finding validation
* ``autopilot``      -- full hunt loop with safety modes
* ``bb-report``      -- platform-native bug-bounty report
                        (suffixed to avoid clashing with existing ``report``)
* ``web3-audit``     -- smart contract audit
* ``lab``            -- docker-compose lab management
* ``skills``         -- symlink vendored skills into ~/.claude
* ``kg``             -- attack knowledge graph query/export/prune
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable


# ----------------------------------------------------------------- registration

def register(sub: argparse._SubParsersAction) -> None:
    # engage --------------------------------------------------------------
    p = sub.add_parser("engage", help="Soundwave engagement interview (writes roe.yaml + OPPLAN.md + ConOps.md)")
    p.add_argument("--engagement-id", required=True)
    p.add_argument("--targets", required=True, help="comma-separated list of hostnames/CIDRs/URLs")
    p.add_argument("--contact", required=True)
    p.add_argument("--outdir", default=".swift-engagement")
    p.add_argument("--quick", action="store_true", help="skip the LLM interview; stamp templates only")

    # redteam-full --------------------------------------------------------
    p = sub.add_parser("redteam-full", help="Decepticon kill chain: recon -> exploit -> post_exploit -> analyst")
    p.add_argument("--roe", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--graph", default="decepticon", help="graph name (see `swiftsec lab graphs`)")
    p.add_argument("--out-dir", default=".swift-artifacts/redteam")

    # vuln-pipeline -------------------------------------------------------
    p = sub.add_parser("vuln-pipeline", help="5-stage vulnerability pipeline (vulnresearch graph)")
    p.add_argument("--roe", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--out-dir", default=".swift-artifacts/vuln-pipeline")

    # hunt ----------------------------------------------------------------
    p = sub.add_parser("hunt", help="Bug-bounty hunt workflow (recon -> hunt -> validate)")
    p.add_argument("--roe", required=True)
    p.add_argument("--program", required=True, help="program slug (e.g. h1-shopify)")
    p.add_argument("--target", required=True)
    p.add_argument("--bearer", default=None, help="auth bearer token for downstream scanners")
    p.add_argument("--cookie", default=None, help="raw Cookie header for downstream scanners")
    p.add_argument("--out-dir", default=".swift-artifacts/hunt")
    p.add_argument("--ptes", action="store_true", help="route hunt through PTES 7-phase DAG")
    p.add_argument("--platform", choices=["h1", "bugcrowd", "intigriti", "immunefi"], default="h1")

    # validate ------------------------------------------------------------
    p = sub.add_parser("validate", help="Run 7-question + 4-gate validation on a finding JSON")
    p.add_argument("finding", help="path to finding JSON (or - for stdin)")

    # autopilot -----------------------------------------------------------
    p = sub.add_parser("autopilot", help="Autonomous hunt loop with safety modes")
    p.add_argument("--roe", required=True)
    p.add_argument("--program", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--mode", choices=["paranoid", "normal", "yolo"], default="paranoid")
    p.add_argument("--out-dir", default=".swift-artifacts/autopilot")

    # bb-report -----------------------------------------------------------
    p = sub.add_parser("bb-report", help="Format a finding for a bounty platform")
    p.add_argument("finding", help="path to finding JSON")
    p.add_argument("--platform", choices=["h1", "bugcrowd", "intigriti", "immunefi"], required=True)
    p.add_argument("--out", default=None, help="write rendered markdown to this path")

    # web3-audit ----------------------------------------------------------
    p = sub.add_parser("web3-audit", help="Smart contract static analysis (slither + mythril + patterns)")
    p.add_argument("--roe", required=True)
    p.add_argument("target", help="path to .sol file or project directory")
    p.add_argument("--no-mythril", action="store_true")
    p.add_argument("--no-slither", action="store_true")

    # lab -----------------------------------------------------------------
    p = sub.add_parser("lab", help="Manage the optional docker-compose lab (LiteLLM, Neo4j, sandbox-daemon)")
    lab_sub = p.add_subparsers(dest="lab_cmd", required=True)
    lab_sub.add_parser("up",     help="Start lab services")
    lab_sub.add_parser("down",   help="Stop lab services")
    lab_sub.add_parser("status", help="Show service status")
    lab_sub.add_parser("graphs", help="List available LangGraph sub-graphs")

    # skills --------------------------------------------------------------
    p = sub.add_parser("skills", help="Manage vendored Claude Code skills + slash commands")
    sk = p.add_subparsers(dest="skills_cmd", required=True)
    sk_i = sk.add_parser("install", help="Symlink swift/skills into ~/.claude/")
    sk_i.add_argument("--dry-run", action="store_true")
    sk_i.add_argument("--force", action="store_true", help="overwrite existing non-symlink files of the same name")
    sk_i.add_argument("--source", choices=["swift", "cbh", "all"], default="all",
                      help="which skill bundle to install (default: all)")
    sk.add_parser("uninstall", help="Remove SWIFT-installed symlinks")
    sk.add_parser("list",      help="Show currently installed skills + commands")

    # ptes ----------------------------------------------------------------
    p = sub.add_parser("ptes", help="PTES 7-phase engagement (Mitnick mind / Haddix hunt / Rosén report)")
    p.add_argument("target", help="target URL, hostname, or CIDR")
    p.add_argument("--roe", required=True, help="path to roe.yaml")
    p.add_argument("--mode", choices=["pentest", "bounty"], default="pentest")
    p.add_argument("--depth", choices=["fast", "standard", "deep"], default="standard")
    p.add_argument("--stop-after", metavar="PHASE",
                   choices=["pre_engage", "intel", "threat_model", "vuln",
                            "exploit_phase", "post_exploit", "report_phase"],
                   default=None, help="halt after this phase (for dry runs)")
    p.add_argument("--out-dir", default=".swift-artifacts/ptes")
    p.add_argument("--engagement-id", default=None, help="optional engagement identifier")

    # kg ------------------------------------------------------------------
    p = sub.add_parser("kg", help="Attack knowledge graph: query / export / prune")
    kg = p.add_subparsers(dest="kg_cmd", required=True)
    kgq = kg.add_parser("export", help="Export the graph as json / cypher / graphml")
    kgq.add_argument("--format", choices=["json", "cypher", "graphml"], default="json")
    kgq.add_argument("--out", default=None)
    kgn = kg.add_parser("neighbors", help="List a node's direct neighbors")
    kgn.add_argument("node_id")
    kgn.add_argument("--relation", default=None)
    kgp = kg.add_parser("prune", help="Drop everything for an engagement (re-scope)")
    kgp.add_argument("engagement_id")

    # cbh -----------------------------------------------------------------
    p = sub.add_parser("cbh", help="Run the Claude-BugHunter CLI (cbh.py) — deterministic terminal runner")
    p.add_argument("cbh_args", nargs=argparse.REMAINDER, help="arguments forwarded to cbh.py")

    # kev-refresh ---------------------------------------------------------
    sub.add_parser("kev-refresh", help="Pull latest CISA KEV catalog into swift/intel/data/cisa_kev.json")


# --------------------------------------------------------------------- handlers

def _load_roe(path: str):
    from security.roe import load_roe, assert_window_active
    roe = load_roe(path)
    assert_window_active(roe)
    return roe


def run_engage(args: argparse.Namespace) -> dict[str, Any]:
    from engagement import engage, engage_quick
    targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    fn = engage_quick if args.quick else engage
    paths = fn(
        engagement_id=args.engagement_id,
        targets=targets,
        contact=args.contact,
        outdir=args.outdir,
    )
    return {"status": "ok", "files": {k: str(v) for k, v in paths.items()}}


def run_redteam_full(args: argparse.Namespace) -> dict[str, Any]:
    from agent.langgraph_layer import run_subgraph
    from security.roe import assert_technique_allowed
    roe = _load_roe(args.roe)
    assert_technique_allowed(roe, "langgraph_subagent")
    state: dict[str, Any] = {
        "roe": roe,
        "engagement": _engagement_dict(roe),
        "target": args.target,
        "goal": f"Run the full kill chain against {args.target}.",
    }
    run_subgraph(args.graph, state)
    out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    (out / "findings.json").write_text(json.dumps(state["findings"], indent=2, default=str), encoding="utf-8")
    return {"status": "ok", "graph": args.graph,
            "findings_count": len(state["findings"]),
            "out": str(out / "findings.json")}


def run_vuln_pipeline(args: argparse.Namespace) -> dict[str, Any]:
    from agent.langgraph_layer import run_subgraph
    from security.roe import assert_technique_allowed
    roe = _load_roe(args.roe)
    assert_technique_allowed(roe, "vuln_pipeline")
    state: dict[str, Any] = {
        "roe": roe,
        "engagement": _engagement_dict(roe),
        "target": args.target,
        "goal": f"Run 5-stage vulnerability pipeline against {args.target}.",
    }
    run_subgraph("vulnresearch", state)
    out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    (out / "findings.json").write_text(json.dumps(state["findings"], indent=2, default=str), encoding="utf-8")
    return {"status": "ok", "findings_count": len(state["findings"]),
            "out": str(out / "findings.json")}


def run_hunt(args: argparse.Namespace) -> dict[str, Any]:
    if getattr(args, "ptes", False):
        from bounty.ptes_router import run_bounty_ptes
        from security.roe import load_roe, assert_window_active
        roe = load_roe(args.roe)
        assert_window_active(roe)
        state: dict[str, Any] = {
            "roe": roe,
            "engagement": _engagement_dict(roe),
            "target": args.target,
            "program": args.program,
        }
        result = run_bounty_ptes(
            state,
            program=args.program,
            platform=getattr(args, "platform", "h1"),
            depth="standard",
            out_dir=args.out_dir,
        )
        print(f"[HUNT-PTES] Complete. {len(result.get('findings', []))} findings.")
        return {"status": "ok", "findings_count": len(result.get("findings", []))}

    from agent.langgraph_layer import run_subgraph
    from bounty.auth_session import AuthSession, set_session
    from bounty.hunt_memory import HuntMemory
    from security.roe import assert_technique_allowed
    roe = _load_roe(args.roe)
    for tech in ("osint", "active_scan", "auth_chain"):
        if tech not in roe.allowed_techniques:
            # auth_chain is optional; soft-warn instead of deny when missing
            if tech == "auth_chain":
                continue
            assert_technique_allowed(roe, tech)

    if args.bearer or args.cookie:
        cookies: dict[str, str] = {}
        if args.cookie:
            for kv in args.cookie.split(";"):
                k, _, v = kv.partition("=")
                if k.strip():
                    cookies[k.strip()] = v.strip()
        set_session(AuthSession(
            engagement_id=roe.engagement_id, bearer=args.bearer, cookies=cookies,
        ))

    mem = HuntMemory()
    mem.record_action(engagement=roe.engagement_id, action="hunt.start",
                      target=args.target, program=args.program)

    state: dict[str, Any] = {
        "roe": roe,
        "engagement": _engagement_dict(roe),
        "target": args.target,
        "program": args.program,
        "goal": f"Run a bounty hunt against {args.target} for program {args.program}.",
    }
    run_subgraph("decepticon", state)
    out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    (out / "findings.json").write_text(json.dumps(state["findings"], indent=2, default=str), encoding="utf-8")
    mem.record_action(engagement=roe.engagement_id, action="hunt.finish",
                      target=args.target, findings=len(state["findings"]))
    return {"status": "ok", "findings_count": len(state["findings"]),
            "out": str(out / "findings.json")}


def run_validate(args: argparse.Namespace) -> dict[str, Any]:
    from bounty.validator import validate_dict
    raw = sys.stdin.read() if args.finding == "-" else Path(args.finding).read_text(encoding="utf-8")
    data = json.loads(raw)
    res = validate_dict(data)
    return {
        "verdict": res.verdict.value,
        "reason": res.reason,
        "failed_question": res.failed_question,
        "suggested_severity": res.suggested_severity,
        "gates": res.gates,
    }


def run_autopilot(args: argparse.Namespace) -> dict[str, Any]:
    """Autopilot = hunt + validate + (optionally) bb-report, gated by mode."""
    from bounty.validator import validate_dict
    out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)

    # Phase 1: hunt
    hunt_args = argparse.Namespace(
        roe=args.roe, program=args.program, target=args.target,
        bearer=None, cookie=None, out_dir=str(out / "hunt"),
    )
    hunt_res = run_hunt(hunt_args)
    findings_path = Path(hunt_res["out"])
    findings = json.loads(findings_path.read_text(encoding="utf-8"))

    validated: list[dict[str, Any]] = []
    for f in findings:
        try:
            v = validate_dict(f)
            validated.append({"finding": f, "verdict": v.verdict.value, "reason": v.reason})
        except Exception as e:  # malformed finding; keep but mark
            validated.append({"finding": f, "verdict": "ERROR", "reason": str(e)})
    (out / "validated.json").write_text(json.dumps(validated, indent=2, default=str), encoding="utf-8")

    # Phase 3: report -- paranoid never auto-files; normal stages drafts; yolo would post
    passed = [v for v in validated if v["verdict"] == "PASS"]
    return {
        "status": "ok", "mode": args.mode,
        "findings": len(findings),
        "validated_pass": len(passed),
        "validated_path": str(out / "validated.json"),
        "next": ("draft reports under " + str(out / "reports"))
                 if args.mode != "paranoid"
                 else "paranoid: operator must run `swiftsec bb-report` per finding manually",
    }


def run_bb_report(args: argparse.Namespace) -> dict[str, Any]:
    from bounty.report_formats import format_report
    data = json.loads(Path(args.finding).read_text(encoding="utf-8"))
    md = format_report(args.platform, data)
    if args.out:
        Path(args.out).write_text(md, encoding="utf-8")
        return {"status": "ok", "platform": args.platform, "out": args.out, "bytes": len(md)}
    print(md)
    return {"status": "ok", "platform": args.platform, "bytes": len(md)}


def run_web3_audit(args: argparse.Namespace) -> dict[str, Any]:
    from bounty.web3 import mythril, patterns, slither
    from security.roe import assert_technique_allowed
    roe = _load_roe(args.roe)
    assert_technique_allowed(roe, "web3_audit")
    result: dict[str, Any] = {
        "target": args.target,
        "patterns": patterns.scan(args.target),
    }
    if not args.no_slither:
        result["slither"] = slither.analyze(args.target)
    if not args.no_mythril:
        result["mythril"] = mythril.analyze(args.target)
    return result


def run_lab(args: argparse.Namespace) -> dict[str, Any]:
    if args.lab_cmd == "graphs":
        from agent.langgraph_layer import list_graphs
        return {"graphs": list_graphs()}
    compose = _find_compose_file()
    if compose is None:
        return {"status": "error", "message": "deploy/compose.yaml not found; reinstall swiftsec"}
    if not shutil.which("docker"):
        return {"status": "error", "message": "docker CLI missing"}
    cmd: list[str]
    if args.lab_cmd == "up":
        cmd = ["docker", "compose", "-f", str(compose), "up", "-d"]
    elif args.lab_cmd == "down":
        cmd = ["docker", "compose", "-f", str(compose), "down"]
    elif args.lab_cmd == "status":
        cmd = ["docker", "compose", "-f", str(compose), "ps"]
    else:
        return {"status": "error", "message": f"unknown lab cmd: {args.lab_cmd}"}
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return {
        "status": "ok" if proc.returncode == 0 else "error",
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr_tail": proc.stderr[-2000:],
    }


def run_skills(args: argparse.Namespace) -> dict[str, Any]:
    if args.skills_cmd == "list":
        return _skills_list()
    if args.skills_cmd == "install":
        return _skills_install(dry_run=args.dry_run, force=args.force, source=args.source)
    if args.skills_cmd == "uninstall":
        return _skills_uninstall()
    return {"status": "error", "message": f"unknown skills cmd: {args.skills_cmd}"}


def run_kg(args: argparse.Namespace) -> dict[str, Any]:
    from graph import open_kg
    kg = open_kg()
    if args.kg_cmd == "export":
        blob = kg.export(args.format)
        if args.out:
            Path(args.out).write_text(blob, encoding="utf-8")
            return {"status": "ok", "format": args.format, "out": args.out, "bytes": len(blob)}
        print(blob)
        return {"status": "ok", "format": args.format, "bytes": len(blob)}
    if args.kg_cmd == "neighbors":
        return {"status": "ok",
                "node": args.node_id,
                "neighbors": kg.neighbors(args.node_id, relation=args.relation)}
    if args.kg_cmd == "prune":
        return {"status": "not-implemented",
                "message": "engagement-scoped prune lands in v8.1"}
    return {"status": "error", "message": f"unknown kg cmd: {args.kg_cmd}"}


# ------------------------------------------------------------------ internals

def _engagement_dict(roe) -> dict[str, Any]:
    return {
        "engagement_id": roe.engagement_id,
        "authorized_targets": list(roe.authorized_targets),
        "allowed_techniques": list(roe.allowed_techniques),
        "contact": roe.contact,
        "simulate_only": roe.simulate_only,
    }


def _find_compose_file() -> Path | None:
    # 1. installed share path (set via setuptools.data-files)
    candidates = [
        Path(sys.prefix) / "share/swiftsec/deploy/compose.yaml",
        Path(__file__).resolve().parent.parent / "deploy/compose.yaml",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def _claude_skills_dir() -> Path:
    return Path(os.getenv("CLAUDE_HOME") or Path.home() / ".claude") / "skills"


def _claude_commands_dir() -> Path:
    return Path(os.getenv("CLAUDE_HOME") or Path.home() / ".claude") / "commands"


def _vendored_skills_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "skills"


def _skills_install(*, dry_run: bool, force: bool, source: str = "all") -> dict[str, Any]:
    src_root = _vendored_skills_dir()
    if not src_root.exists():
        return {"status": "error", "message": f"vendored skills dir missing: {src_root}"}

    # Each tuple: (src_file, dst_root, provenance)
    entries: list[tuple[Path, Path, str]] = []

    if source in ("swift", "all"):
        for kind, dst_root in (("agents", _claude_skills_dir()), ("commands", _claude_commands_dir())):
            src_dir = src_root / kind
            for src_file in src_dir.glob("swift-*.md"):
                entries.append((src_file, dst_root, "swift"))

    if source in ("cbh", "all"):
        cbh_root = src_root / "cbh"
        # CBH skills: each lives in a subdir as SKILL.md; symlink as <dir-name>.md
        cbh_skills_dir = cbh_root / "skills"
        if cbh_skills_dir.exists():
            for src_file in cbh_skills_dir.rglob("SKILL.md"):
                entries.append((src_file, _claude_skills_dir(), "cbh"))
        # CBH commands are flat .md files
        cbh_commands_dir = cbh_root / "commands"
        if cbh_commands_dir.exists():
            for src_file in cbh_commands_dir.glob("*.md"):
                entries.append((src_file, _claude_commands_dir(), "cbh"))

    plan: list[dict[str, str]] = []
    for src_file, dst_root, provenance in entries:
        dst_root.mkdir(parents=True, exist_ok=True)
        # CBH SKILL.md files: use parent dir name as the symlink filename
        if provenance == "cbh" and src_file.name == "SKILL.md":
            dst_name = src_file.parent.name + ".md"
        else:
            dst_name = src_file.name
        dst_file = dst_root / dst_name
        action = _plan_install(src_file, dst_file, force=force)
        plan.append({
            "provenance": provenance,
            "src": str(src_file),
            "dst": str(dst_file),
            "action": action,
        })

    if dry_run:
        return {"status": "dry-run", "actions": plan}

    for entry in plan:
        dst = Path(entry["dst"])
        if entry["action"] == "skip-conflict":
            continue
        if entry["action"] in {"replace", "force-replace"} and dst.exists():
            dst.unlink()
        if entry["action"] != "noop":
            dst.symlink_to(Path(entry["src"]))
    return {"status": "ok", "actions": plan}


def _plan_install(src: Path, dst: Path, *, force: bool) -> str:
    if not dst.exists():
        return "create-symlink"
    if dst.is_symlink():
        target = os.readlink(dst)
        if target == str(src):
            return "noop"
        return "replace"
    # exists, not symlink
    if force:
        return "force-replace"
    return "skip-conflict"


def _skills_uninstall() -> dict[str, Any]:
    cbh_root = _vendored_skills_dir() / "cbh"
    removed: list[str] = []
    for dst_root in (_claude_skills_dir(), _claude_commands_dir()):
        if not dst_root.exists():
            continue
        # Remove SWIFT-prefixed symlinks
        for f in dst_root.glob("swift-*.md"):
            if f.is_symlink():
                f.unlink()
                removed.append(str(f))
        # Remove any symlinks that point inside swift/skills/cbh/
        for f in dst_root.iterdir():
            if f.is_symlink():
                try:
                    target = Path(os.readlink(f))
                    # Resolve relative symlinks against the dst_root
                    if not target.is_absolute():
                        target = (dst_root / target).resolve()
                    if str(cbh_root) in str(target):
                        f.unlink()
                        removed.append(str(f))
                except OSError:
                    pass
    return {"status": "ok", "removed": removed}


def _skills_list() -> dict[str, Any]:
    cbh_marker = "/cbh/"
    out: dict[str, list[dict[str, str]]] = {"agents": [], "commands": []}
    for kind, dst_root in (("agents", _claude_skills_dir()), ("commands", _claude_commands_dir())):
        if not dst_root.exists():
            continue
        for f in sorted(dst_root.iterdir()):
            if not f.name.endswith(".md"):
                continue
            tag = "link" if f.is_symlink() else "file"
            provenance = "unknown"
            if f.is_symlink():
                try:
                    target = os.readlink(f)
                    provenance = "cbh" if cbh_marker in target else "swift"
                except OSError:
                    pass
            out[kind].append({"name": f.name, "tag": tag, "provenance": provenance})
    return {"status": "ok", "installed": out}


def run_cbh(args: argparse.Namespace) -> dict[str, Any]:
    cbh_script = Path(__file__).resolve().parent.parent / "skills" / "cbh" / "scripts" / "cbh.py"
    if not cbh_script.exists():
        return {"status": "error", "message": f"cbh.py not found at {cbh_script}; run `swiftsec skills install --source cbh` first"}
    cmd = [sys.executable, str(cbh_script)] + list(args.cbh_args)
    result = subprocess.run(cmd)
    return {"status": "ok", "exit_code": result.returncode}


def run_kev_refresh(args: argparse.Namespace) -> dict[str, Any]:
    script = Path(__file__).resolve().parent.parent / "skills" / "cbh" / "scripts" / "refresh-cve-index.py"
    if not script.exists():
        return {"status": "error", "message": f"refresh-cve-index.py not found at {script}"}
    out_dir = Path(__file__).resolve().parent.parent / "intel" / "data"
    out_dir.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "SWIFT_KEV_OUTPUT": str(out_dir / "cisa_kev.json")}
    result = subprocess.run([sys.executable, str(script)], env=env)
    return {"status": "ok", "exit_code": result.returncode}


def _handle_ptes(args: argparse.Namespace) -> int:
    from security.roe import load_roe, assert_techniques
    from agent.langgraph_layer.graphs.ptes import run_ptes
    import json

    roe = load_roe(args.roe)
    required = ["osint", "active_scan", "exploit", "post_exploit",
                "engagement_planning", "vuln_pipeline", "ptes_pre_engage",
                "ptes_intel", "ptes_threat_model", "ptes_report"]
    if args.mode == "bounty":
        required = [t for t in required if t not in ("exploit",)]
    assert_techniques(roe, required)

    state: dict = {
        "roe": roe,
        "engagement": {
            "target": args.target,
            "mode": args.mode,
            "depth": args.depth,
            "engagement_id": args.engagement_id or f"ptes-{args.target}",
        },
    }

    print(f"[PTES] Starting {args.mode} engagement on {args.target} (depth={args.depth})")
    if args.stop_after:
        print(f"[PTES] Will stop after phase: {args.stop_after}")

    result = run_ptes(
        state,
        mode=args.mode,
        depth=args.depth,
        stop_after=args.stop_after,
        out_dir=args.out_dir,
    )

    findings = result.get("findings", [])
    print(f"\n[PTES] Complete. {len(findings)} findings. Artifacts: {args.out_dir}")
    return 0


# ----------------------------------------------------------------- dispatch map

HANDLERS: dict[str, Callable[[argparse.Namespace], dict[str, Any]]] = {
    "engage":         run_engage,
    "redteam-full":   run_redteam_full,
    "vuln-pipeline":  run_vuln_pipeline,
    "hunt":           run_hunt,
    "validate":       run_validate,
    "autopilot":      run_autopilot,
    "bb-report":      run_bb_report,
    "web3-audit":     run_web3_audit,
    "lab":            run_lab,
    "skills":         run_skills,
    "kg":             run_kg,
    "ptes":           _handle_ptes,
    "cbh":            run_cbh,
    "kev-refresh":    run_kev_refresh,
}

# Commands that should bypass zero-trust + may emit non-JSON.
ZERO_TRUST_EXEMPT = set(HANDLERS.keys())
NO_JSON_DUMP = {"bb-report", "kg"}  # these may print large markdown / cypher
