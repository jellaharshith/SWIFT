"""CLI-first zero-trust local workflow for SWIFT."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from output.formatters import JSONFormatter, MarkdownFormatter
from patch_validator import validate_patch
from sandbox_runner import run_in_sandbox
from agent.agent_pool import AgentPool
from analysis.privesc import PrivilegeEscalationAnalyzer
from output.bug_bounty_report import BugBountyFormatter
from output.pentest_report import PentestFormatter


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _append_audit(audit_log: Path, payload: dict[str, Any]) -> None:
    audit_log.parent.mkdir(parents=True, exist_ok=True)
    with audit_log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")


def _artifact_paths(repo: Path) -> tuple[Path, Path]:
    base = repo / ".swift-artifacts"
    return base, base / "audit.log.jsonl"


def _fail_closed(message: str) -> None:
    raise SystemExit(f"[DENY] {message}")


def _load_config(config_path: str | None) -> dict[str, Any]:
    if not config_path:
        return {}
    p = Path(config_path).resolve()
    if not p.exists():
        _fail_closed(f"Config file not found: {p}")
    return json.loads(p.read_text(encoding="utf-8"))


def _ensure_zero_trust(args: argparse.Namespace) -> None:
    if getattr(args, "read_only", True) and args.command in {"patch", "validate", "full"}:
        _fail_closed(f"{args.command} is blocked while --read-only is enabled.")
    if getattr(args, "allow_patch_generation", False) is False and args.command == "patch":
        _fail_closed("Patch generation requires --allow-patch-generation.")
    if getattr(args, "allow_sandbox", False) is False and args.command == "validate":
        _fail_closed("Sandbox validation requires --allow-sandbox.")
    if getattr(args, "allow_sandbox", False) is False and args.command == "full":
        _fail_closed("Full workflow with validation requires --allow-sandbox.")


def _format_scan(result: Any, output_format: str) -> str:
    if output_format == "markdown":
        return MarkdownFormatter().format(result)
    return JSONFormatter().format(result)


def run_scan(args: argparse.Namespace) -> dict[str, Any]:
    from agent.orchestrator import scan_codebase

    repo = Path(args.repo).resolve()
    artifacts_dir, audit_log = _artifact_paths(repo)
    _append_audit(
        audit_log,
        {
            "timestamp": _utc_now(),
            "action": "scan",
            "repo_path": str(repo),
            "command_executed": "swift scan",
        },
    )
    result = scan_codebase(str(repo), generate_patches_flag=False)
    rendered = _format_scan(result, args.output)
    out_file = artifacts_dir / f"scan.{ 'md' if args.output == 'markdown' else 'json'}"
    out_file.write_text(rendered, encoding="utf-8")
    json_file = artifacts_dir / "scan.json"
    json_file.write_text(JSONFormatter().format(result), encoding="utf-8")
    payload = {
        "status": "ok",
        "summary": f"Scan completed. Findings: {len(result.vulnerabilities)}",
        "artifact": str(out_file),
    }
    _write_json(artifacts_dir / "scan.result.json", payload)
    return payload


def run_triage(args: argparse.Namespace) -> dict[str, Any]:
    return run_scan(args)


def run_patch(args: argparse.Namespace) -> dict[str, Any]:
    from agent.orchestrator import scan_codebase

    repo = Path(args.repo).resolve()
    artifacts_dir, audit_log = _artifact_paths(repo)
    _append_audit(
        audit_log,
        {
            "timestamp": _utc_now(),
            "action": "patch",
            "repo_path": str(repo),
            "command_executed": "swift patch",
        },
    )
    result = scan_codebase(str(repo), generate_patches_flag=True)
    rendered = _format_scan(result, args.output)
    out_file = artifacts_dir / f"patch.{ 'md' if args.output == 'markdown' else 'json'}"
    out_file.write_text(rendered, encoding="utf-8")
    payload = {
        "status": "ok",
        "summary": f"Patches generated: {len(result.patches)}",
        "artifact": str(out_file),
    }
    _write_json(artifacts_dir / "patch.result.json", payload)
    return payload


def run_validate(args: argparse.Namespace) -> dict[str, Any]:
    repo = Path(args.repo).resolve()
    artifacts_dir, audit_log = _artifact_paths(repo)
    _append_audit(
        audit_log,
        {
            "timestamp": _utc_now(),
            "action": "validate",
            "repo_path": str(repo),
            "file_path": args.target_file or "",
            "command_executed": "swift validate",
        },
    )
    if args.patch_file:
        patch_text = Path(args.patch_file).resolve().read_text(encoding="utf-8")
        result = validate_patch(
            original_repo_path=str(repo),
            target_file_path=args.target_file or "",
            unified_diff_patch=patch_text,
            artifacts_root=str(artifacts_dir / "validator"),
        )
    else:
        result = run_in_sandbox(
            repo_path=str(repo),
            command=args.command_override,
            artifacts_root=str(artifacts_dir / "sandbox"),
        )
    _write_json(artifacts_dir / "validate.result.json", result)
    return result


def run_report(args: argparse.Namespace) -> dict[str, Any]:
    repo = Path(args.repo).resolve()
    artifacts_dir, _ = _artifact_paths(repo)
    scan_file = artifacts_dir / "scan.json"
    if not scan_file.exists():
        _fail_closed("No local scan.json found. Run scan first.")
    data = json.loads(scan_file.read_text(encoding="utf-8"))
    if args.format == "markdown":
        rendered = "# SWIFT Report\n\n```json\n" + json.dumps(data, indent=2) + "\n```"
        out_file = artifacts_dir / "report.md"
    else:
        rendered = json.dumps(data, indent=2, sort_keys=True)
        out_file = artifacts_dir / "report.json"
    out_file.write_text(rendered, encoding="utf-8")
    return {"status": "ok", "artifact": str(out_file), "summary": "Report generated locally."}


def run_full(args: argparse.Namespace) -> dict[str, Any]:
    scan_payload = run_scan(args)
    if args.allow_patch_generation:
        patch_payload = run_patch(args)
    else:
        patch_payload = {"status": "skipped", "summary": "Patch generation not allowed."}
    validate_payload = run_validate(args) if args.allow_sandbox else {
        "status": "skipped",
        "summary": "Sandbox validation not allowed.",
    }
    return {
        "status": "ok",
        "summary": "Full workflow completed with zero-trust gates.",
        "scan": scan_payload,
        "patch": patch_payload,
        "validate": validate_payload,
    }


# ─── Unified Scanner ──────────────────────────────────────────────────────────

def run_full_scan(args: argparse.Namespace) -> dict[str, Any]:
    """Run code + Kali + CVE feed simultaneously and produce unified report."""
    import asyncio
    from config.consent import require_consent
    from agent.unified_orchestrator import unified_scan
    from output.unified_report import UnifiedReportFormatter

    if not getattr(args, "repo", None) and not getattr(args, "target", None):
        _fail_closed("full-scan requires --repo and/or --target.")

    require_consent()

    repo = str(Path(args.repo).resolve()) if args.repo else None
    artifacts_dir = (Path(args.repo).resolve() / ".swift-artifacts") if args.repo else Path(".swift-artifacts")
    tools = [t.strip() for t in args.tools.split(",")] if args.tools else None

    print(f"\n[SWIFT] Starting unified scan...")
    if repo:
        print(f"  Code target : {repo}")
    if args.target:
        print(f"  Kali target : {args.target}")
    print()

    result = asyncio.run(unified_scan(
        repo_path=repo,
        kali_target=args.target,
        tools=tools,
        generate_patches=args.patches,
        skip_kali_build=args.skip_build,
    ))

    formatter = UnifiedReportFormatter()
    output_fmt = getattr(args, "output", "both")
    if output_fmt == "md":
        md_path = str(artifacts_dir / f"report-{result.scan_id}.md")
        Path(md_path).parent.mkdir(parents=True, exist_ok=True)
        Path(md_path).write_text(formatter.format_markdown(result), encoding="utf-8")
        txt_path = None
    elif output_fmt == "txt":
        txt_path = str(artifacts_dir / f"report-{result.scan_id}.txt")
        Path(txt_path).parent.mkdir(parents=True, exist_ok=True)
        Path(txt_path).write_text(formatter.format_txt(result), encoding="utf-8")
        md_path = None
    else:
        md_path, txt_path = formatter.save(result, str(artifacts_dir))

    result.report_md_path = md_path
    result.report_txt_path = txt_path

    n_merged = len(result.merged_findings)
    n_code = len(result.code_only_findings)
    n_kali = len(result.kali_only_findings)
    print(f"[SWIFT] Scan complete in {result.duration:.1f}s")
    print(f"  Merged findings : {n_merged}")
    print(f"  Code-only       : {n_code}")
    print(f"  Kali-only       : {n_kali}")
    if md_path:
        print(f"  Report (MD)     : {md_path}")
    if txt_path:
        print(f"  Report (TXT)    : {txt_path}")

    return {
        "status": "ok",
        "scan_id": result.scan_id,
        "merged_findings": n_merged,
        "code_only_findings": n_code,
        "kali_only_findings": n_kali,
        "report_md": md_path,
        "report_txt": txt_path,
        "duration": result.duration,
    }


# ─── Kali / Live Feed Commands ────────────────────────────────────────────────

def run_kali_scan(args: argparse.Namespace) -> dict[str, Any]:
    """Run Kali Linux container with all offensive security tools against target."""
    from kali.runner import KaliRunner

    target = args.target
    tools = [t.strip() for t in args.tools.split(",")] if args.tools != "all" else None

    runner = KaliRunner()

    if not args.skip_build:
        runner.build_image()

    print(f"\n[SWIFT] Starting Kali scan → {target}\n")

    # Start live CVE feed in background if requested
    cve_task = None
    if args.live_cve:
        import threading
        from feeds.live_cve import LiveCVEFeed
        feed = LiveCVEFeed()

        def _cve_thread():
            def _on_cve(e: object) -> None:
                from feeds.live_cve import CVEEntry
                if not isinstance(e, CVEEntry):
                    return
                print(
                    f"[LIVE CVE] {e.cve_id} CVSS:{e.cvss_score:.1f} {e.severity} "
                    f"{'[KEV] ' if e.cisa_known_exploited else ''}{e.description[:60]}...",
                    flush=True,
                )
            asyncio.run(feed.poll_forever(_on_cve))

        cve_thread = threading.Thread(target=_cve_thread, daemon=True)
        cve_thread.start()

    report = runner.run_scan(target=target, tools=tools)

    # Save report
    out_path = Path(args.output_file) if args.output_file else Path(f"kali-scan-{target.replace('/', '_')}.json")
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\n[SWIFT] Report saved → {out_path}")

    return {
        "status": "ok",
        "target": target,
        "tools_run": report.get("tools_run", []),
        "mitre_techniques": report.get("mitre_techniques", []),
        "artifact": str(out_path),
    }


def run_live_feed(args: argparse.Namespace) -> dict[str, Any]:
    """Stream live CVE data from NVD + CISA KEV every 2 seconds."""
    from feeds.live_cve import LiveCVEFeed
    import threading

    feed = LiveCVEFeed()
    severity_filter = args.severity.upper() if args.severity else None
    count = {"total": 0}

    def on_cve(entry: object) -> None:
        from feeds.live_cve import CVEEntry
        if not isinstance(entry, CVEEntry):
            return
        if severity_filter and entry.severity != severity_filter:
            return
        count["total"] += 1
        kev = " [KEV-EXPLOITED]" if entry.cisa_known_exploited else ""
        line = {
            "cve_id": entry.cve_id,
            "cvss": entry.cvss_score,
            "severity": entry.severity,
            "cwe": entry.cwe_ids,
            "description": entry.description,
            "known_exploited": entry.cisa_known_exploited,
            "published": entry.published,
        }
        if args.output == "json":
            print(json.dumps(line), flush=True)
        else:
            print(
                f"[LIVE CVE] {entry.cve_id}  CVSS:{entry.cvss_score:.1f}  "
                f"{entry.severity}{kev}\n"
                f"  CWE: {', '.join(entry.cwe_ids) or 'N/A'}\n"
                f"  {entry.description[:120]}\n",
                flush=True,
            )

    print(f"[SWIFT] Live CVE feed started (poll every {args.interval}s). Ctrl+C to stop.\n", flush=True)
    try:
        asyncio.run(feed.poll_forever(on_cve))
    except KeyboardInterrupt:
        print(f"\n[SWIFT] Feed stopped. Total CVEs seen: {count['total']}")

    return {"status": "stopped", "cves_seen": count["total"]}


def run_attack_sim(args: argparse.Namespace) -> dict[str, Any]:
    """Run MITRE ATT&CK-mapped exploit simulation inside Kali container."""
    from kali.runner import KaliRunner, MITRE_MAPPINGS, ALL_TOOLS

    target = args.target
    technique = args.technique.upper() if args.technique != "all" else "all"

    # Map technique ID to tool
    tool_for_technique: dict[str, str] = {
        v["technique_id"]: k for k, v in MITRE_MAPPINGS.items()
    }

    if technique == "all":
        tools_to_run = ALL_TOOLS
    else:
        matched_tool = tool_for_technique.get(technique)
        if not matched_tool:
            available = ", ".join(sorted(set(v["technique_id"] for v in MITRE_MAPPINGS.values())))
            _fail_closed(f"Unknown technique {technique}. Available: {available}")
        tools_to_run = [matched_tool]

    print(f"\n[SWIFT ATTACK-SIM] Target: {target}")
    print(f"[SWIFT ATTACK-SIM] Technique: {technique}")
    print(f"[SWIFT ATTACK-SIM] Tools: {', '.join(tools_to_run)}\n")

    runner = KaliRunner()
    if not args.skip_build:
        runner.build_image()

    report = runner.run_scan(target=target, tools=tools_to_run)

    out_path = Path(f"attack-sim-{target.replace('/', '_')}-{technique}.json")
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\n[SWIFT] Attack simulation report → {out_path}")

    return {
        "status": "ok",
        "target": target,
        "technique": technique,
        "mitre_techniques": report.get("mitre_techniques", []),
        "artifact": str(out_path),
    }


# ─── Parser ───────────────────────────────────────────────────────────────────

def _add_shared_flags(p: argparse.ArgumentParser, include_output: bool = True) -> None:
    p.add_argument("--repo", required=True, help="Local repository path")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--read-only", dest="read_only", action="store_true", default=True)
    mode.add_argument("--no-read-only", dest="read_only", action="store_false")
    p.add_argument("--allow-patch-generation", action="store_true")
    p.add_argument("--allow-sandbox", action="store_true")
    if include_output:
        p.add_argument("--output", choices=["json", "markdown"], default="json")
    p.add_argument("--config", default=None)
    p.add_argument("--strict", action="store_true")


_WIZARD_BANNER = """
╔══════════════════════════════════════════╗
║   SWIFT Security Scanner                 ║
║   Powered by live CVEs + MITRE ATT&CK   ║
╚══════════════════════════════════════════╝
"""

_WIZARD_MENU = """What do you want to scan?

  1. Codebase   (static analysis — local path or GitHub URL)
  2. URL        (web vuln scan — https://target.com)
  3. Domain     (full recon — example.com)
  4. Everything (codebase + domain/URL combined)
"""


def run_wizard(_args: Any) -> None:
    """Interactive plain-English wizard for target selection and scanning."""
    from config.consent import require_consent

    print(_WIZARD_BANNER)
    print(_WIZARD_MENU)

    choice_str = input("Enter choice [1-4]: ").strip()
    if choice_str not in ("1", "2", "3", "4"):
        print("Invalid choice. Exiting.")
        return

    choice = int(choice_str)
    repo_path: str | None = None
    kali_target: str | None = None

    if choice in (1, 4):
        repo_path = input("Enter codebase path or GitHub URL: ").strip()
    if choice in (2, 3, 4):
        label = "URL" if choice == 2 else "Domain"
        kali_target = input(f"Enter {label} to scan: ").strip()
        require_consent()

    artifacts_dir = Path(".swift-artifacts")
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    def progress(msg: str) -> None:
        print(msg)

    print()
    result = asyncio.run(AgentPool().run_all(repo_path, kali_target, progress))

    print("\n[PrivEsc] analyzing privilege escalation chains...")
    paths = PrivilegeEscalationAnalyzer().analyze(result)
    if paths:
        print(f"[PrivEsc] {len(paths)} escalation path(s) found")

    bounty_path = BugBountyFormatter().save(result, paths, str(artifacts_dir))
    pentest_path = PentestFormatter().save(result, paths, str(artifacts_dir))

    duration = getattr(result, "duration", 0)
    print(f"\n✓ Scan complete in {duration:.0f}s\n")
    print("Reports saved:")
    print(f"  {bounty_path}  (HackerOne/Bugcrowd)")
    print(f"  {pentest_path}  (Internal pentest)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="swift",
        description="SWIFT — CLI-only security scanner with Kali Linux offensive capabilities",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ── Code analysis commands ─────────────────────────────────────────────
    scan = sub.add_parser("scan", help="Scan local repo for vulnerabilities")
    _add_shared_flags(scan)

    triage = sub.add_parser("triage", help="Fast triage scan (alias for scan)")
    _add_shared_flags(triage)

    patch = sub.add_parser("patch", help="Generate security patches")
    _add_shared_flags(patch)

    v = sub.add_parser("validate", help="Validate patches in sandbox")
    _add_shared_flags(v, include_output=False)
    v.add_argument("--patch-file", default=None)
    v.add_argument("--target-file", default=None)
    v.add_argument("--command-override", default=None)

    r = sub.add_parser("report", help="Generate report from previous scan")
    _add_shared_flags(r, include_output=False)
    r.add_argument("--format", choices=["json", "markdown"], default="markdown")

    full = sub.add_parser("full", help="Full pipeline: scan → patch → validate")
    _add_shared_flags(full)

    # ── Unified scanner ────────────────────────────────────────────────────
    fs = sub.add_parser("full-scan", help="Run code + Kali + CVE scan simultaneously")
    fs.add_argument("--repo", default=None, help="Local repo path for code scan")
    fs.add_argument("--target", default=None, help="Host/URL for Kali offensive scan")
    fs.add_argument("--tools", default=None, help="Comma-separated Kali tools (default: all)")
    fs.add_argument("--patches", action="store_true", help="Generate patches for code findings")
    fs.add_argument("--output", choices=["md", "txt", "both"], default="both")
    fs.add_argument("--skip-build", dest="skip_build", action="store_true",
                    help="Skip Kali Docker image build check")

    # ── Kali offensive commands ────────────────────────────────────────────
    kali = sub.add_parser("kali-scan", help="Run Kali Linux tools against live target")
    kali.add_argument("--target", required=True, help="Target IP, hostname, or URL")
    kali.add_argument(
        "--tools",
        default="all",
        help="Comma-separated tools or 'all': nmap,masscan,nikto,sqlmap,nuclei,gobuster,searchsploit",
    )
    kali.add_argument("--live-cve", action="store_true", help="Pull live CVE feed during scan")
    kali.add_argument("--skip-build", action="store_true", help="Skip docker image build check")
    kali.add_argument("--output-file", default=None, help="Path to save JSON report")

    feed = sub.add_parser("live-feed", help="Stream live CVEs from NVD + CISA KEV every 2s")
    feed.add_argument("--severity", default=None, choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    feed.add_argument("--output", choices=["json", "stream"], default="stream")
    feed.add_argument("--interval", type=int, default=2, help="Poll interval in seconds")

    atk = sub.add_parser("attack-sim", help="MITRE ATT&CK-mapped exploit simulation")
    atk.add_argument("--target", required=True, help="Target IP, hostname, or URL")
    atk.add_argument(
        "--technique",
        default="all",
        help="MITRE technique ID (e.g. T1046) or 'all'",
    )
    atk.add_argument("--skip-build", action="store_true", help="Skip docker image build check")

    sub.add_parser(
        "wizard",
        help="Interactive scanner wizard — choose codebase, URL, or domain in plain English",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if hasattr(args, "config"):
        _load_config(args.config)

    if args.command not in {"kali-scan", "live-feed", "attack-sim", "full-scan", "wizard"}:
        _ensure_zero_trust(args)

    handlers = {
        "scan": run_scan,
        "triage": run_triage,
        "patch": run_patch,
        "validate": run_validate,
        "report": run_report,
        "full": run_full,
        "full-scan": run_full_scan,
        "kali-scan": run_kali_scan,
        "live-feed": run_live_feed,
        "attack-sim": run_attack_sim,
        "wizard": run_wizard,
    }
    payload = handlers[args.command](args)
    if args.command not in {"live-feed", "wizard"}:
        print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
