"""CLI-first zero-trust local workflow for SWIFT."""
from __future__ import annotations

# Load .env before any module reads os.getenv at import time.
from dotenv import load_dotenv
load_dotenv()

import argparse
import asyncio
import json
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cli.banner import print_banner, should_show_banner
from swift import __version__
from output.formatters import JSONFormatter, MarkdownFormatter
from agent.agent_pool import AgentPool
from analysis.privesc import PrivilegeEscalationAnalyzer
from output.bug_bounty_report import BugBountyFormatter
from output.pentest_report import PentestFormatter
from log.audit import log_step, set_step_log_path
from config.auto_confirm import is_auto_confirmed


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _append_audit(audit_log: Path, payload: dict[str, Any]) -> None:
    """Back-compat wrapper. New code should call log_step()."""
    audit_log.parent.mkdir(parents=True, exist_ok=True)
    with audit_log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")
    step = payload.get("action") or payload.get("step") or "audit"
    fields = {k: v for k, v in payload.items() if k not in {"action", "timestamp"}}
    log_step(f"audit.{step}", **fields)


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
    if getattr(args, "read_only", True) is False:
        return  # --no-read-only explicitly set; allow all operations


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
    result = scan_codebase(str(repo))
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


def run_redteam(args: argparse.Namespace) -> dict:
    """Full red-team pipeline: ROE → OSINT → scan → probes → Kali → chains → post-exploit."""
    print("[redteam] Not yet fully wired — run: swift web-scan + swift kali-scan + swift osint")
    return {"status": "stub", "message": "redteam command coming in next integration step"}


def run_osint(args: argparse.Namespace) -> dict:
    """OSINT recon phase: DNS, subdomain, GitHub dorks, Shodan, WHOIS."""
    print("[osint] Not yet fully wired — OSINT modules created separately")
    return {"status": "stub", "message": "osint command coming in next integration step"}


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
    return run_scan(args)


# ─── Unified Scanner ──────────────────────────────────────────────────────────

def run_full_scan(args: argparse.Namespace) -> dict[str, Any]:
    """Run code + Kali + CVE feed simultaneously and produce unified report."""
    import asyncio
    from config.consent import require_consent
    from agent.unified_orchestrator import unified_scan
    from output.unified_report import UnifiedReportFormatter

    if not getattr(args, "repo", None) and not getattr(args, "target", None):
        _fail_closed("full-scan requires --repo and/or --target.")

    require_consent(args)

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

    out_path = Path(args.output_file) if args.output_file else Path(f"kali-scan-{target.replace('/', '_')}.json")
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    from output.kali_report import KaliBugBountyReport
    print(KaliBugBountyReport().render(report, artifact_path=str(out_path)))

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
        asyncio.run(feed.poll_forever(on_cve, interval=args.interval))
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
    p.add_argument("--allow-sandbox", action="store_true")
    if include_output:
        p.add_argument("--output", choices=["json", "markdown"], default="json")
    p.add_argument("--config", default=None)
    p.add_argument("--strict", action="store_true")



_WIZARD_MENU = """What do you want to scan?

  1. Codebase   (static analysis — local path or GitHub URL)
  2. URL        (web vuln scan — https://target.com)
  3. Domain     (full recon — example.com)
  4. Everything (codebase + domain/URL combined)
"""


def run_wizard(args: Any) -> None:
    """Interactive plain-English wizard for target selection and scanning."""
    from config.consent import require_consent

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
        require_consent(args)

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
        prog="swiftsec",
        description="SWIFT — AI-powered vulnerability scanner (Kali + Playwright + Docker privesc)",
    )
    parser.add_argument("--version", action="version", version=f"swiftsec {__version__}")
    parser.add_argument("--yes", "-y", action="store_true",
                        help="Auto-confirm all interactive prompts (also: SWIFT_AUTO_CONFIRM=1)")
    parser.add_argument("--no-banner", action="store_true",
                        help="Suppress startup banner")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Minimal output (also suppresses banner)")
    parser.add_argument("--log-file", default=None,
                        help="Override step log file path (default: swift/log/steps.log.jsonl)")
    sub = parser.add_subparsers(dest="command", required=True)

    # ── Code analysis commands ─────────────────────────────────────────────
    scan = sub.add_parser("scan", help="Scan local repo for vulnerabilities")
    _add_shared_flags(scan)

    triage = sub.add_parser("triage", help="Fast triage scan (alias for scan)")
    _add_shared_flags(triage)

    r = sub.add_parser("report", help="Generate report from previous scan")
    _add_shared_flags(r, include_output=False)
    r.add_argument("--format", choices=["json", "markdown"], default="markdown")

    full = sub.add_parser("full", help="Full scan pipeline")
    _add_shared_flags(full)

    # ── Unified scanner ────────────────────────────────────────────────────
    fs = sub.add_parser("full-scan", help="Run code + Kali + CVE scan simultaneously")
    fs.add_argument("--repo", default=None, help="Local repo path for code scan")
    fs.add_argument("--target", default=None, help="Host/URL for Kali offensive scan")
    fs.add_argument("--tools", default=None, help="Comma-separated Kali tools (default: all)")
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
    feed.add_argument("--interval", type=int, default=7, help="Poll interval in seconds (NVD unauthed limit: 5 req/30s)")

    atk = sub.add_parser("attack-sim", help="MITRE ATT&CK-mapped exploit simulation")
    atk.add_argument("--target", required=True, help="Target IP, hostname, or URL")
    atk.add_argument(
        "--technique",
        default="all",
        help="MITRE technique ID (e.g. T1046) or 'all'",
    )
    atk.add_argument("--skip-build", action="store_true", help="Skip docker image build check")

    redteam = sub.add_parser("redteam", help="Full red-team pipeline (ROE required)")
    redteam.add_argument("--roe", required=True, help="Path to rules-of-engagement YAML")
    redteam.add_argument("--repo", default=None)
    redteam.add_argument("--target", default=None)
    redteam.add_argument("--phases", default="osint,active,chain,postex",
                         help="Comma-separated phases to run")
    redteam.add_argument("--max-runtime", type=int, default=1800)
    redteam.add_argument("--no-llm-payloads", action="store_true")

    osint = sub.add_parser("osint", help="OSINT recon: DNS, GitHub dorks, Shodan, WHOIS")
    osint.add_argument("--roe", required=True)
    osint.add_argument("--out", default="osint.json")

    sub.add_parser(
        "wizard",
        help="Interactive scanner wizard — choose codebase, URL, or domain in plain English",
    )

    web = sub.add_parser("web-scan", help="Playwright-driven live web vulnerability scan")
    web.add_argument("--target", required=True, help="HTTP(S) URL to scan")
    web.add_argument("--headed", action="store_true", help="Show browser (default: headless)")
    web.add_argument("--output-file", default=None, help="JSON report path")
    web.add_argument("--yes", "-y", action="store_true", default=argparse.SUPPRESS,
                     help="Auto-confirm all interactive prompts (also: SWIFT_AUTO_CONFIRM=1)")

    pe = sub.add_parser("privesc", help="Docker-based privilege escalation tester")
    pe.add_argument("--repo", required=True, help="Workspace path to mount into container")
    pe.add_argument("--yes", "-y", action="store_true", default=argparse.SUPPRESS,
                    help="Auto-confirm all interactive prompts (also: SWIFT_AUTO_CONFIRM=1)")
    pe.add_argument("--allow-privesc", action="store_true",
                    help="Required gate: enables SYS_PTRACE cap inside disposable container")
    pe.add_argument("--image", default="ubuntu:22.04")
    pe.add_argument("--timeout", type=int, default=120)
    pe.add_argument("--output-file", default=None)

    return parser


def run_web_scan(args: argparse.Namespace) -> dict[str, Any]:
    from browser.playwright_runner import scan_url
    from config.consent import require_consent

    require_consent(args)
    log_step("cli.web_scan.start", target=args.target, headed=args.headed)
    result = scan_url(args.target, headless=not args.headed)
    out = Path(args.output_file) if args.output_file else Path(f"web-scan-{uuid_safe(args.target)}.json")
    out.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    log_step("cli.web_scan.finish", target=args.target, findings=len(result.findings), artifact=str(out))
    return {
        "status": "ok",
        "target": args.target,
        "findings": len(result.findings),
        "artifact": str(out),
        "error": result.error,
    }


def run_privesc(args: argparse.Namespace) -> dict[str, Any]:
    from sandbox.privesc_runner import run_privesc_scan

    if not args.allow_privesc:
        _fail_closed("privesc requires --allow-privesc.")

    repo = Path(args.repo).resolve()
    artifacts_dir, _ = _artifact_paths(repo)
    log_step("cli.privesc.start", repo=str(repo), image=args.image)
    result = run_privesc_scan(
        repo_path=str(repo),
        artifacts_root=str(artifacts_dir / "privesc"),
        image=args.image,
        timeout=args.timeout,
        allow_ptrace=True,
    )
    out = Path(args.output_file) if args.output_file else (artifacts_dir / "privesc" / "result.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    log_step("cli.privesc.finish", repo=str(repo), findings=len(result.findings), artifact=str(out))
    return {
        "status": "ok" if result.success else "failed",
        "container_id": result.container_id,
        "findings": len(result.findings),
        "artifact": str(out),
        "errors": result.errors,
    }


def uuid_safe(s: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in s)[:48]


def main() -> None:
    from log.logger import get_logger
    from cli.repl import run_repl, NO_JSON_DUMP_CMDS
    logger = get_logger("swift.cli")

    parser = build_parser()

    if len(sys.argv) == 1:
        print_banner()
        handlers = {
            "scan": run_scan,
            "triage": run_triage,
            "report": run_report,
            "full": run_full,
            "full-scan": run_full_scan,
            "kali-scan": run_kali_scan,
            "live-feed": run_live_feed,
            "attack-sim": run_attack_sim,
            "wizard": run_wizard,
            "web-scan": run_web_scan,
            "privesc": run_privesc,
            "redteam": run_redteam,
            "osint": run_osint,
        }
        sys.exit(run_repl(parser, handlers))

    args = parser.parse_args()

    if should_show_banner(args, sys.argv):
        print_banner()

    if getattr(args, "log_file", None):
        set_step_log_path(args.log_file)

    log_step("cli.invoke", command=args.command, auto_confirmed=is_auto_confirmed(args))

    if hasattr(args, "config"):
        _load_config(args.config)

    if args.command not in {"kali-scan", "live-feed", "attack-sim", "full-scan",
                             "wizard", "web-scan", "privesc"}:
        _ensure_zero_trust(args)

    handlers = {
        "scan": run_scan,
        "triage": run_triage,
        "report": run_report,
        "full": run_full,
        "full-scan": run_full_scan,
        "kali-scan": run_kali_scan,
        "live-feed": run_live_feed,
        "attack-sim": run_attack_sim,
        "wizard": run_wizard,
        "web-scan": run_web_scan,
        "privesc": run_privesc,
        "redteam": run_redteam,
        "osint": run_osint,
    }
    try:
        payload = handlers[args.command](args)
        log_step("cli.complete", command=args.command)
        if args.command not in NO_JSON_DUMP_CMDS:
            print(json.dumps(payload, indent=2, sort_keys=True))
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
    except SystemExit:
        raise
    except (FileNotFoundError, PermissionError) as e:
        log_step("cli.error", error=str(e))
        print(f"swiftsec: {e}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        tb = traceback.format_exc()
        log_step("cli.fatal", error=str(e))
        logger.exception("fatal error")
        print(f"swiftsec: unexpected error: {e}\n  see log/swift.log for details", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
