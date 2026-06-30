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


_ERRORS = {
    "roe_not_found": (
        "ROE file not found.\n"
        "  Fix: swiftsec init --ctf juice-shop  (or create roe.yaml manually)"
    ),
    "api_key_missing": (
        "ANTHROPIC_API_KEY not set.\n"
        "  Fix: export ANTHROPIC_API_KEY=sk-ant-..."
    ),
    "target_unreachable": (
        "Target unreachable.\n"
        "  Fix: Is the target running? Try: docker run -p 3000:3000 bkimminich/juice-shop"
    ),
    "playwright_not_installed": (
        "Playwright not installed.\n"
        "  Fix: pip install 'swiftsec[web]' && playwright install chromium"
    ),
    "scan_json_not_found": (
        "scan.json not found.\n"
        "  Fix: Run a scan first: swiftsec web-scan <target>"
    ),
}


def _fail_closed(message: str) -> None:
    """Fail with a user-friendly error: problem + cause + fix."""
    import sys as _sys
    try:
        from rich.console import Console
        from rich.panel import Panel
        console = Console(stderr=True)
        console.print(Panel(f"[red][DENY][/red] {message}", title="SWIFT Error", border_style="red"))
    except ImportError:
        print(f"[DENY] {message}", file=_sys.stderr)
    raise SystemExit(1)


def _print_scan_summary(payload: dict[str, Any]) -> None:
    """Print Rich terminal summary of scan results."""
    try:
        from rich.console import Console
        from rich.table import Table
        console = Console()
        findings = payload.get("findings", [])
        count = len(findings) if isinstance(findings, list) else findings
        table = Table(title="Scan Summary")
        table.add_column("Status", style="green")
        table.add_column("Findings", style="yellow")
        table.add_row(payload.get("status", "ok"), str(count))
        console.print(table)
    except ImportError:
        pass  # rich not available, skip


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
    import warnings
    warnings.warn(
        "'triage' is deprecated and will be removed in v8. Use 'scan' instead.",
        DeprecationWarning, stacklevel=2,
    )
    return run_scan(args)


def run_redteam(args: argparse.Namespace) -> dict[str, Any]:
    """Full red-team pipeline: ROE → OSINT → code → web + Kali → exploit chains → post-exploit sim."""
    from pathlib import Path

    from agent.redteam_orchestrator import execute_redteam, save_redteam_artifact
    from config.consent import require_consent

    # Pre-flight: target reachability
    import httpx
    target_url = getattr(args, "target", None)
    if target_url:
        try:
            httpx.get(target_url, timeout=5.0)
        except Exception as e:
            _fail_closed(
                f"Target unreachable: {target_url}\n"
                f"  Cause: {e}\n"
                f"  Hint: Is the target running? Try: docker run -p 3000:3000 bkimminich/juice-shop"
            )

    require_consent(args)
    log_step("cli.redteam.start", roe=args.roe, target=getattr(args, "target", None),
             agentic=getattr(args, "agentic", False))

    if getattr(args, "agentic", False):
        from security.roe import load_roe
        from agent.redteam_agent import RedTeamAgent
        from agent.agent_prompts import AgentBudget
        import os
        roe = load_roe(args.roe)
        budget = AgentBudget(
            max_probe_calls=int(os.getenv("SWIFT_AGENT_BUDGET_PROBES", "50")),
            max_sonnet_calls=int(os.getenv("SWIFT_AGENT_BUDGET_SONNET", "20")),
            max_time_seconds=int(os.getenv("SWIFT_AGENT_BUDGET_SECONDS", "3600")),
        )
        agent = RedTeamAgent(target=args.target or "", roe=roe, budget=budget)
        result = asyncio.run(agent.run())
        return {
            "status": "ok",
            "mode": "agentic",
            "iterations": result.iterations,
            "findings": len(result.findings),
            "agent_log": str(result.agent_log_path),
        }

    payload = asyncio.run(execute_redteam(args))
    eng = payload.get("engagement_id", "engagement")
    out_path = (
        Path(args.output_file)
        if getattr(args, "output_file", None)
        else Path(f"redteam-{eng}.json")
    )
    save_redteam_artifact(payload, out_path)
    payload["artifact"] = str(out_path.resolve())
    log_step("cli.redteam.finish", artifact=str(out_path), status=payload.get("status"))
    # Rich terminal summary (suppress with --json flag)
    if not getattr(args, "json_output", False):
        _print_scan_summary(payload)
    return payload


def run_osint(args: argparse.Namespace) -> dict[str, Any]:
    """OSINT recon phase: DNS, subdomain, GitHub dorks, Shodan, WHOIS (ROE-scoped)."""
    from pathlib import Path

    from config.consent import require_consent
    from osint.runner import run_osint as run_osint_pipeline
    from security.roe import load_roe, validate_all

    require_consent(args)
    roe = load_roe(args.roe)
    validate_all(roe, args.target, "osint")
    log_step("cli.osint.start", target=args.target)
    result = asyncio.run(run_osint_pipeline(args.target, roe=roe))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    log_step("cli.osint.finish", artifact=str(out), findings=result.to_dict().get("total_findings"))
    return {"status": "ok", "artifact": str(out.resolve()), "target": args.target}


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
    import warnings
    warnings.warn(
        "'full' is deprecated and will be removed in v8. Use 'scan' instead.",
        DeprecationWarning, stacklevel=2,
    )
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
    redteam.add_argument("--repo", default=None, help="Local repo for static analysis / chaining")
    redteam.add_argument("--target", default=None, help="URL or host for OSINT, web scan, and Kali")
    redteam.add_argument("--phases", default="osint,active,chain,postex",
                         help="Comma-separated: osint, code, active, chain, postex")
    redteam.add_argument("--max-runtime", type=int, default=1800)
    redteam.add_argument("--no-llm-payloads", action="store_true",
                         help="Skip LLM chain narrative enhancement (deterministic chains only)")
    redteam.add_argument("--headed", action="store_true",
                         help="Run Playwright web probe with a visible browser")
    redteam.add_argument("--skip-build", action="store_true",
                         help="Skip Kali Docker image build check")
    redteam.add_argument("--output-file", default=None, help="Path for combined JSON report")
    redteam.add_argument(
        "--kali-tools",
        default=None,
        help="Comma-separated Kali tools (default: all). Example: nmap,nikto,nuclei",
    )
    redteam.add_argument(
        "--no-cve-snapshot",
        action="store_true",
        help="Skip one-shot NVD+KEV fetch used for correlation (faster / air-gapped)",
    )
    redteam.add_argument(
        "--allow-privesc",
        action="store_true",
        help="When phase 'privesc' is in --phases, run Docker privesc probes (requires --repo)",
    )
    redteam.add_argument("--privesc-image", default="ubuntu:22.04", help="Container image for privesc phase")
    redteam.add_argument("--privesc-timeout", type=int, default=120, help="Privesc container timeout seconds")
    # v6.0: agentic mode
    redteam.add_argument("--agentic", action="store_true",
                         help="Use Sonnet agentic loop instead of deterministic pipeline")
    redteam.add_argument("--json", dest="json_output", action="store_true",
                         help="JSON output only (no rich summary)")

    osint = sub.add_parser("osint", help="OSINT recon: DNS, GitHub dorks, Shodan, WHOIS")
    osint.add_argument("--roe", required=True)
    osint.add_argument("--target", required=True, help="Domain or URL in ROE scope")
    osint.add_argument("--out", default="osint.json")
    osint.add_argument("--full", action="store_true", help="Run full 10-source OSINT (includes crt.sh, wayback, tech fingerprint, email enum, subdomain takeover)")

    # ── Payload management ─────────────────────────────────────────────────
    payload_p = sub.add_parser("payload", help="Manage custom payload library")
    payload_sub = payload_p.add_subparsers(dest="payload_cmd", required=True)

    payload_add = payload_sub.add_parser("add", help="Add payloads from a file")
    payload_add.add_argument("filepath", help="Path to payload file (one payload per line)")
    payload_add.add_argument("--vuln-type", required=True, dest="vuln_type",
                             help="Vulnerability type (xss, sqli, ssrf, ssti, idor, etc.)")

    payload_list = payload_sub.add_parser("list", help="List registered payloads")
    payload_list.add_argument("--vuln-type", default=None, dest="vuln_type",
                              help="Filter by vulnerability type")

    payload_remove = payload_sub.add_parser("remove", help="Remove a payload")
    payload_remove.add_argument("--vuln-type", required=True, dest="vuln_type")
    payload_remove.add_argument("--payload", required=True, help="Exact payload string to remove")

    # ── Niche classifier ───────────────────────────────────────────────────
    niche_p = sub.add_parser("niche", help="Classify OWASP/CWE niches for a target via Sonnet")
    niche_p.add_argument("--roe", required=True, help="Path to ROE YAML")
    niche_p.add_argument("--target", required=True, help="Target domain or URL")
    niche_p.add_argument("--yes", "-y", action="store_true", default=argparse.SUPPRESS)

    # ── Chain executor ─────────────────────────────────────────────────────
    chain_p = sub.add_parser("chain", help="Replay an attack chain (ROE required, sandbox targets only)")
    chain_p.add_argument("--execute", required=True, dest="chain_id", metavar="CHAIN_ID",
                         help="Chain ID to execute (loads chain-<id>.json from --out-dir)")
    chain_p.add_argument("--roe", required=True, help="Path to ROE YAML (allow_chain_execution must be true)")
    chain_p.add_argument("--out-dir", default="output", dest="out_dir",
                         help="Directory containing chain JSON files and for saving evidence")

    sub.add_parser(
        "wizard",
        help="Interactive scanner wizard — choose codebase, URL, or domain in plain English",
    )

    ver = sub.add_parser("version", help="Show installed swiftsec version")
    ver.add_argument("--check", action="store_true", help="Check PyPI for a newer release")

    upd = sub.add_parser("update", help="Upgrade swiftsec to the latest release via pip")
    upd.add_argument("--check", action="store_true", help="Only check for updates, do not install")

    # ── Research subcommand (v7.1) ────────────────────────────────────────────
    research = sub.add_parser(
        "research",
        help="Claude-driven research over PUBLIC surface (docs, OSS, CVEs). No decompile, no live exploit.",
    )
    research.add_argument("--target", required=True,
                          help="Product / system under research (e.g. 'Burp Suite Pro')")
    research.add_argument("--focus", required=True,
                          help="Free-text research focus (e.g. 'project file untrusted mode')")
    research.add_argument("--roe", required=True,
                          help="Path to ROE YAML (must include 'research' in allowed_techniques)")
    research.add_argument("--max-iterations", type=int, default=20,
                          help="Max agent loop iterations (default: 20)")
    research.add_argument("--out-dir", default=None,
                          help="Output directory (default: ./research-out)")
    research.add_argument("--dry-run", action="store_true",
                          help="Print tool plan without making any API calls")

    web = sub.add_parser("web-scan", help="Playwright-driven live web vulnerability scan")
    web.add_argument("--target", required=True, help="HTTP(S) URL to scan")
    web.add_argument("--roe", required=True,
                     help="Path to rules-of-engagement YAML (must include rate_limit_rps)")
    web.add_argument("--headed", action="store_true", help="Show browser (default: headless)")
    web.add_argument("--output-file", default=None, help="JSON report path")
    web.add_argument("--live", action="store_true", help="Show live Rich TUI dashboard")
    web.add_argument("--json", dest="json_output", action="store_true", help="JSON output only (no rich summary)")
    web.add_argument("--yes", "-y", action="store_true", default=argparse.SUPPRESS,
                     help="Auto-confirm all interactive prompts (also: SWIFT_AUTO_CONFIRM=1)")

    # ── CTF / init wizard ─────────────────────────────────────────────────────
    init_p = sub.add_parser("init", help="Initialize ROE config (CTF preset or interactive wizard)")
    init_p.add_argument("--ctf", choices=["juice-shop", "dvwa", "metasploitable"], default=None,
                        help="CTF target preset")
    init_p.add_argument("--bugbounty", metavar="PROGRAM_JSON", default=None,
                        help="HackerOne program scope JSON")

    pe = sub.add_parser("privesc", help="Docker-based privilege escalation tester")
    pe.add_argument("--repo", required=True, help="Workspace path to mount into container")
    pe.add_argument("--yes", "-y", action="store_true", default=argparse.SUPPRESS,
                    help="Auto-confirm all interactive prompts (also: SWIFT_AUTO_CONFIRM=1)")
    pe.add_argument("--allow-privesc", action="store_true",
                    help="Required gate: enables SYS_PTRACE cap inside disposable container")
    pe.add_argument("--image", default="ubuntu:22.04")
    pe.add_argument("--timeout", type=int, default=120)
    pe.add_argument("--output-file", default=None)

    # v6.0: audit verify / export
    audit_p = sub.add_parser("audit", help="Audit log verification and export")
    audit_sub = audit_p.add_subparsers(dest="audit_cmd", required=True)
    av = audit_sub.add_parser("verify", help="Verify audit log hash chain integrity")
    av.add_argument("--log", required=True, help="Path to audit.jsonl file")
    ax = audit_sub.add_parser("export", help="Export audit log as Markdown report")
    ax.add_argument("--log", required=True, help="Path to audit.jsonl file")
    ax.add_argument("--out", required=True, help="Output Markdown path")

    # v6.0: plugin install / list / remove / validate
    plugin_p = sub.add_parser("plugin", help="Manage SWIFT probe plugins")
    plugin_sub = plugin_p.add_subparsers(dest="plugin_cmd", required=True)
    pi = plugin_sub.add_parser("install", help="Install a plugin from PyPI or local path")
    pi.add_argument("package", help="PyPI package name or local path")
    plugin_sub.add_parser("list", help="List registered plugins")
    pr = plugin_sub.add_parser("remove", help="Remove an installed plugin")
    pr.add_argument("name", help="Plugin module name")
    pv = plugin_sub.add_parser("validate", help="Validate a plugin without installing")
    pv.add_argument("path", help="Path to plugin Python file or package")

    # v6.0: agent-status
    agent_status_p = sub.add_parser("agent-status", help="Show live agentic engagement status")
    agent_status_p.add_argument(
        "--engagement-dir",
        default=None,
        help="Path to engagement dir (default: latest ~/.swift/engagements/*)",
    )

    auto_p = sub.add_parser(
        "auto",
        help="One-command auto mode: detect H1 program, validate scope, run pipeline, submit reports.",
    )
    auto_p.add_argument("--target", required=True, help="Full target URL (e.g. https://mystore.com).")
    auto_p.add_argument(
        "--h1-token",
        default=None,
        help="HackerOne API token. Falls back to H1_API_TOKEN env var.",
    )
    auto_p.add_argument(
        "--h1-identifier",
        default=None,
        help="HackerOne username. Falls back to H1_USERNAME env var.",
    )
    auto_p.add_argument("--out-dir", default="output", help="Output directory for reports and ROE.")
    auto_p.add_argument(
        "--min-confidence",
        type=float,
        default=0.9,
        help="Min finding confidence (0.0-1.0) for H1 submission (default: 0.9).",
    )
    auto_p.add_argument(
        "--h1-program",
        default=None,
        help="H1 program handle (e.g. shopify) to skip auto-discovery.",
    )

    # ── Intel engine ──────────────────────────────────────────────────────────
    intel_p = sub.add_parser("intel", help="Intel engine: sync, search, status, version")
    intel_sub = intel_p.add_subparsers(dest="intel_cmd", required=True)

    intel_sync = intel_sub.add_parser("sync", help="Sync intel from all 10 sources")
    intel_sync.add_argument("--sources", default=None,
                            help="Comma-separated source names (default: all)")
    intel_sync.add_argument("--force", action="store_true",
                            help="Force sync even if last sync was < 24h ago")
    intel_sync.add_argument("--dry-run", action="store_true",
                            help="Show what would be synced without writing")

    intel_search = intel_sub.add_parser("search", help="Search intel knowledge base")
    intel_search.add_argument("query", help="Search query")
    intel_search.add_argument("--n", type=int, default=10, help="Number of results")
    intel_search.add_argument("--output", choices=["json", "text"], default="text")

    intel_sub.add_parser("status", help="Show intel KB status (doc count, last sync)")

    intel_ver = intel_sub.add_parser("version", help="Intel KB version management")
    intel_ver.add_argument("--list", action="store_true", help="List versions")
    intel_ver.add_argument("--rollback", default=None, metavar="ID",
                           help="Roll back to version ID")

    # swiftsec_ai -- LLM ethical-hacker assistant (CVE RAG + tool-calling)
    ai_p = sub.add_parser("ai", help="LLM ethical-hacker assistant (live-CVE RAG + tool-calling)")
    ai_sub = ai_p.add_subparsers(dest="ai_cmd", required=True)
    ai_sub.add_parser("info", help="Show backend, model, and CVE store status")
    ai_sync = ai_sub.add_parser("sync", help="Incrementally sync the local NVD/CVE mirror")
    ai_sync.add_argument("--force", action="store_true", help="ignore the min sync interval")
    ai_sync.add_argument("--days", type=int, default=None, help="initial backfill window (days)")
    ai_ask = ai_sub.add_parser("ask", help="Ask the assistant a single question")
    ai_ask.add_argument("message", help="your question / instruction")
    ai_ask.add_argument("--roe", default=None, help="ROE yaml authorizing active tools")
    ai_repl = ai_sub.add_parser("repl", help="Interactive assistant loop")
    ai_repl.add_argument("--roe", default=None, help="ROE yaml authorizing active tools")
    ai_sched = ai_sub.add_parser(
        "schedule", help="Daily CVE auto-sync job (launchd on macOS, cron on Linux)")
    ai_sched.add_argument("action", choices=["install", "uninstall", "status"])
    ai_sched.add_argument("--hour", type=int, default=7, help="hour of day, 0-23 (default 7)")
    ai_sched.add_argument("--minute", type=int, default=0, help="minute, 0-59 (default 0)")
    ai_asm = ai_sub.add_parser(
        "ai-asm", help="Map a target's AI-specific attack surface (run before standard recon)")
    ai_asm.add_argument("target", help="host or URL")
    ai_asm.add_argument("--roe", default=None, help="ROE yaml authorizing active tools")
    ai_rt = ai_sub.add_parser(
        "ai-redteam", help="Send crafted attack prompts to an LLM endpoint and score responses")
    ai_rt.add_argument("endpoint", help="LLM endpoint URL")
    ai_rt.add_argument("--roe", default=None, help="ROE yaml authorizing active tools")
    ai_rt.add_argument(
        "--category", default="all",
        help="prompt_injection|jailbreak|data_exfil|indirect_injection|model_dos|hallucination_abuse|all")
    ai_rt.add_argument(
        "--confirm", action="store_true",
        help="explicit operator confirmation -- required, endpoint must be authorized for technique=exploit in the ROE")

    # v8.0 -- Decepticon + claude-bug-bounty merged subcommands
    from cli.v8 import register as _register_v8
    _register_v8(sub)

    return parser


def run_intel(args: argparse.Namespace) -> dict[str, Any]:
    """Intel engine CLI — sync, search, status, version."""
    subcmd = args.intel_cmd

    if subcmd == "sync":
        from intel.sync.scheduler import IntelSyncScheduler
        sources = [s.strip() for s in args.sources.split(",")] if args.sources else None
        if getattr(args, "dry_run", False):
            from intel.sync.scheduler import SOURCE_REGISTRY
            targets = sources or list(SOURCE_REGISTRY.keys())
            print(f"[dry-run] Would sync: {', '.join(targets)}")
            return {"status": "dry-run", "sources": targets}
        scheduler = IntelSyncScheduler()
        report = asyncio.run(scheduler.sync_all(sources=sources, force=args.force))
        return {
            "status": "ok",
            "sources_synced": report.sources_synced,
            "docs_added": report.docs_added,
            "errors": report.errors,
        }

    elif subcmd == "search":
        from intel.query.retriever import IntelRetriever
        r = IntelRetriever()
        results = r.query(args.query, n=args.n)
        if args.output == "json":
            return {"results": results}
        for i, res in enumerate(results, 1):
            meta = res.get("metadata", {})
            print(f"\n[{i}] {meta.get('title', '(no title)')} — {meta.get('source', '')}")
            print(res["content"][:300])
        return {"status": "ok", "count": len(results)}

    elif subcmd == "status":
        from intel.store.metadata_index import MetadataIndex
        idx = MetadataIndex()
        from intel.sync.scheduler import SOURCE_REGISTRY
        status_rows = []
        for source in SOURCE_REGISTRY:
            last = idx.get_last_sync(source)
            status_rows.append({
                "source": source,
                "last_synced": last.isoformat() if last else "never",
            })
        return {"status": "ok", "sources": status_rows}

    elif subcmd == "version":
        from intel.sync.version_tracker import IntelVersionTracker
        tracker = IntelVersionTracker()
        if args.rollback:
            tracker.rollback(args.rollback)
            return {"status": "ok", "rolled_back_to": args.rollback}
        versions = tracker.list_versions()
        if getattr(args, "list", False) or True:
            for v in versions:
                print(f"{v['version_id']}  {v['timestamp']}  docs={v.get('doc_count', '?')}")
        return {"status": "ok", "versions": versions}

    return {"status": "error", "message": f"Unknown intel subcommand: {subcmd}"}


def run_research(args: argparse.Namespace) -> dict[str, Any]:
    """Claude-driven research agent (v7.1). PUBLIC surface only.

    Loads ROE, validates 'research' technique is allowed, then drives a
    Sonnet tool-use loop that reads vendor docs / OSS code / CVE database and
    produces a hypothesis ledger + research playbook in markdown.
    """
    from security.roe import load_roe, assert_window_active, assert_technique_allowed
    from agent.research_agent import ResearchAgent

    roe = load_roe(args.roe)
    assert_window_active(roe)
    assert_technique_allowed(roe, "research")

    out_dir = Path(args.out_dir).resolve() if args.out_dir else (Path.cwd() / "research-out")
    log_step("cli.research.start", target=args.target, focus=args.focus,
             engagement_id=roe.engagement_id, max_iterations=args.max_iterations,
             dry_run=bool(args.dry_run))

    agent = ResearchAgent(
        target=args.target,
        focus=args.focus,
        roe=roe,
        max_iterations=args.max_iterations,
        engagement_dir=out_dir,
        dry_run=bool(args.dry_run),
    )
    result = asyncio.run(agent.run())
    log_step("cli.research.finish",
             target=args.target,
             status=result.get("status"),
             iterations=result.get("iterations"),
             hypotheses=len(result.get("hypotheses", [])))
    return result


def run_web_scan(args: argparse.Namespace) -> dict[str, Any]:
    from browser.playwright_runner import scan_url
    from config.consent import require_consent

    # Pre-flight: target reachability
    import httpx
    target_url = getattr(args, "target", None)
    if target_url:
        try:
            httpx.get(target_url, timeout=5.0)
        except Exception as e:
            _fail_closed(
                f"Target unreachable: {target_url}\n"
                f"  Cause: {e}\n"
                f"  Hint: Is the target running? Try: docker run -p 3000:3000 bkimminich/juice-shop"
            )

    # Pre-flight: Playwright availability
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            p.chromium.executable_path  # just probe it
    except Exception:
        _fail_closed(
            "Playwright not installed.\n"
            "  Fix: pip install 'swiftsec[web]' && playwright install chromium"
        )

    require_consent(args)

    # Support --live flag for TUI mode
    if getattr(args, "live", False):
        from events.bus import get_bus
        from cli.tui import ScanTUI
        bus = get_bus()
        tui = ScanTUI(bus)
        return tui.run(_do_web_scan, args)

    return _do_web_scan(args)


def _do_web_scan(args: argparse.Namespace) -> dict[str, Any]:
    """Inner web scan logic (separated for TUI wrapping)."""
    from browser.playwright_runner import scan_url
    from browser.rate_gate import AsyncRateGate
    from security.roe import load_roe, assert_target_in_scope, assert_window_active, assert_technique_allowed

    # ROE gate: load + validate (fail-closed)
    roe = load_roe(args.roe)
    assert_window_active(roe)
    assert_target_in_scope(roe, args.target)
    assert_technique_allowed(roe, "active_scan")

    if roe.rate_limit_rps is None:
        _fail_closed(
            f"ROE '{roe.engagement_id}' is missing required field `rate_limit_rps` for web-scan.\n"
            f"  Add to {args.roe}:  rate_limit_rps: 1   (or program-appropriate value)"
        )

    gate = AsyncRateGate(rps=roe.rate_limit_rps, burst=roe.rate_limit_burst)
    log_step("cli.web_scan.start", target=args.target, headed=args.headed,
             rate_limit_rps=roe.rate_limit_rps, rate_limit_burst=roe.rate_limit_burst,
             engagement_id=roe.engagement_id)
    result = scan_url(args.target, headless=not args.headed, rate_gate=gate)
    out = Path(args.output_file) if args.output_file else Path(f"web-scan-{uuid_safe(args.target)}.json")
    out.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    log_step("cli.web_scan.finish", target=args.target, findings=len(result.findings), artifact=str(out))
    payload = {
        "status": "ok",
        "target": args.target,
        "findings": len(result.findings),
        "artifact": str(out),
        "error": result.error,
    }
    # Rich terminal summary (suppress with --json flag)
    if not getattr(args, "json_output", False):
        _print_scan_summary(payload)
    return payload


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


# ─── WS5/WS6 CLI Handlers ─────────────────────────────────────────────────────

def run_payload(args: argparse.Namespace) -> dict[str, Any]:
    """Manage custom payload library: add, list, or remove payloads."""
    from browser.payload_library import PayloadLibrary

    lib = PayloadLibrary()
    subcmd = args.payload_cmd

    if subcmd == "add":
        from browser.payload_uploader import upload_payloads
        result = upload_payloads(args.filepath, args.vuln_type)
        return {"status": "ok", "added": result}

    if subcmd == "list":
        vuln_type = getattr(args, "vuln_type", None)
        payloads = lib.list_payloads(vuln_type=vuln_type)
        return {"status": "ok", "payloads": payloads}

    if subcmd == "remove":
        removed = lib.remove_payload(vuln_type=args.vuln_type, payload=args.payload)
        return {"status": "ok", "removed": removed}

    _fail_closed(f"Unknown payload subcommand: {subcmd}")


def run_niche(args: argparse.Namespace) -> dict[str, Any]:
    """Run OSINT then classify niches for a target."""
    from config.consent import require_consent
    from security.roe import load_roe, validate_all
    from osint.runner import run_osint as run_osint_pipeline

    require_consent(args)
    roe = load_roe(args.roe)
    validate_all(roe, args.target, "osint")
    log_step("cli.niche.start", target=args.target)

    osint_result = asyncio.run(run_osint_pipeline(args.target, roe=roe))

    try:
        from agent.niche_classifier import classify_niches
        import anthropic
        client = anthropic.Anthropic()
        profile = asyncio.run(classify_niches(args.target, osint_result, client=client))
        profile_dict = profile.__dict__ if hasattr(profile, "__dict__") else str(profile)
    except Exception as exc:  # noqa: BLE001
        log_step("cli.niche.error", err=str(exc), level="warning")
        profile_dict = {"error": str(exc)}

    log_step("cli.niche.finish", target=args.target)
    print(json.dumps(profile_dict, indent=2, default=str))
    return {"status": "ok", "target": args.target, "niche_profile": profile_dict}


def run_version(args: argparse.Namespace) -> dict[str, Any]:
    """Show current version and optionally check PyPI for updates."""
    from swift import __version__

    print(f"swiftsec {__version__}")

    if getattr(args, "check", False):
        import urllib.request
        import urllib.error
        try:
            url = "https://pypi.org/pypi/swiftsec/json"
            with urllib.request.urlopen(url, timeout=5) as resp:
                import json as _json
                data = _json.loads(resp.read())
            latest = data["info"]["version"]
            if latest == __version__:
                print(f"Up to date (latest: {latest})")
            else:
                print(f"Update available: {latest}  →  run: swiftsec update")
        except urllib.error.URLError as exc:
            print(f"Could not reach PyPI: {exc}", file=sys.stderr)

    return {"version": __version__}


def _get_editable_source() -> str | None:
    """Return the local source path if swiftsec is an editable install, else None."""
    try:
        import importlib.metadata as meta
        dist = meta.distribution("swiftsec")
        direct_url = dist.read_text("direct_url.json")
        if direct_url:
            import json as _json
            data = _json.loads(direct_url)
            if data.get("dir_info", {}).get("editable") and data.get("url", "").startswith("file://"):
                return data["url"][len("file://"):]
    except Exception:  # noqa: BLE001
        pass
    return None


def run_init(args: argparse.Namespace) -> dict[str, Any]:
    """Initialize ROE config — CTF preset or interactive wizard."""
    import yaml  # type: ignore[import]

    ctf_name = getattr(args, "ctf", None)
    bugbounty_path = getattr(args, "bugbounty", None)

    if ctf_name:
        from config.ctf_targets import CTF_TARGETS
        if ctf_name not in CTF_TARGETS:
            valid = ", ".join(CTF_TARGETS.keys())
            _fail_closed(f"Unknown CTF target: {ctf_name}. Valid options: {valid}")
        target_cfg = CTF_TARGETS[ctf_name]
        roe = {
            "version": "1.0",
            "name": target_cfg["name"],
            "target": target_cfg["default_url"],
            "techniques": target_cfg["techniques"],
            **target_cfg["roe_template"],
        }
        out = Path("roe.yaml")
        out.write_text(yaml.dump(roe, default_flow_style=False), encoding="utf-8")
        print(f"[SWIFT] ROE config written to {out}")
        print(f"[SWIFT] Start target with: {target_cfg['docker_hint']}")
        return {"status": "ok", "roe": str(out), "target": target_cfg["default_url"]}

    if bugbounty_path:
        from config.hackerone_validator import load_scope, extract_in_scope_domains
        scope_data = load_scope(bugbounty_path)
        domains = extract_in_scope_domains(scope_data)
        roe = {
            "version": "1.0",
            "name": f"Bug Bounty: {bugbounty_path}",
            "scope": domains,
            "allow_web_probes": True,
            "allow_chain_execution": False,
        }
        out = Path("roe.yaml")
        out.write_text(yaml.dump(roe, default_flow_style=False), encoding="utf-8")
        print(f"[SWIFT] ROE config written to {out}")
        print(f"[SWIFT] In-scope domains: {domains}")
        return {"status": "ok", "roe": str(out), "scope": domains}

    # Interactive wizard (no --ctf or --bugbounty)
    try:
        from rich.prompt import Prompt, Confirm
        target_url = Prompt.ask("Target URL", default="http://localhost:3000")
        techniques_str = Prompt.ask("Techniques (comma-sep)", default="xss,sqli,idor")
        allow_chain = Confirm.ask("Allow chain execution?", default=False)
    except ImportError:
        target_url = input("Target URL [http://localhost:3000]: ").strip() or "http://localhost:3000"
        techniques_str = input("Techniques (comma-sep) [xss,sqli,idor]: ").strip() or "xss,sqli,idor"
        allow_chain = input("Allow chain execution? [y/N]: ").strip().lower() == "y"

    techniques = [t.strip() for t in techniques_str.split(",") if t.strip()]
    roe = {
        "version": "1.0",
        "name": "Custom Target",
        "target": target_url,
        "techniques": techniques,
        "scope": [target_url],
        "allow_web_probes": True,
        "allow_chain_execution": allow_chain,
    }
    out = Path("roe.yaml")
    out.write_text(yaml.dump(roe, default_flow_style=False), encoding="utf-8")
    print(f"[SWIFT] ROE config written to {out}")
    return {"status": "ok", "roe": str(out), "target": target_url}


def run_update(args: argparse.Namespace) -> dict[str, Any]:
    """Upgrade swiftsec via local source reinstall, pipx, or pip."""
    import shutil
    import subprocess

    check_only = getattr(args, "check", False)

    if check_only:
        import types
        v_args = types.SimpleNamespace(check=True)
        return run_version(v_args)

    source_path = _get_editable_source()
    in_pipx = ".local/pipx/venvs" in sys.executable or "pipx" in sys.executable

    if source_path and in_pipx and shutil.which("pipx"):
        # Editable source install via pipx — reinstall from local source
        print(f"Reinstalling swiftsec from local source: {source_path}")
        result = subprocess.run(
            ["pipx", "install", source_path, "--force"],
            capture_output=False,
        )
    elif source_path:
        # Editable source install via pip
        print(f"Reinstalling swiftsec from local source: {source_path}")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--force-reinstall", source_path],
            capture_output=False,
        )
    elif in_pipx and shutil.which("pipx"):
        print("Upgrading swiftsec via pipx...")
        result = subprocess.run(["pipx", "upgrade", "swiftsec"], capture_output=False)
    else:
        print("Upgrading swiftsec via pip...")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade", "swiftsec"],
            capture_output=False,
        )

    if result.returncode != 0:
        print("Upgrade failed.", file=sys.stderr)
        sys.exit(result.returncode)

    from swift import __version__
    print(f"\nswiftsec upgraded successfully → {__version__}")
    return {"status": "ok"}


def run_chain_execute(args: argparse.Namespace) -> dict[str, Any]:
    """Load a chain from output dir and execute it (ROE required)."""
    from security.roe import load_roe
    from agent.chain_executor import execute_chain

    roe = load_roe(args.roe)
    chain_id = args.chain_id

    chain_file = Path(args.out_dir) / f"chain-{chain_id}.json"
    if not chain_file.exists():
        _fail_closed(f"Chain file not found: {chain_file}")

    chain_data = json.loads(chain_file.read_text(encoding="utf-8"))
    log_step("cli.chain_execute.start", chain_id=chain_id)
    result = asyncio.run(execute_chain(chain_data, roe, out_dir=args.out_dir))
    log_step("cli.chain_execute.finish", chain_id=chain_id, validated=result.validated)
    return {
        "status": "ok",
        "chain_id": result.chain_id,
        "validated": result.validated,
        "steps_attempted": result.steps_attempted,
        "steps_succeeded": result.steps_succeeded,
        "evidence": result.evidence,
        "error": result.error,
    }


def run_auto(args: argparse.Namespace) -> dict[str, Any]:
    """Run the full auto-mode workflow against an H1 program target."""
    import os
    from auto_workflow import run_auto_workflow

    h1_token = args.h1_token or os.environ.get("H1_API_TOKEN", "")
    h1_username = args.h1_identifier or os.environ.get("H1_USERNAME", "")

    if not h1_token:
        _fail_closed("H1 API token required. Pass --h1-token or set H1_API_TOKEN env var.")
    if not h1_username:
        _fail_closed("H1 username required. Pass --h1-identifier or set H1_USERNAME env var.")

    result = asyncio.run(
        run_auto_workflow(
            args.target,
            h1_token,
            h1_username,
            min_confidence=args.min_confidence,
            out_dir=args.out_dir,
            program_handle=getattr(args, "h1_program", None),
        )
    )
    return {
        "status": "ok",
        "target": result.target,
        "program": result.program_handle,
        "findings_total": result.findings_total,
        "findings_submitted": result.findings_submitted,
        "h1_report_urls": result.h1_report_urls,
        "elapsed_seconds": result.elapsed_seconds,
        "engagement_id": result.engagement_id,
    }


def run_ai(args: argparse.Namespace) -> dict[str, Any]:
    """swiftsec ai — LLM ethical-hacker assistant with live-CVE RAG + tool-calling.

    Wires the real SWIFTSEC callables (ROE/scope, OSINT recon, web scan, H1 report)
    into the swiftsec_ai assistant. Active tools stay ROE-gated; reports are drafted
    only, never auto-submitted.
    """
    import json as _json
    from pathlib import Path as _Path
    from datetime import datetime as _dt, timezone as _tz

    from swiftsec_ai import SwiftSecAssistant
    from swiftsec_ai.config import load_settings as _load_settings
    from bounty.report_formats import format_report as _format_report

    # Scheduling needs no LLM backend / CVE store — handle it up front.
    if getattr(args, "ai_cmd", None) == "schedule":
        from swiftsec_ai import schedule as _schedule
        action = args.action
        if action == "install":
            result = _schedule.install(hour=args.hour, minute=args.minute)
        elif action == "uninstall":
            result = _schedule.uninstall()
        else:
            result = _schedule.status()
        print(json.dumps(result, indent=2))
        return {"status": "ok", "command": "ai", "ai_cmd": "schedule", "action": action}

    roe_path = getattr(args, "roe", None)

    def _roe_adapter(target: str, technique: str = "active_scan") -> dict[str, Any]:
        """Non-fatal scope verdict (never sys.exit, unlike the assert_* helpers)."""
        if not roe_path or not _Path(roe_path).exists():
            return {"in_scope": False, "reason": "no valid ROE file (pass --roe <roe.yaml>)"}
        try:
            from security.roe import load_roe, assert_technique_allowed, ROEViolation
            roe = load_roe(roe_path)
            tl = target.lower()
            in_scope = any(
                tl == a or tl.startswith(a) or a in tl
                for a in (str(x).lower() for x in roe.authorized_targets)
            )
            if not in_scope:
                return {"in_scope": False,
                        "reason": f"{target} not in authorized_targets {roe.authorized_targets}"}
            now = _dt.now(_tz.utc)
            if now < roe.window_start or now > roe.window_end:
                return {"in_scope": False, "reason": "engagement window not active"}
            try:
                assert_technique_allowed(roe, technique, raise_on_violation=True)
            except ROEViolation as e:
                return {"in_scope": False, "reason": str(e)}
            return {"in_scope": True, "reason": f"authorized by ROE {roe.engagement_id}"}
        except SystemExit as e:
            return {"in_scope": False, "reason": f"ROE load failed: {e}"}

    def _recon_adapter(target: str):
        from osint.runner import run_osint as _osint_run
        return _osint_run(target)  # coroutine; tools layer awaits it

    def _scanner_adapter(target: str):
        from browser.playwright_runner import scan_url
        from browser.rate_gate import AsyncRateGate
        gate = None
        if roe_path and _Path(roe_path).exists():
            try:
                from security.roe import load_roe
                roe = load_roe(roe_path)
                if roe.rate_limit_rps:
                    gate = AsyncRateGate(rps=roe.rate_limit_rps, burst=roe.rate_limit_burst)
            except SystemExit:
                pass
        return scan_url(target, headless=True, rate_gate=gate)

    settings = _load_settings()
    assistant = SwiftSecAssistant(
        settings,
        roe=_roe_adapter,
        recon=_recon_adapter,
        scanner=_scanner_adapter,
        h1=lambda d: _format_report("h1", d),
    )
    try:
        cmd = getattr(args, "ai_cmd", None)
        if cmd == "info":
            print(_json.dumps(assistant.info(), indent=2))
        elif cmd == "sync":
            print(_json.dumps(
                assistant.update_cves(force=args.force, initial_days=args.days), indent=2))
        elif cmd == "ask":
            print(assistant.ask(args.message))
        elif cmd == "repl":
            print("SWIFTSEC-AI REPL — type 'exit' or Ctrl-D to quit.")
            while True:
                try:
                    line = input("swiftsec-ai> ").strip()
                except (EOFError, KeyboardInterrupt):
                    print()
                    break
                if line.lower() in {"exit", "quit"}:
                    break
                if line:
                    print(assistant.ask(line))
        elif cmd == "ai-asm":
            from log.audit import log_step
            verdict = _roe_adapter(args.target, "active_scan")
            if not verdict.get("in_scope"):
                print(_json.dumps({"error": f"REFUSED: {args.target} not authorized", **verdict}, indent=2))
                return {"status": "refused", "command": "ai", "ai_cmd": cmd}
            from swiftsec_ai.ai_asm import run_ai_asm
            result = run_ai_asm(args.target)
            log_step("ai_asm", target=args.target, surfaces=result["tier1_count"])
            print(_json.dumps(result, indent=2))
        elif cmd == "ai-redteam":
            from log.audit import log_step
            if not args.confirm:
                print(_json.dumps(
                    {"error": "REFUSED: --confirm required -- operator must explicitly opt in"},
                    indent=2))
                return {"status": "refused", "command": "ai", "ai_cmd": cmd}
            verdict = _roe_adapter(args.endpoint, "exploit")
            if not verdict.get("in_scope"):
                print(_json.dumps({"error": f"REFUSED: {args.endpoint} not authorized for exploit", **verdict}, indent=2))
                return {"status": "refused", "command": "ai", "ai_cmd": cmd}
            from swiftsec_ai.redteam import AIRedTeamer
            result = AIRedTeamer().run(args.endpoint, category=args.category, confirmed=True)
            log_step("ai_redteam", endpoint=args.endpoint, findings=len(result["findings_queued"]))
            print(_json.dumps(result, indent=2))
        return {"status": "ok", "command": "ai", "ai_cmd": cmd}
    finally:
        assistant.close()


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
            "payload": run_payload,
            "niche": run_niche,
            "chain": run_chain_execute,
            "version": run_version,
            "update": run_update,
            "auto": run_auto,
            "init": run_init,
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

    _V6_NO_ZERO_TRUST = {"audit", "plugin", "agent-status"}
    from cli.v8 import ZERO_TRUST_EXEMPT as _V8_EXEMPT
    if args.command not in {"kali-scan", "live-feed", "attack-sim", "full-scan",
                             "wizard", "web-scan", "privesc", "redteam", "osint",
                             "payload", "niche", "chain", "version", "update", "auto",
                             "init", "ai"} | _V6_NO_ZERO_TRUST | _V8_EXEMPT:
        _ensure_zero_trust(args)

    # v6.0 commands handled inline (no JSON dump)
    if args.command == "audit":
        from audit.cli import run_verify, run_export
        {"verify": run_verify, "export": run_export}[args.audit_cmd](args)
        return

    if args.command == "plugin":
        from sdk.cli import run_install, run_list, run_remove, run_validate
        {"install": run_install, "list": run_list, "remove": run_remove,
         "validate": run_validate}[args.plugin_cmd](args)
        return

    if args.command == "agent-status":
        from agent.redteam_agent import show_agent_status
        show_agent_status(args)
        return

    if args.command == "intel":
        payload = run_intel(args)
        if args.command not in NO_JSON_DUMP_CMDS:
            print(json.dumps(payload, indent=2, sort_keys=True))
        return

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
        "payload": run_payload,
        "niche": run_niche,
        "chain": run_chain_execute,
        "version": run_version,
        "update": run_update,
        "auto": run_auto,
        "intel": run_intel,
        "init": run_init,
        "research": run_research,
        "ai": run_ai,
    }
    # v8.0 -- merge in Decepticon + claude-bug-bounty subcommand handlers
    from cli.v8 import HANDLERS as _V8_HANDLERS, NO_JSON_DUMP as _V8_NO_JSON
    handlers.update(_V8_HANDLERS)
    no_json_dump = NO_JSON_DUMP_CMDS | _V8_NO_JSON | {"ai"}  # ai prints its own output
    try:
        payload = handlers[args.command](args)
        log_step("cli.complete", command=args.command)
        if args.command not in no_json_dump:
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
