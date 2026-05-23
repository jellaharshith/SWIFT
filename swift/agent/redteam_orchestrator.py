"""Full red-team engagement: parallel recon, active probes, CVE correlation, chaining, post-ex."""
from __future__ import annotations

import asyncio
import json
import sys
import time
from argparse import Namespace
from dataclasses import asdict
from pathlib import Path
from typing import Any, Optional

from agent.correlator import Correlator
from agent.models import ExploitChain, MergedFinding, ScanResult, Vulnerability
from chains.detector import ExploitChainDetector
from config.settings import get_config
from feeds.live_cve import CVEEntry, LiveCVEFeed
from log.audit import log_step
from post_exploit.c2_sim import simulate_c2
from post_exploit.data_exfil_sim import simulate_data_exfil
from post_exploit.persistence_sim import simulate_persistence
from security.roe import ROE, assert_target_in_scope, assert_technique_allowed, assert_window_active


def parse_phases(phases_csv: str) -> set[str]:
    return {p.strip().lower() for p in phases_csv.split(",") if p.strip()}


def phases_need_network_target(phases: set[str]) -> bool:
    return bool(phases & {"osint", "active"})


def effective_phases(args: Namespace) -> set[str]:
    phases = parse_phases(args.phases)
    repo = getattr(args, "repo", None)
    if repo and "chain" in phases and "code" not in phases:
        phases = set(phases)
        phases.add("code")
    return phases


def browser_kind_to_vuln_type(kind: str) -> str:
    k = (kind or "").lower()
    if "xss" in k:
        return "xss"
    if "sql" in k or "sqli" in k:
        return "sql_injection"
    if "ssti" in k:
        return "command_injection"
    if "idor" in k:
        return "insecure_direct_object"
    if "jwt" in k or "auth" in k:
        return "auth_bypass"
    if "nosql" in k:
        return "nosql_injection"
    if "prototype" in k:
        return "unsafe_deserialization"
    if "xxe" in k:
        return "xxe"
    if "crlf" in k or "smuggling" in k:
        return "information_disclosure"
    if "ssrf" in k:
        return "ssrf"
    return "information_disclosure"


def browser_findings_to_vulnerabilities(findings: list[Any], default_target: str) -> list[Vulnerability]:
    from browser.playwright_runner import BrowserFinding

    out: list[Vulnerability] = []
    for i, f in enumerate(findings):
        if not isinstance(f, BrowserFinding):
            continue
        sev = (f.severity or "HIGH").upper()
        if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            sev = "HIGH"
        vt = browser_kind_to_vuln_type(f.kind)
        url = getattr(f, "url", None) or default_target
        out.append(
            Vulnerability(
                id=f"WEB-{i + 1:03d}",
                file_path=url,
                line_number=0,
                vuln_type=vt,
                description=f"{f.kind}: {f.evidence[:400]}",
                confidence=0.96,
                severity=sev,
                code_snippet=(f.payload or f.evidence)[:800],
                status="CONFIRMED",
            )
        )
    return out


_TOOL_TO_VULN = {
    "nmap": "information_disclosure",
    "masscan": "information_disclosure",
    "nikto": "information_disclosure",
    "sqlmap": "sql_injection",
    "nuclei": "information_disclosure",
    "gobuster": "information_disclosure",
    "searchsploit": "information_disclosure",
    "wfuzz": "information_disclosure",
    "ffuf": "information_disclosure",
    "httpx": "information_disclosure",
    "subfinder": "information_disclosure",
    "amass": "information_disclosure",
    "feroxbuster": "information_disclosure",
}


def kali_rows_to_vulnerabilities(kali_only: list[dict]) -> list[Vulnerability]:
    """Turn unmatched Kali tool rows into synthetic Vulnerabilities for graph chaining."""
    out: list[Vulnerability] = []
    for idx, kf in enumerate(kali_only):
        tool = str(kf.get("tool") or "kali")
        vt = _TOOL_TO_VULN.get(tool, "information_disclosure")
        blob = (kf.get("output") or "")[:2000]
        sev = "MEDIUM"
        blob_l = blob.lower()
        if "critical" in blob_l or "sql injection" in blob_l or "cve-20" in blob_l:
            sev = "HIGH"
        if "0 critical" in blob_l and "critical" not in blob_l:
            sev = "MEDIUM"
        out.append(
            Vulnerability(
                id=f"KALI-{tool.upper()}-{idx + 1:03d}",
                file_path=str(kf.get("target") or "network"),
                line_number=0,
                vuln_type=vt,
                description=f"Kali/{tool} signal (correlator kali-only row)",
                confidence=0.72,
                severity=sev,
                code_snippet=blob[:1200],
                status="REVIEW_REQUIRED",
            )
        )
    return out


def _chains_to_jsonable(chains: list[ExploitChain]) -> list[dict[str, Any]]:
    return [asdict(c) for c in chains]


def _merged_to_jsonable(merged: list[MergedFinding]) -> list[dict[str, Any]]:
    return [asdict(m) for m in merged]


def _all_cve_matches_from_merged(merged: list[MergedFinding]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for mf in merged:
        for cm in mf.cve_matches:
            rows.append(
                {
                    "matched_finding_id": cm.matched_finding_id,
                    "match_reason": cm.match_reason,
                    "confidence": cm.confidence,
                    "cve": asdict(cm.cve),
                }
            )
    return rows


async def _cve_snapshot() -> list[CVEEntry]:
    feed = LiveCVEFeed()
    try:
        return await feed.snapshot_recent()
    finally:
        await feed.close()


def _credential_summary_from_web(web_session_path: str | None) -> dict[str, Any]:
    if not web_session_path:
        return {"available": False}
    p = Path(web_session_path)
    if not p.is_file():
        return {"available": False, "path": web_session_path}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return {"available": True, "path": str(p), "summary": data}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": str(exc)}


async def execute_redteam(args: Namespace) -> dict[str, Any]:
    from agent.unified_orchestrator import _run_kali_scan
    from browser.playwright_runner import BrowserScanResult, scan_url_async
    from osint.runner import OsintResult, run_osint as run_osint_pipeline
    from security.roe import load_roe

    started = time.monotonic()
    roe: ROE = load_roe(args.roe)
    assert_window_active(roe)

    phases = effective_phases(args)
    target: Optional[str] = getattr(args, "target", None) or None
    repo: Optional[str] = getattr(args, "repo", None)
    if phases_need_network_target(phases) and not target:
        print(
            "[DENY] redteam: --target is required for network phases "
            f"(osint/active). Phases={sorted(phases)}",
            file=sys.stderr,
        )
        sys.exit(2)

    if ("code" in phases or "chain" in phases) and not repo:
        if "code" in parse_phases(args.phases):
            print("[DENY] redteam: --repo is required when phase 'code' is selected.", file=sys.stderr)
            sys.exit(2)

    max_rt = min(int(getattr(args, "max_runtime", 1800) or 1800), int(roe.max_runtime_seconds))
    deadline = time.monotonic() + max_rt
    skip_build = bool(getattr(args, "skip_build", False))
    want_cve = not bool(getattr(args, "no_cve_snapshot", False))
    kali_tools = None
    if getattr(args, "kali_tools", None):
        kali_tools = [t.strip() for t in args.kali_tools.split(",") if t.strip()]

    out: dict[str, Any] = {
        "status": "ok",
        "engagement_id": roe.engagement_id,
        "roe_sha256": roe.roe_sha256,
        "phases": sorted(phases),
        "target": target,
        "repo": repo,
        "max_runtime_seconds": max_rt,
        "results": {},
        "errors": [],
    }
    merged: list[MergedFinding] = []
    code_only: list[Vulnerability] = []
    kali_only: list[dict] = []

    def time_left() -> float:
        return deadline - time.monotonic()

    code_scan: ScanResult | None = None
    osint_dict: dict[str, Any] | None = None
    cve_entries: list[CVEEntry] = []

    # --- Parallel recon: OSINT + code scan + CVE snapshot ---
    if time_left() > 0 and (
        ("osint" in phases and target)
        or ("code" in phases and repo)
        or want_cve
    ):
        log_step("redteam.parallel", stage="recon_cve")

        async def _osint() -> tuple[str, Any]:
            if "osint" not in phases or not target:
                return "osint", None
            assert_target_in_scope(roe, target)
            assert_technique_allowed(roe, "osint")
            log_step("redteam.phase.start", phase="osint", target=target)
            r = await run_osint_pipeline(target, roe=roe)
            return "osint", r

        async def _cve() -> tuple[str, Any]:
            if not want_cve:
                return "cve", []
            log_step("redteam.phase.start", phase="cve_snapshot")
            try:
                rows = await _cve_snapshot()
                return "cve", rows
            except Exception as exc:  # noqa: BLE001
                out["errors"].append(f"cve_snapshot: {exc}")
                return "cve", []

        recon_tasks = [_osint(), _code(), _cve()]
        recon_raw = await asyncio.gather(*recon_tasks, return_exceptions=True)
        for item in recon_raw:
            if isinstance(item, BaseException):
                out["errors"].append(f"recon: {item}")
                continue
            key, val = item
            if key == "osint" and val is not None:
                assert isinstance(val, OsintResult)
                osint_dict = val.to_dict()
                out["results"]["osint"] = osint_dict
            elif key == "code" and val is not None:
                assert isinstance(val, ScanResult)
                code_scan = val
                out["results"]["code"] = {
                    "scan_id": code_scan.scan_id,
                    "vulnerabilities": len(code_scan.vulnerabilities),
                    "exploit_chains_from_code_scan": _chains_to_jsonable(code_scan.exploit_chains),
                    "duration_seconds": code_scan.duration_seconds,
                }
            elif key == "cve":
                cve_entries = list(val) if isinstance(val, list) else []

    web_result: BrowserScanResult | None = None
    kali_report: dict[str, Any] | None = None

    # --- Parallel active: Playwright + Kali ---
    if "active" in phases and target and time_left() > 0:
        assert_target_in_scope(roe, target)
        log_step("redteam.parallel", stage="active_web_kali")

        async def _web() -> BrowserScanResult | None:
            if "active_scan" not in roe.allowed_techniques:
                return None
            log_step("redteam.phase.start", phase="active.web", target=target)
            return await scan_url_async(
                target, headless=not getattr(args, "headed", False), mode="pentester"
            )

        async def _kali() -> dict[str, Any] | None:
            if "exploit" not in roe.allowed_techniques:
                return None
            if time_left() <= 1:
                return None
            log_step("redteam.phase.start", phase="active.kali", target=target)
            return await _run_kali_scan(target, kali_tools, skip_build=skip_build)

        try:
            w, k = await asyncio.gather(_web(), _kali())
            if isinstance(w, BaseException):
                out["errors"].append(f"web_scan: {w}")
                out["results"]["web_scan"] = {"error": str(w)}
            elif w is not None:
                web_result = w
                out["results"]["web_scan"] = w.to_dict()
            elif "active_scan" not in roe.allowed_techniques:
                out["results"]["web_scan"] = {"skipped": True, "reason": "active_scan not in ROE"}
            if isinstance(k, BaseException):
                out["errors"].append(f"kali_scan: {k}")
                out["results"]["kali_scan"] = {"error": str(k)}
            elif k is not None:
                kali_report = k
                out["results"]["kali_scan"] = k
            elif "exploit" not in roe.allowed_techniques:
                out["results"]["kali_scan"] = {"skipped": True, "reason": "exploit not in ROE"}
        except Exception as exc:  # noqa: BLE001
            out["errors"].append(f"active_parallel: {exc}")

    # --- Correlation (code + Kali + CVE) ---
    if (code_scan or kali_report) and time_left() > 0:
        log_step("redteam.phase.start", phase="correlate")
        try:
            merged, code_only, kali_only = Correlator().merge(code_scan, kali_report, cve_entries)
            out["results"]["correlation"] = {
                "merged_count": len(merged),
                "code_only_count": len(code_only),
                "kali_only_count": len(kali_only),
                "merged_findings": _merged_to_jsonable(merged),
                "cve_matches": _all_cve_matches_from_merged(merged),
                "cve_snapshot_size": len(cve_entries),
            }
        except Exception as exc:  # noqa: BLE001
            out["errors"].append(f"correlate: {exc}")
            out["results"]["correlation"] = {"error": str(exc)}

    out["results"]["credential_chain"] = _credential_summary_from_web(
        web_result.session_artifact if web_result else None
    )

    all_vulns: list[Vulnerability] = []
    if code_scan:
        all_vulns.extend(code_scan.vulnerabilities)
    if web_result and web_result.findings:
        all_vulns.extend(browser_findings_to_vulnerabilities(web_result.findings, target or ""))
    all_vulns.extend(kali_rows_to_vulnerabilities(kali_only))

    chains: list[ExploitChain] = []
    code_chains_json = (
        _chains_to_jsonable(code_scan.exploit_chains) if code_scan else []
    )
    if "chain" in phases and time_left() > 0:
        if not all_vulns:
            out["results"]["chains"] = {
                "exploit_chains": [],
                "exploit_chains_from_code_scan": code_chains_json,
                "note": "no vulnerabilities to chain after merge",
            }
        else:
            if target:
                assert_target_in_scope(roe, target)
            if not (roe.allowed_techniques & {"exploit", "active_scan"}):
                out["results"]["chains"] = {
                    "skipped": True,
                    "reason": "chain requires exploit or active_scan in ROE allowed_techniques",
                    "exploit_chains_from_code_scan": code_chains_json,
                }
            else:
                log_step("redteam.phase.start", phase="chain", findings=len(all_vulns))
                auditor = VulnerabilityChainAuditor()
                audit_result = auditor.audit(all_vulns)
                chains = list(audit_result.exploit_chains)
                if not getattr(args, "no_llm_payloads", False) and chains:
                    try:
                        detector = ExploitChainDetector()
                        chains = detector.enhance_chains(chains)
                    except Exception as exc:  # noqa: BLE001
                        log_step("redteam.phase.warn", phase="chain.llm", err=str(exc))
                        out["errors"].append(f"chain_llm: {exc}")
                unified_chains = code_chains_json + _chains_to_jsonable(chains)
                out["results"]["chains"] = {
                    "exploit_chains_unified": unified_chains,
                    "exploit_chains_graph": _chains_to_jsonable(chains),
                    "exploit_chains_from_code_scan": code_chains_json,
                    "auditor_status": audit_result.status,
                    "auditor_reason": audit_result.reason,
                }

    if "privesc" in phases and repo and time_left() > 0:
        log_step("redteam.phase.start", phase="privesc", repo=repo)
        if not getattr(args, "allow_privesc", False):
            out["results"]["privesc"] = {"skipped": True, "reason": "pass --allow-privesc to run privesc"}
        elif "exploit" not in roe.allowed_techniques:
            out["results"]["privesc"] = {"skipped": True, "reason": "exploit not in ROE"}
        else:
            try:
                from sandbox.privesc_runner import run_privesc_scan

                repo_path = str(Path(repo).resolve())
                art = Path(repo_path) / ".swift-artifacts" / "privesc-redteam"
                pr = await asyncio.to_thread(
                    run_privesc_scan,
                    repo_path,
                    str(art),
                    getattr(args, "privesc_image", "ubuntu:22.04"),
                    int(getattr(args, "privesc_timeout", 120)),
                    True,
                )
                out["results"]["privesc"] = pr.to_dict()
            except Exception as exc:  # noqa: BLE001
                out["errors"].append(f"privesc: {exc}")
                out["results"]["privesc"] = {"error": str(exc)}

    post_ex: list[dict[str, Any]] = []
    if "postex" in phases and time_left() > 0:
        assert_technique_allowed(roe, "post_exploit")
        log_step("redteam.phase.start", phase="postex")
        for ch in chains[:5]:
            desc = ch.impact or ch.name
            post_ex.append(asdict(simulate_data_exfil(desc, vuln_chain_id=ch.chain_id)))
        for f in (web_result.findings[:5] if web_result else []):
            desc = f"{f.kind} @ {getattr(f, 'url', '')}"
            sample = f"{getattr(f, 'evidence', '')} {getattr(f, 'payload', '')}"
            post_ex.append(asdict(simulate_data_exfil(desc, sample, vuln_chain_id="WEB")))
        for mf in merged[:5]:
            if mf.code_finding:
                post_ex.append(
                    asdict(
                        simulate_data_exfil(
                            mf.code_finding.description,
                            mf.code_finding.code_snippet[:400],
                            vuln_chain_id=mf.id,
                        )
                    )
                )
        if not post_ex:
            post_ex.append(asdict(simulate_data_exfil("engagement baseline (no confirmed vulns)")))
        post_ex.append(asdict(simulate_persistence(None)))
        post_ex.append(asdict(simulate_c2(None)))
        out["results"]["post_exploit"] = post_ex

    out["duration_seconds"] = round(time.monotonic() - started, 2)
    if time_left() <= 0:
        out["status"] = "partial"
        out["errors"].append("max_runtime exceeded (some phases may have been skipped)")
    log_step("redteam.complete", engagement=roe.engagement_id, phases=sorted(phases))
    return out


def save_redteam_artifact(payload: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
