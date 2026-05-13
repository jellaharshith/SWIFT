"""Bug bounty engagement orchestrator: ROE → VPN → OSINT → Probe → Novel → Post-Exploit → Report."""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from pathlib import Path
from typing import Optional

from agent.bounty_models import AttackSurface, BountyResult, PostExploitResult, WebFinding
from agent.post_exploit_runner import run_post_exploit
from log.audit import log_step

_ANTHROPIC_CLIENT = None


def _get_anthropic_client():
    global _ANTHROPIC_CLIENT
    if _ANTHROPIC_CLIENT is None:
        api_key = __import__("os").getenv("ANTHROPIC_API_KEY")
        if api_key:
            try:
                import anthropic
                _ANTHROPIC_CLIENT = anthropic.Anthropic(api_key=api_key)
            except ImportError:
                pass
    return _ANTHROPIC_CLIENT


async def run_bounty_engagement(
    target: str,
    roe_path: str,
    *,
    scope_path: str | None = None,
    vpn_profile: str | None = None,
    autonomous: bool = False,
    phases: str = "osint,probe,novel,post_exploit",
    out_dir: str = "output",
) -> BountyResult:
    """Run full bug bounty engagement pipeline.

    Args:
        target: Primary domain/IP (e.g. "example.com").
        roe_path: Path to roe.yaml.
        scope_path: Optional scope file path.
        vpn_profile: Path to WireGuard/OpenVPN config (None = no VPN).
        autonomous: Whether autonomous consent was granted.
        phases: Comma-separated phases to run.
        out_dir: Output directory for reports.

    Returns:
        BountyResult with all findings, post-exploit results, report path.

    Raises:
        ValueError: If ROE file is missing or scope check fails.
    """
    engagement_id = uuid.uuid4().hex[:8]
    active_phases = {p.strip().lower() for p in phases.split(",") if p.strip()}
    start_time = time.time()

    log_step("engagement_start", {
        "engagement_id": engagement_id,
        "target": target,
        "phases": list(active_phases),
        "autonomous": autonomous,
    })

    # Load ROE
    roe_file = Path(roe_path)
    if not roe_file.exists():
        raise ValueError(f"ROE file not found: {roe_path}")

    roe = None
    try:
        from security.roe import load_roe, assert_target_in_scope, assert_window_active
        roe = load_roe(roe_path)
        assert_target_in_scope(roe, target)
        assert_window_active(roe)
        log_step("roe_validated", {"target": target})
    except ImportError:
        log_step("roe_module_missing", {"note": "security.roe not available, skipping ROE checks"})

    # VPN setup
    egress_ip: str | None = None
    vpn_ctx = None
    if vpn_profile:
        try:
            from network.vpn import vpn_session
            vpn_ctx = vpn_session(vpn_profile)
            egress_ip = await vpn_ctx.__aenter__()
            log_step("vpn_up", {"egress_ip": egress_ip, "profile": vpn_profile})
        except (ImportError, Exception) as exc:
            log_step("vpn_skip", {"reason": str(exc)})

    findings: list[WebFinding] = []
    surface: AttackSurface | None = None
    niche_profile = None

    try:
        # Phase: OSINT
        if "osint" in active_phases:
            log_step("phase_osint_start", {"target": target})
            try:
                from osint.runner import run_osint
                recon_result = await run_osint(roe) if roe else await run_osint(None)
                from agent.attack_surface import build_attack_surface
                surface = await build_attack_surface(target, recon_result)
                log_step("phase_osint_done", {
                    "subdomains": len(surface.subdomains),
                    "endpoints": len(surface.endpoints),
                })
            except ImportError as exc:
                log_step("phase_osint_skip", {"reason": str(exc)})
                # Build minimal surface from target alone
                surface = AttackSurface(
                    target=target,
                    subdomains=[],
                    endpoints=[f"https://{target}/"],
                    auth_endpoints=[],
                    tech_stack=[],
                    open_ports=[],
                    github_leaks=[],
                    shodan_info={},
                )

        # Niche classification — post-OSINT, gates active probe focus
        if surface is not None:
            try:
                from agent.niche_classifier import classify_niches
                niche_profile = await classify_niches(
                    target, surface, _get_anthropic_client()
                )
                log_step("niche_classified", {
                    "niches": niche_profile.primary_niches,
                    "tier": niche_profile.bounty_tier,
                })
            except Exception as exc:
                log_step("niche_classify_skip", {"reason": str(exc)})

        # Ensure surface exists even if OSINT phase skipped
        if surface is None:
            surface = AttackSurface(
                target=target,
                subdomains=[],
                endpoints=[f"https://{target}/"],
                auth_endpoints=[],
                tech_stack=[],
                open_ports=[],
                github_leaks=[],
                shodan_info={},
            )

        # Phase: Browser probes
        if "probe" in active_phases:
            focus = niche_profile.focus_payloads if niche_profile else None
            log_step("phase_probe_start", {
                "endpoint_count": len(surface.endpoints),
                "focus_payloads": focus,
            })
            try:
                from browser.playwright_runner import run_web_probes
                probe_findings = await run_web_probes(
                    surface.endpoints, roe=roe, focus_vuln_types=focus
                )
                findings.extend(probe_findings)
                log_step("phase_probe_done", {"raw_findings": len(probe_findings)})
            except (ImportError, Exception) as exc:
                log_step("phase_probe_skip", {"reason": str(exc)})

        # Phase: Novel methods
        if "novel" in active_phases:
            log_step("phase_novel_start", {})
            try:
                from agent.novel_method import discover_novel_methods
                novel = await discover_novel_methods(surface, findings, roe)
                findings.extend(novel)
                log_step("phase_novel_done", {"novel_count": len(novel)})
            except (ImportError, Exception) as exc:
                log_step("phase_novel_skip", {"reason": str(exc)})

        # Calibrate confidence before gate
        try:
            from agent.confidence_calibrator import ConfidenceCalibrator
            _cal = ConfidenceCalibrator()
            findings = _cal.calibrate_batch(findings)
        except Exception:
            pass

        # Confidence gate: 95%
        confirmed = [f for f in findings if f.confidence >= 0.95]
        log_step("confidence_gate", {
            "total": len(findings),
            "confirmed": len(confirmed),
            "filtered": len(findings) - len(confirmed),
        })

        # Enrich with CVSS + remediation
        enriched: list[WebFinding] = []
        for f in confirmed:
            try:
                from agent.severity import enrich_finding
                f = enrich_finding(f)
            except (ImportError, Exception):
                pass
            try:
                from agent.fix_suggester import suggest_fix
                if not f.remediation:
                    f.remediation = suggest_fix(f)
            except (ImportError, Exception):
                pass
            enriched.append(f)

        # Phase: Post-exploitation
        post_results: list[PostExploitResult] = []
        if "post_exploit" in active_phases:
            log_step("phase_post_exploit_start", {})
            post_results = await run_post_exploit(enriched, roe)
            log_step("phase_post_exploit_done", {"sim_count": len(post_results)})

        # Build result
        result = BountyResult(
            engagement_id=engagement_id,
            target=target,
            scope_path=scope_path,
            roe_path=roe_path,
            findings=enriched,
            post_exploit=post_results,
            attack_surface=surface,
            vpn_egress_ip=egress_ip,
            autonomous=autonomous,
            niche_profile=niche_profile,
        )

        # Write JSON report
        out_path = Path(out_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        report_file = out_path / f"{engagement_id}_bounty.json"
        report_file.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        result.report_path = str(report_file)

        elapsed = time.time() - start_time
        log_step("engagement_done", {
            "engagement_id": engagement_id,
            "findings": len(enriched),
            "post_exploit": len(post_results),
            "elapsed_s": round(elapsed, 2),
            "report": str(report_file),
        })

        return result

    finally:
        # Tear down VPN
        if vpn_ctx is not None:
            try:
                await vpn_ctx.__aexit__(None, None, None)
                log_step("vpn_down", {})
            except Exception as exc:
                log_step("vpn_teardown_error", {"reason": str(exc)})
