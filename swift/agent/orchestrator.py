"""Agent orchestrator — full SWIFT pipeline: triage → haiku → sonnet → patch → sandbox."""
from __future__ import annotations

import os
import time
import uuid
from datetime import datetime, timezone
from typing import Callable, List, Optional

import anthropic

from agent.models import Patch, ScanResult, Vulnerability
from chains.detector import ExploitChainDetector
from config.settings import get_config
from log.logger import MetricsCollector, get_logger
from output.chains import ChainsFormatter
from patches.generator import PatchGenerator
from sandbox.docker_runner import DockerSandbox
from scanners.haiku_scanner import HaikuTriageScanner
from scanners.sonnet_scanner import SonnetAnalysisScanner
from triage.patterns import triage_codebase
from triage.ranking import RiskScorer

logger = get_logger()


def scan_codebase(
    repo_path: str,
    generate_patches_flag: bool = False,
    progress_callback: Optional[Callable[[dict], None]] = None,
) -> ScanResult:
    """Run the full SWIFT scan pipeline on a local repository.

    Pipeline:
    1. Regex triage (free) — flag suspicious files and line numbers
    2. Haiku scan — fast API call to confirm suspicious lines (~$0.05/file)
    3. Sonnet analysis — deep reasoning with 95% confidence gate (~$0.50/location)
    4. Patch generation + sandbox validation (optional, only when flag is set)

    Args:
        repo_path: Path to the repository root to scan.
        generate_patches_flag: If True, generate and sandbox-test patches after scan.
        progress_callback: Optional callback function to report progress. Called with dict of
            {stage, stage_name, files_total, files_scanned, current_file}.

    Returns:
        ScanResult with confirmed vulnerabilities and optional patches.
    """
    config = get_config()
    metrics = MetricsCollector()
    scan_id = f"SCAN-{uuid.uuid4().hex[:8]}"
    metrics.start_scan(scan_id, repo_path)

    client = anthropic.Anthropic(api_key=config.api_key)
    haiku = HaikuTriageScanner(
        client, model=config.haiku_model, max_retries=config.max_retries
    )
    sonnet = SonnetAnalysisScanner(client, model=config.sonnet_model)
    chain_detector = ExploitChainDetector(client, model=config.sonnet_model)

    logger.info("Scan %s started on %s", scan_id, repo_path)
    start = time.monotonic()

    # Progress callback helper — safe even if callback is None or raises
    def _emit(payload: dict) -> None:
        if progress_callback:
            try:
                progress_callback(payload)
            except Exception:
                pass

    # --- Phase 1: Regex triage (zero cost) ---
    flagged_map = triage_codebase(repo_path)
    files_scanned = len(flagged_map)
    logger.info("Regex triage: %d files flagged", files_scanned)
    _emit({
        "stage": 0,
        "stage_name": "triage_complete",
        "files_total": files_scanned,
        "files_scanned": files_scanned,
        "current_file": "",
    })

    # --- Phase 2: Haiku fast scan ---
    haiku_results: dict[str, tuple[str, list[int]]] = {}
    for idx, (file_path, line_numbers) in enumerate(flagged_map.items()):
        _emit({
            "stage": 1,
            "stage_name": "haiku",
            "files_total": files_scanned,
            "files_scanned": idx,
            "current_file": os.path.basename(file_path),
        })
        try:
            with open(file_path, encoding="utf-8", errors="replace") as fh:
                source = fh.read()

            # Skip minified files and files too large for Haiku token limit
            is_minified = file_path.endswith((".min.js", ".min.css", ".min.ts"))
            file_size_kb = len(source) / 1024
            max_size_kb = 100  # ~50k tokens, safe margin from 200k limit

            if is_minified or file_size_kb > max_size_kb:
                logger.debug("Skip %s (minified=%s, size=%.1fKB)", file_path, is_minified, file_size_kb)
                continue

            suspicious = haiku.scan_lines(file_path, source, set(line_numbers))
            if suspicious:
                haiku_results[file_path] = (source, sorted(suspicious))
        except Exception as exc:
            logger.error("Haiku scan error %s: %s", file_path, exc)

    logger.info("Haiku stage: %d files with suspicious lines", len(haiku_results))
    _emit({
        "stage": 2,
        "stage_name": "sonnet",
        "files_total": len(haiku_results),
        "files_scanned": 0,
        "current_file": "",
    })

    # --- Phase 3: Sonnet deep analysis (95% gate) ---
    vulnerabilities: List[Vulnerability] = []
    for f_idx, (file_path, (source, line_numbers)) in enumerate(haiku_results.items()):
        _emit({
            "stage": 2,
            "stage_name": "sonnet",
            "files_total": len(haiku_results),
            "files_scanned": f_idx,
            "current_file": os.path.basename(file_path),
        })
        for line_num in line_numbers:
            try:
                vuln = sonnet.analyze_line(file_path, line_num, source)
                if vuln:
                    vulnerabilities.append(vuln)
                    metrics.record_vulnerability(vuln.id)
            except Exception as exc:
                logger.error("Sonnet error %s:%d: %s", file_path, line_num, exc)

    logger.info("Sonnet stage: %d vulnerabilities confirmed (≥95%% confidence)", len(vulnerabilities))

    # --- Phase 3.2: Risk scoring and ranking ---
    scorer = RiskScorer()
    for vuln in vulnerabilities:
        # Infer exploitability if not already set
        if vuln.exploitability is None:
            vuln.exploitability = scorer.get_exploitability_score(vuln)
        # Infer business impact category if not already set
        if vuln.business_impact_category is None:
            vuln.business_impact_category = scorer.get_impact_category(vuln)
        # Calculate risk score
        vuln.risk_score = scorer.calculate_risk_score(vuln)
    logger.info("Risk scoring: %d vulnerabilities ranked", len(vulnerabilities))

    # --- Phase 3.5: Exploit chain detection (best-effort) ---
    exploit_chains = []
    if vulnerabilities:
        exploit_chains = chain_detector.detect_chains(vulnerabilities)
        logger.info("Chain detection: %d exploit chains identified", len(exploit_chains))

    duration = time.monotonic() - start

    result = ScanResult(
        scan_id=scan_id,
        repo_path=repo_path,
        files_scanned=files_scanned,
        vulnerabilities=vulnerabilities,
        patches=[],
        duration_seconds=duration,
        total_cost_usd=metrics.total_cost_usd,
        timestamp=datetime.now(timezone.utc).isoformat(),
        exploit_chains=exploit_chains,
    )

    # --- Phase 4: Patch generation (optional) ---
    if generate_patches_flag and vulnerabilities:
        _emit({
            "stage": 3,
            "stage_name": "patches",
            "files_total": len(vulnerabilities),
            "files_scanned": 0,
            "current_file": "",
        })
        result = generate_patches(result)

    # Export chains to standalone JSON if chains exist
    if result.exploit_chains:
        chains_export = export_chains_standalone(result)
        logger.debug("Chains standalone export: %d bytes", len(chains_export))

    logger.info(
        "Scan %s complete: %d vulns, %d patches, %d chains, %.1fs",
        scan_id, len(result.vulnerabilities), len(result.patches),
        len(result.exploit_chains), result.duration_seconds,
    )
    return result


def generate_patches(scan_result: ScanResult) -> ScanResult:
    """Generate and sandbox-test patches for all vulnerabilities in a ScanResult.

    Calls PatchGenerator (Sonnet) for each vulnerability, then runs each
    patch through DockerSandbox for isolation-tested validation.

    Args:
        scan_result: Completed scan with confirmed vulnerabilities.

    Returns:
        New ScanResult with patches populated.
    """
    config = get_config()
    client = anthropic.Anthropic(api_key=config.api_key)
    generator = PatchGenerator(client, model=config.sonnet_model)
    sandbox = DockerSandbox(timeout=config.sandbox_timeout)

    patches: List[Patch] = []
    for vuln in scan_result.vulnerabilities:
        patch = generator.generate_patch(vuln)
        if patch:
            test_result = sandbox.test_patch(patch)
            logger.info(
                "Patch %s sandbox: %s",
                patch.id,
                "PASSED" if test_result.passed else "FAILED",
            )
            patches.append(patch)

    return ScanResult(
        scan_id=scan_result.scan_id,
        repo_path=scan_result.repo_path,
        files_scanned=scan_result.files_scanned,
        vulnerabilities=scan_result.vulnerabilities,
        patches=patches,
        duration_seconds=scan_result.duration_seconds,
        total_cost_usd=scan_result.total_cost_usd,
        timestamp=scan_result.timestamp,
        exploit_chains=scan_result.exploit_chains,
    )


def export_chains_standalone(scan_result: ScanResult) -> str:
    """Export exploit chains to standalone JSON format with attack step details.

    Args:
        scan_result: Completed scan with exploit chains.

    Returns:
        JSON string containing standalone chains export.
    """
    formatter = ChainsFormatter()
    chains_json = formatter.format(scan_result)
    logger.info(
        "Chains exported: %d chains with attack steps",
        len(scan_result.exploit_chains),
    )
    return chains_json
