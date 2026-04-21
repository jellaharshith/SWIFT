"""Agent orchestrator — full SWIFT pipeline: triage → haiku → sonnet → patch → sandbox."""
from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Callable, List, Optional

import anthropic

from agent.models import Patch, ScanResult, Vulnerability
from agent.vuln_chain_auditor import VulnerabilityChainAuditor
from chains.detector import ExploitChainDetector
from config.settings import get_config
from log.logger import MetricsCollector, get_logger
from output.chains import ChainsFormatter
from patches.generator import PatchGenerator
from sandbox.docker_runner import DockerSandbox
from scanners.haiku_scanner import HaikuTriageScanner
from scanners.sonnet_scanner import SonnetAnalysisScanner
from triage.exploit_graph import MAX_CHAIN_CANDIDATES
from triage.patterns import triage_codebase
from triage.ranking import RiskScorer

# Sentinel alias used in log/emit calls (avoids importing twice)
MAX_CHAIN_CANDIDATES_SENTINEL = MAX_CHAIN_CANDIDATES

logger = get_logger()

# Batch size for Haiku scanning. Process files in chunks to manage memory/timeout.
HAIKU_BATCH_SIZE = 50


def _serialize_findings_sample(vulns: List, max_items: int = 100) -> str:
    """Serialize the first max_items findings to a compact JSON string.

    Caps output to avoid DB bloat on large repos with 600+ signals.
    """
    sample = vulns[:max_items]
    try:
        return json.dumps([asdict(v) for v in sample])
    except Exception:
        return "[]"


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
    chain_auditor = VulnerabilityChainAuditor()

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

    # --- Phase 2: Haiku fast scan (batched) ---
    # Process files in batches to manage memory and prevent timeouts on large codebases.
    haiku_results: dict[str, tuple[str, list[int]]] = {}
    flagged_items = list(flagged_map.items())
    num_batches = max(1, (len(flagged_items) + HAIKU_BATCH_SIZE - 1) // HAIKU_BATCH_SIZE)

    for batch_num, batch_start in enumerate(range(0, len(flagged_items), HAIKU_BATCH_SIZE)):
        batch_end = min(batch_start + HAIKU_BATCH_SIZE, len(flagged_items))
        batch = flagged_items[batch_start:batch_end]

        for batch_idx, (file_path, line_numbers) in enumerate(batch):
            global_idx = batch_start + batch_idx
            _emit({
                "stage": 1,
                "stage_name": "haiku",
                "files_total": files_scanned,
                "files_scanned": global_idx,
                "current_file": os.path.basename(file_path),
                "batch_current": batch_num + 1,
                "batch_total": num_batches,
                "progress": int((global_idx / max(files_scanned, 1)) * 60),  # 0–60%
                "signals_detected": 0,
            })
            try:
                with open(file_path, encoding="utf-8", errors="replace") as fh:
                    source = fh.read()

                # Skip test files, minified files, and files too large for Haiku token limit
                base_name = os.path.basename(file_path).lower()
                is_test_file = (
                    file_path.endswith((".spec.ts", ".spec.js", ".test.ts", ".test.js", ".spec.tsx", ".test.tsx"))
                    or "spec" in base_name or "test" in base_name  # Catch userProfileSpec.ts, etc.
                )
                is_minified = file_path.endswith((".min.js", ".min.css", ".min.ts"))
                file_size_kb = len(source) / 1024
                max_size_kb = 100  # ~50k tokens, safe margin from 200k limit

                if is_test_file or is_minified or file_size_kb > max_size_kb:
                    logger.debug("Skip %s (test=%s, minified=%s, size=%.1fKB)", file_path, is_test_file, is_minified, file_size_kb)
                    continue

                suspicious = haiku.scan_lines(file_path, source, set(line_numbers))
                if suspicious:
                    haiku_results[file_path] = (source, sorted(suspicious))
            except Exception as exc:
                logger.error("Haiku scan error %s: %s", file_path, exc)

        logger.info("Haiku batch %d/%d: %d results", batch_num + 1, num_batches, len(haiku_results))

    logger.info("Haiku phase: %d files scanned from %d flagged", len(haiku_results), len(flagged_items))
    _emit({
        "stage": 2,
        "stage_name": "review_required",
        "files_total": len(haiku_results),
        "files_scanned": 0,
        "current_file": "",
    })

    # --- Phase 3: Convert Haiku signals to REVIEW_REQUIRED findings (MVP mode) ---
    # Disabled Sonnet deep analysis for MVP stability. All findings are Haiku detections
    # marked REVIEW_REQUIRED with confidence ~0.7 for manual verification.
    vulnerabilities: List[Vulnerability] = []
    signal_counter = 0
    num_haiku_files = max(len(haiku_results), 1)

    for f_idx, (file_path, (source, line_numbers)) in enumerate(haiku_results.items()):
        _emit({
            "stage": 2,
            "stage_name": "review_required",
            "files_total": num_haiku_files,
            "files_scanned": f_idx,
            "current_file": os.path.basename(file_path),
            "progress": 60 + int((f_idx / num_haiku_files) * 35),  # 60–95%
            "signals_detected": signal_counter,
        })
        for line_num in line_numbers:
            try:
                # Get the line content from source
                lines = source.split('\n')
                code_snippet = ""
                if line_num > 0 and line_num <= len(lines):
                    code_snippet = lines[line_num - 1]

                # Create REVIEW_REQUIRED finding from Haiku signal
                vuln = Vulnerability(
                    id=f"SIGNAL-{uuid.uuid4().hex[:8]}",
                    file_path=file_path,
                    line_number=line_num,
                    vuln_type="signal_requires_review",
                    description=f"Haiku pattern match detected on line {line_num} — requires manual verification",
                    confidence=0.7,
                    severity="medium",
                    code_snippet=code_snippet,
                    status="REVIEW_REQUIRED",
                    cwe_id=None,
                    cwe_url=None,
                    owasp_category=None,
                    exploit_description=None,
                    exploit_impact=None,
                    remediation=None,
                    remediation_code=None,
                    remediation_effort=None,
                    remediation_time_minutes=None,
                    references=[],
                )
                vulnerabilities.append(vuln)
                signal_counter += 1
                metrics.record_vulnerability(vuln.id)
            except Exception as exc:
                logger.error("Signal conversion error %s:%d: %s", file_path, line_num, exc)

        # Emit incremental findings snapshot at end of each file (capped to 100 items)
        _emit({
            "stage": 2,
            "stage_name": "review_required",
            "files_total": num_haiku_files,
            "files_scanned": f_idx + 1,
            "current_file": os.path.basename(file_path),
            "progress": 60 + int(((f_idx + 1) / num_haiku_files) * 35),
            "signals_detected": signal_counter,
            "findings_json": _serialize_findings_sample(vulnerabilities),
        })

    logger.info("Signals generated: %d REVIEW_REQUIRED findings", signal_counter)
    logger.debug("Files discovered: %d, files passed to Haiku: %d", files_scanned, len(haiku_results))

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

    # --- Phase 3.3: Triage findings for chain detection ---
    # Limit to top N findings by risk score to prevent timeout on 600+ signals.
    # Only most critical findings sent to expensive LLM reasoning.
    triaged_findings = scorer.triage_findings(vulnerabilities)
    logger.info("Triage: %d / %d findings selected for chain detection", len(triaged_findings), len(vulnerabilities))

    # --- Phase 3.5: Bounded exploit graph + chain detection ---
    # Architecture: deterministic graph pipeline first, LLM enhances narrative only.
    # Memory guards prevent OOM; partial results are preserved on any resource limit.
    exploit_chains = []
    ranked_findings: List[Vulnerability] = []
    chain_detection_error: Optional[str] = None
    chain_stage_metrics: dict = {}

    if triaged_findings:
        _emit({
            "stage": 3,
            "stage_name": "chain_graph_build",
            "files_total": len(triaged_findings),
            "files_scanned": 0,
            "current_file": "",
            "progress": 95,
            "chain_stage": "graph_build",
            "chain_nodes": 0,
            "chain_edges": 0,
            "chain_candidates": 0,
            "ranked_chains": 0,
        })
        try:
            # Pass 1: deterministic bounded graph — builds chains without LLM.
            audit = chain_auditor.audit(triaged_findings)
            exploit_chains = audit.exploit_chains
            ranked_findings = audit.ranked_findings
            chain_stage_metrics = audit.graph_metrics

            logger.info(
                "[CHAIN-STAGE] Graph: nodes=%d edges=%d candidates=%d "
                "ranked_chains=%d status=%s reason=%s",
                chain_stage_metrics.get("graph_nodes", 0),
                chain_stage_metrics.get("graph_edges", 0),
                MAX_CHAIN_CANDIDATES_SENTINEL,
                len(exploit_chains),
                audit.status,
                audit.reason or "none",
            )

            _emit({
                "stage": 3,
                "stage_name": "chain_llm_enhance",
                "files_total": len(triaged_findings),
                "files_scanned": len(triaged_findings),
                "current_file": "",
                "progress": 97,
                "chain_stage": "llm_enhance",
                "chain_nodes": chain_stage_metrics.get("graph_nodes", 0),
                "chain_edges": chain_stage_metrics.get("graph_edges", 0),
                "chain_candidates": MAX_CHAIN_CANDIDATES_SENTINEL,
                "ranked_chains": len(exploit_chains),
                "resource_limited": audit.status == "partial",
                "resource_limit_reason": audit.reason,
            })

            # Pass 2: LLM enhances narrative of pre-built chains (optional).
            # On parse failure the original deterministic chains are returned unchanged.
            if exploit_chains:
                enhanced = chain_detector.enhance_chains(exploit_chains)
                if enhanced:
                    exploit_chains = enhanced

            if audit.status == "partial":
                chain_detection_error = audit.reason

            logger.info(
                "[CHAIN-STAGE] Complete: %d chains, %d ranked findings, "
                "resource_limited=%s",
                len(exploit_chains), len(ranked_findings), audit.status == "partial",
            )

        except Exception as exc:
            chain_detection_error = str(exc)
            logger.error(
                "chain_detection_failed scan_id=%s triaged_findings=%d error=%s",
                scan_id,
                len(triaged_findings),
                chain_detection_error,
                exc_info=True,
            )
    else:
        logger.info("[CHAIN-STAGE] Skipped: no triaged findings")

    duration = time.monotonic() - start

    # Determine status: partial_success when chain detection hit a resource limit
    # or a hard error. Legitimate empty chains (no connections in graph) are "complete".
    status = "complete"
    if chain_detection_error:
        status = "partial_success"

    _emit({
        "stage": 3,
        "stage_name": "chain_complete",
        "files_total": len(triaged_findings),
        "files_scanned": len(triaged_findings),
        "current_file": "",
        "progress": 99,
        "chain_stage": "complete",
        "chain_nodes": chain_stage_metrics.get("graph_nodes", 0),
        "chain_edges": chain_stage_metrics.get("graph_edges", 0),
        "chain_candidates": MAX_CHAIN_CANDIDATES_SENTINEL,
        "ranked_chains": len(exploit_chains),
        "resource_limited": bool(chain_detection_error),
        "resource_limit_reason": chain_detection_error or "",
    })

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
        ranked_findings=ranked_findings,
        status=status,
        signals_detected=signal_counter,
        signals_triaged=len(triaged_findings),
        chain_detection_error=chain_detection_error,
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
        "Scan %s complete [%s]: %d signals detected, %d triaged, %d chains, %d patches, %.1fs",
        scan_id, result.status, result.signals_detected, result.signals_triaged,
        len(result.exploit_chains), len(result.patches), result.duration_seconds,
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
        ranked_findings=scan_result.ranked_findings,
        chain_detection_error=scan_result.chain_detection_error,
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
