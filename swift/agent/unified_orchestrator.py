"""Unified orchestrator — runs code scan, Kali scan, and CVE feed simultaneously."""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Callable, List, Optional

from feeds.live_cve import CVEEntry, LiveCVEFeed


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _run_code_scan(
    repo_path: str,
    progress_callback: Optional[Callable] = None,
) -> object:
    from agent.orchestrator import scan_codebase
    return await asyncio.to_thread(
        scan_codebase,
        repo_path,
        progress_callback=progress_callback,
    )


async def _run_kali_scan(
    target: str,
    tools: Optional[List[str]],
    skip_build: bool = False,
) -> dict:
    from kali.runner import KaliRunner
    runner = KaliRunner()
    if not skip_build:
        await asyncio.to_thread(runner.build_image)
    return await asyncio.to_thread(runner.run_scan, target, tools)


async def unified_scan(
    repo_path: Optional[str] = None,
    kali_target: Optional[str] = None,
    tools: Optional[List[str]] = None,
    skip_kali_build: bool = False,
    progress_callback: Optional[Callable] = None,
) -> object:
    """Run code scan + Kali offensive scan + CVE feed simultaneously.

    Args:
        repo_path: Local repo path for static code analysis (None to skip).
        kali_target: Host/URL for Kali offensive scan (None to skip).
        tools: Kali tools to run (None = all).
        skip_kali_build: Skip Kali Docker image build check.
        progress_callback: Optional progress callback forwarded to code scanner.

    Returns:
        UnifiedScanResult with all findings correlated.

    Raises:
        ValueError: If neither repo_path nor kali_target is provided.
    """
    from agent.correlator import Correlator
    from agent.models import UnifiedScanResult

    if not repo_path and not kali_target:
        raise ValueError("At least one of repo_path or kali_target must be provided.")

    scan_id = uuid.uuid4().hex[:12]
    started_at = _utc_now()
    start_time = asyncio.get_event_loop().time()

    # Collect CVEs in background while scans run
    cve_entries: list[CVEEntry] = []

    async def _cve_collector() -> None:
        feed = LiveCVEFeed()
        try:
            await feed.poll_forever(lambda e: cve_entries.append(e))
        finally:
            await feed.close()

    cve_task = asyncio.create_task(_cve_collector())

    # Build scan tasks
    scan_tasks = []
    code_idx = kali_idx = -1

    if repo_path:
        code_idx = len(scan_tasks)
        scan_tasks.append(asyncio.create_task(
            _run_code_scan(repo_path, progress_callback)
        ))

    if kali_target:
        kali_idx = len(scan_tasks)
        scan_tasks.append(asyncio.create_task(
            _run_kali_scan(kali_target, tools, skip_kali_build)
        ))

    # Run scans; stop CVE feed when both finish
    try:
        results = await asyncio.gather(*scan_tasks)
    finally:
        cve_task.cancel()
        try:
            await cve_task
        except asyncio.CancelledError:
            pass

    code_result = results[code_idx] if code_idx >= 0 else None
    kali_result = results[kali_idx] if kali_idx >= 0 else None

    # Correlate
    merged, code_only, kali_only = Correlator().merge(code_result, kali_result, cve_entries)

    # Collect all CVE matches from merged findings
    all_cve_matches = [cm for mf in merged for cm in mf.cve_matches]

    # Carry exploit chains from code result
    exploit_chains = list(code_result.exploit_chains) if code_result else []

    duration = asyncio.get_event_loop().time() - start_time

    return UnifiedScanResult(
        scan_id=scan_id,
        started_at=started_at,
        duration=round(duration, 2),
        repo_path=repo_path,
        kali_target=kali_target,
        merged_findings=merged,
        code_only_findings=code_only,
        kali_only_findings=kali_only,
        all_cve_matches=all_cve_matches,
        exploit_chains=exploit_chains,
        osint_findings=[],
        post_exploit_findings=[],
    )
