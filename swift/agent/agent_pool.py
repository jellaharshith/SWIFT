from __future__ import annotations
import asyncio
import time
import uuid
from datetime import datetime, timezone
from typing import Callable, List, Optional
from agent.orchestrator import scan_codebase
from agent.correlator import Correlator
from kali.runner import KaliRunner
from feeds.live_cve import LiveCVEFeed, CVEEntry
from agent.models import ScanResult, UnifiedScanResult


def _make_scan_id() -> str:
    return uuid.uuid4().hex[:12]


def _format_timestamp(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


class CodeAgent:
    async def run(self, repo_path: str, progress_cb: Callable[[str], None]) -> ScanResult:
        progress_cb(f"[CodeAgent] starting static analysis on {repo_path}...")
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, scan_codebase, repo_path)
        progress_cb(f"[CodeAgent] complete — {len(result.vulnerabilities)} findings")
        return result


class NetworkAgent:
    _TOOLS = ["nmap", "masscan", "searchsploit"]

    async def run(self, target: str, progress_cb: Callable[[str], None]) -> dict:
        progress_cb(f"[NetworkAgent] running nmap + masscan on {target}...")
        runner = KaliRunner()
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, runner.run_scan, target, self._TOOLS)
        progress_cb("[NetworkAgent] complete")
        return result


class WebAgent:
    _TOOLS = ["nikto", "nuclei", "sqlmap", "gobuster"]

    async def run(self, target: str, progress_cb: Callable[[str], None]) -> dict:
        from log.audit import log_step
        progress_cb(f"[WebAgent] running nikto + nuclei + sqlmap + gobuster on {target}...")
        log_step("agent.web.start", target=target, tools=self._TOOLS)
        runner = KaliRunner()
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, runner.run_scan, target, self._TOOLS)

        if isinstance(target, str) and target.startswith(("http://", "https://")):
            try:
                import uuid as _uuid
                from browser.playwright_runner import scan_url_async
                from browser.finding_bridge import browser_scan_to_vulnerabilities
                progress_cb(f"[WebAgent] launching Playwright browser scan on {target}...")
                browser_result = await scan_url_async(target)
                scan_id = _uuid.uuid4().hex[:8]
                browser_vulns = browser_scan_to_vulnerabilities(browser_result, scan_id)
                if isinstance(result, dict):
                    result["browser"] = browser_result.to_dict()
                    result["browser_vulnerabilities"] = [
                        {
                            "id": v.id,
                            "vuln_type": v.vuln_type,
                            "severity": v.severity,
                            "confidence": v.confidence,
                            "description": v.description,
                            "file_path": v.file_path,
                            "cwe_id": v.cwe_id,
                        }
                        for v in browser_vulns
                    ]
                progress_cb(
                    f"[WebAgent] browser scan complete — {len(browser_result.findings)} findings, "
                    f"{len(browser_vulns)} confirmed (≥95%)"
                )
                log_step(
                    "agent.web.browser_done",
                    target=target,
                    findings=len(browser_result.findings),
                    confirmed=len(browser_vulns),
                )
            except Exception as exc:  # noqa: BLE001
                progress_cb(f"[WebAgent] browser scan failed: {exc}")
                log_step("agent.web.browser_error", target=target, err=str(exc), level="warning")

        progress_cb("[WebAgent] complete")
        log_step("agent.web.finish", target=target)
        return result


class CVEAgent:
    def __init__(self) -> None:
        self._entries: List[CVEEntry] = []

    async def run(self, duration: float, progress_cb: Callable[[str], None]) -> List[CVEEntry]:
        progress_cb("[CVEAgent] polling NVD + CISA KEV...")
        feed = LiveCVEFeed()

        def callback(entry: CVEEntry) -> None:
            self._entries.append(entry)
            progress_cb(f"[CVEAgent] {len(self._entries)} CVEs collected")

        poll_task = asyncio.create_task(feed.poll_forever(callback))
        await asyncio.sleep(duration)
        poll_task.cancel()
        try:
            await poll_task
        except asyncio.CancelledError:
            pass
        return self._entries


class AgentPool:
    async def run_all(
        self,
        repo_path: Optional[str],
        kali_target: Optional[str],
        progress_cb: Callable[[str], None],
    ) -> UnifiedScanResult:
        started = time.time()

        tasks = []
        code_idx = net_idx = web_idx = -1

        if repo_path:
            code_idx = len(tasks)
            tasks.append(CodeAgent().run(repo_path, progress_cb))

        if kali_target:
            net_idx = len(tasks)
            tasks.append(NetworkAgent().run(kali_target, progress_cb))
            web_idx = len(tasks)
            tasks.append(WebAgent().run(kali_target, progress_cb))

        cve_agent = CVEAgent()
        cve_task = asyncio.create_task(cve_agent.run(120, progress_cb))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        cve_task.cancel()
        try:
            await cve_task
        except (asyncio.CancelledError, Exception):
            pass
        cve_entries = cve_agent._entries

        code_result = results[code_idx] if code_idx >= 0 and not isinstance(results[code_idx], Exception) else None
        kali_result: dict = {}
        if net_idx >= 0 and not isinstance(results[net_idx], Exception):
            kali_result.update(results[net_idx] or {})
        browser_confirmed_vulns: list = []
        if web_idx >= 0 and not isinstance(results[web_idx], Exception):
            web_tools = results[web_idx] or {}
            kali_result.setdefault("results", [])
            kali_result["results"].extend(web_tools.get("results", []))
            # Extract browser-confirmed Vulnerability objects from WebAgent result
            # They were stored as dicts; re-hydrate via bridge on raw browser findings
            browser_dict = web_tools.get("browser", {})
            raw_findings = browser_dict.get("findings", [])
            if raw_findings:
                try:
                    from browser.playwright_runner import BrowserFinding
                    from browser.finding_bridge import browser_finding_to_vulnerability
                    import uuid as _uuid2
                    _scan_id = _uuid2.uuid4().hex[:8]
                    for idx, fd in enumerate(raw_findings):
                        bf = BrowserFinding(
                            kind=fd.get("kind", ""),
                            severity=fd.get("severity", "low"),
                            url=fd.get("url", ""),
                            evidence=fd.get("evidence", ""),
                            payload=fd.get("payload", ""),
                        )
                        vuln = browser_finding_to_vulnerability(bf, _scan_id, idx)
                        if vuln is not None:
                            browser_confirmed_vulns.append(vuln)
                except Exception:  # noqa: BLE001
                    pass

        correlator = Correlator()
        merged, code_only, kali_only = correlator.merge(
            code_result, kali_result if kali_target else None, cve_entries
        )

        # Collect all CVE matches from merged findings
        all_cve_matches = [cm for mf in merged for cm in (mf.cve_matches or [])]

        # Merge browser-confirmed vulns into code_only_findings for unified report
        combined_code_findings = list(code_only) + browser_confirmed_vulns

        return UnifiedScanResult(
            scan_id=_make_scan_id(),
            started_at=_format_timestamp(started),
            duration=time.time() - started,
            repo_path=repo_path,
            kali_target=kali_target,
            merged_findings=merged,
            code_only_findings=combined_code_findings,
            kali_only_findings=kali_only,
            all_cve_matches=all_cve_matches,
        )
