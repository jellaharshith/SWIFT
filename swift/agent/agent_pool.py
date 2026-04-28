from __future__ import annotations
import asyncio
import time
from typing import Callable, List, Optional
from agent.orchestrator import scan_codebase
from agent.correlator import Correlator
from kali.runner import KaliRunner
from feeds.live_cve import LiveCVEFeed, CVEEntry
from agent.models import ScanResult, UnifiedScanResult


class CodeAgent:
    async def run(self, repo_path: str, progress_cb: Callable[[str], None]) -> ScanResult:
        progress_cb(f"[CodeAgent] starting static analysis on {repo_path}...")
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, scan_codebase, repo_path)
        progress_cb(f"[CodeAgent] complete — {len(result.vulnerabilities)} findings")
        return result


class NetworkAgent:
    _TOOLS = ["nmap", "masscan", "searchsploit"]

    async def run(self, target: str, progress_cb: Callable[[str], None]) -> dict:
        progress_cb(f"[NetworkAgent] running nmap + masscan on {target}...")
        runner = KaliRunner()
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, runner.run_scan, target, self._TOOLS)
        progress_cb("[NetworkAgent] complete")
        return result


class WebAgent:
    _TOOLS = ["nikto", "nuclei", "sqlmap", "gobuster"]

    async def run(self, target: str, progress_cb: Callable[[str], None]) -> dict:
        progress_cb(f"[WebAgent] running nikto + nuclei + sqlmap + gobuster on {target}...")
        runner = KaliRunner()
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, runner.run_scan, target, self._TOOLS)
        progress_cb("[WebAgent] complete")
        return result


class CVEAgent:
    def __init__(self) -> None:
        self._entries: List[CVEEntry] = []
        self._feed: Optional[LiveCVEFeed] = None

    async def run(self, duration: float, progress_cb: Callable[[str], None]) -> List[CVEEntry]:
        progress_cb("[CVEAgent] polling NVD + CISA KEV...")
        self._feed = LiveCVEFeed()
        feed = self._feed

        def callback(entry: CVEEntry) -> None:
            self._entries.append(entry)
            progress_cb(f"[CVEAgent] {len(self._entries)} CVEs collected")

        loop = asyncio.get_event_loop()
        poll_task = loop.run_in_executor(None, feed.poll_forever, callback)
        await asyncio.sleep(duration)
        if hasattr(feed, "_stop"):
            feed._stop = True
        poll_task.cancel()
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
        if web_idx >= 0 and not isinstance(results[web_idx], Exception):
            web_tools = results[web_idx] or {}
            kali_result.setdefault("tools", [])
            kali_result["tools"].extend(web_tools.get("tools", []))

        correlator = Correlator()
        unified = correlator.merge(code_result, kali_result if kali_target else None, cve_entries)
        unified.duration = time.time() - started
        unified.repo_path = repo_path
        unified.kali_target = kali_target
        return unified
