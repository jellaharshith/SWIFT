"""Live CVE/exploit feed — polls NVD, CISA KEV, ExploitDB every 2 seconds."""
from __future__ import annotations

import asyncio
import inspect
import json
import os
import subprocess
from dataclasses import dataclass, field
from typing import Callable

import httpx

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
POLL_INTERVAL = int(os.getenv("CVE_POLL_INTERVAL", "7"))  # NVD unauthed: 5 req/30s
NVD_API_KEY = os.getenv("NVD_API_KEY", "")


@dataclass
class CVEEntry:
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    cwe_ids: list[str]
    published: str
    source: str
    exploit_available: bool = False
    cisa_known_exploited: bool = False
    exploitdb_ids: list[str] = field(default_factory=list)


@dataclass
class CVEMatch:
    cve: CVEEntry
    matched_finding_id: str
    match_reason: str
    confidence: float


class LiveCVEFeed:
    """Polls NVD + CISA KEV every 2 seconds, streams new CVEs via callback."""

    def __init__(self) -> None:
        self._seen_cve_ids: set[str] = set()
        self._kev_ids: set[str] = set()
        self._cve_cache: list[CVEEntry] = []
        headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
        self._http = httpx.AsyncClient(headers=headers, timeout=10.0)

    async def _fetch_nvd(self, keyword: str | None = None) -> list[CVEEntry]:
        from datetime import datetime, timedelta, timezone as tz
        # Pull CVEs published in last 30 days, sorted newest first
        now = datetime.now(tz.utc)
        start = (now - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S.000")
        end = now.strftime("%Y-%m-%dT%H:%M:%S.000")
        params: dict[str, str] = {
            "resultsPerPage": "20",
            "startIndex": "0",
            "pubStartDate": start,
            "pubEndDate": end,
        }
        if keyword:
            params["keywordSearch"] = keyword
        try:
            resp = await self._http.get(NVD_API_URL, params=params)
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return []

        entries: list[CVEEntry] = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue

            descs = cve.get("descriptions", [])
            desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")

            metrics = cve.get("metrics", {})
            cvss_score = 0.0
            severity = "UNKNOWN"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    m = metrics[key][0]
                    cvss_data = m.get("cvssData", {})
                    cvss_score = float(cvss_data.get("baseScore", 0.0))
                    severity = cvss_data.get("baseSeverity", m.get("baseSeverity", "UNKNOWN"))
                    break

            cwe_ids: list[str] = []
            for weakness in cve.get("weaknesses", []):
                for wd in weakness.get("description", []):
                    val = wd.get("value", "")
                    if val.startswith("CWE-"):
                        cwe_ids.append(val)

            entries.append(CVEEntry(
                cve_id=cve_id,
                description=desc[:300],
                cvss_score=cvss_score,
                severity=severity,
                cwe_ids=cwe_ids,
                published=cve.get("published", ""),
                source="NVD",
                cisa_known_exploited=cve_id in self._kev_ids,
            ))
        return entries

    async def _fetch_cisa_kev(self) -> set[str]:
        try:
            resp = await self._http.get(CISA_KEV_URL)
            resp.raise_for_status()
            data = resp.json()
            return {v["cveID"] for v in data.get("vulnerabilities", [])}
        except Exception:
            return set()

    def _searchsploit(self, service_name: str) -> list[str]:
        """Run searchsploit inside Kali container or locally if available."""
        try:
            result = subprocess.run(
                ["searchsploit", "--json", service_name],
                capture_output=True, text=True, timeout=5
            )
            data = json.loads(result.stdout or "{}")
            exploits = data.get("RESULTS_EXPLOIT", [])
            return [e.get("EDB-ID", "") for e in exploits if e.get("EDB-ID")]
        except Exception:
            return []

    async def poll_forever(self, callback: Callable[[CVEEntry], None], interval: int = POLL_INTERVAL) -> None:
        """Poll NVD + CISA KEV on the given interval, call callback for new CVEs."""
        # Initial CISA KEV load
        self._kev_ids = await self._fetch_cisa_kev()

        tick = 0
        while True:
            try:
                entries = await self._fetch_nvd()
                for entry in entries:
                    if entry.cve_id not in self._seen_cve_ids:
                        self._seen_cve_ids.add(entry.cve_id)
                        entry.cisa_known_exploited = entry.cve_id in self._kev_ids
                        self._cve_cache.append(entry)
                        result = callback(entry)
                        if inspect.isawaitable(result):
                            await result

                # Refresh KEV every 60 seconds (30 ticks × 2s)
                tick += 1
                if tick % 30 == 0:
                    self._kev_ids = await self._fetch_cisa_kev()

            except Exception:
                pass

            await asyncio.sleep(interval)

    def match_to_findings(self, findings: list[dict]) -> list[CVEMatch]:
        """Correlate cached CVEs to scan findings by CWE or keyword."""
        matches: list[CVEMatch] = []
        for finding in findings:
            cwe = finding.get("cwe_id", "")
            vuln_type = finding.get("vuln_type", "").lower()
            for cve in self._cve_cache:
                if cwe and cwe in cve.cwe_ids:
                    matches.append(CVEMatch(
                        cve=cve,
                        matched_finding_id=finding.get("id", ""),
                        match_reason=f"CWE match: {cwe}",
                        confidence=0.90,
                    ))
                elif any(vuln_type in cve.description.lower() for _ in [1]):
                    matches.append(CVEMatch(
                        cve=cve,
                        matched_finding_id=finding.get("id", ""),
                        match_reason=f"Keyword match: {vuln_type}",
                        confidence=0.60,
                    ))
        return matches

    def stream_to_stdout(self, interval: int = POLL_INTERVAL) -> None:
        """Blocking: print CVEs to stdout as they arrive."""
        from rich.console import Console
        from rich.live import Live
        from rich.table import Table

        console = Console()

        def on_cve(entry: CVEEntry) -> None:
            kev_tag = " [KEV]" if entry.cisa_known_exploited else ""
            console.print(
                f"[bold red][LIVE CVE][/bold red] "
                f"[cyan]{entry.cve_id}[/cyan] "
                f"CVSS:[yellow]{entry.cvss_score:.1f}[/yellow] "
                f"[magenta]{entry.severity}[/magenta] "
                f"{entry.description[:80]}...{kev_tag}"
            )

        asyncio.run(self.poll_forever(on_cve, interval=interval))

    async def close(self) -> None:
        await self._http.aclose()
