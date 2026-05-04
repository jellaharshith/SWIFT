"""OSINT orchestrator — runs all recon sources and returns unified OsintResult."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import List, Optional

from osint.dns_recon import run_dns_recon, DnsReconResult
from osint.github_dorks import run_github_dorks, GithubLeak
from osint.shodan_query import run_shodan_query, ShodanService
from osint.whois_asn import run_whois, WhoisResult


@dataclass
class OsintResult:
    target: str
    dns: Optional[DnsReconResult] = None
    whois: Optional[WhoisResult] = None
    github_leaks: List[GithubLeak] = field(default_factory=list)
    shodan_services: List[ShodanService] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "subdomains": self.subdomains,
            "dns_txt_records": self.dns.txt_records if self.dns else [],
            "axfr_success": self.dns.axfr_success if self.dns else False,
            "whois_registrar": self.whois.registrar if self.whois else None,
            "github_leaks": [
                {"repo": g.repo_full_name, "file": g.file_path,
                 "url": g.html_url, "severity": g.severity}
                for g in self.github_leaks
            ],
            "shodan_services": [
                {"port": s.port, "product": s.product,
                 "version": s.version, "vulns": s.vulns}
                for s in self.shodan_services
            ],
            "errors": self.errors,
            "total_findings": (
                len(self.github_leaks) + len(self.shodan_services) + len(self.subdomains)
            ),
        }


async def run_osint(target: str, roe=None, workbench=None) -> OsintResult:
    """Run all OSINT sources concurrently. ROE scope check handled by caller."""
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    result = OsintResult(target=target)

    loop = asyncio.get_event_loop()

    # Run I/O-bound tasks concurrently
    dns_task = loop.run_in_executor(None, run_dns_recon, domain, workbench)
    whois_task = loop.run_in_executor(None, run_whois, domain, workbench)
    github_task = loop.run_in_executor(None, run_github_dorks, domain, None)
    shodan_task = loop.run_in_executor(None, run_shodan_query, domain, None)

    dns_r, whois_r, github_r, shodan_r = await asyncio.gather(
        dns_task, whois_task, github_task, shodan_task,
        return_exceptions=True,
    )

    if isinstance(dns_r, Exception):
        result.errors.append(f"dns: {dns_r}")
    else:
        result.dns = dns_r
        result.subdomains = dns_r.subdomains

    if isinstance(whois_r, Exception):
        result.errors.append(f"whois: {whois_r}")
    else:
        result.whois = whois_r

    if isinstance(github_r, Exception):
        result.errors.append(f"github: {github_r}")
    else:
        result.github_leaks = github_r

    if isinstance(shodan_r, Exception):
        result.errors.append(f"shodan: {shodan_r}")
    else:
        result.shodan_services = shodan_r

    return result
