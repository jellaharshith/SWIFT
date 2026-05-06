"""OSINT orchestrator — runs all recon sources and returns unified OsintResult."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import List, Optional

from osint.dns_recon import run_dns_recon, DnsReconResult
from osint.github_dorks import run_github_dorks, GithubLeak
from osint.shodan_query import run_shodan_query, ShodanService
from osint.whois_asn import run_whois, WhoisResult
from osint.crtsh import run_crtsh, CrtshResult
from osint.subdomain_takeover import run_subdomain_takeover, TakeoverCandidate
from osint.wayback import run_wayback, WaybackResult
from osint.tech_fingerprint import run_tech_fingerprint, TechFingerprint
from osint.email_enum import run_email_enum, EmailCandidate


@dataclass
class OsintResult:
    target: str
    dns: Optional[DnsReconResult] = None
    whois: Optional[WhoisResult] = None
    github_leaks: List[GithubLeak] = field(default_factory=list)
    shodan_services: List[ShodanService] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    # WS2 new fields
    crtsh_subdomains: List[str] = field(default_factory=list)
    takeover_candidates: List[TakeoverCandidate] = field(default_factory=list)
    wayback_urls: List[str] = field(default_factory=list)
    wayback_interesting: List[str] = field(default_factory=list)
    technologies: List[TechFingerprint] = field(default_factory=list)
    email_candidates: List[EmailCandidate] = field(default_factory=list)
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
            "crtsh_subdomains": self.crtsh_subdomains,
            "takeover_candidates": [
                {"subdomain": t.subdomain, "cname": t.cname,
                 "service": t.service, "confidence": t.confidence}
                for t in self.takeover_candidates
            ],
            "wayback_urls_count": len(self.wayback_urls),
            "wayback_interesting": self.wayback_interesting,
            "technologies": [
                {"name": t.name, "category": t.category,
                 "confidence": t.confidence, "evidence": t.evidence}
                for t in self.technologies
            ],
            "email_candidates": [
                {"email": e.email, "pattern": e.pattern, "confidence": e.confidence}
                for e in self.email_candidates
            ],
            "errors": self.errors,
            "total_findings": (
                len(self.github_leaks) + len(self.shodan_services) + len(self.subdomains)
                + len(self.takeover_candidates) + len(self.wayback_interesting)
                + len(self.technologies)
            ),
        }


async def run_osint(
    target: str,
    roe=None,
    workbench=None,
    hunter_api_key: str | None = None,
) -> OsintResult:
    """Run all 10 OSINT sources concurrently. ROE scope check handled by caller.

    Args:
        target: Domain or URL to recon.
        roe: ROE object (unused here, scope check done by caller).
        workbench: Optional Kali workbench for tool-based recon.
        hunter_api_key: Optional hunter.io key for email enumeration.

    Returns:
        OsintResult aggregating all 10 source results.
    """
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    result = OsintResult(target=target)
    base_url = f"https://{domain}"

    loop = asyncio.get_event_loop()

    # Original 4 sources (sync wrappers → executor)
    dns_task = loop.run_in_executor(None, run_dns_recon, domain, workbench)
    whois_task = loop.run_in_executor(None, run_whois, domain, workbench)
    github_task = loop.run_in_executor(None, run_github_dorks, domain, None)
    shodan_task = loop.run_in_executor(None, run_shodan_query, domain, None)

    # New 5 async sources
    crtsh_task = run_crtsh(domain)
    wayback_task = run_wayback(domain)
    tech_task = run_tech_fingerprint(base_url)
    email_task = run_email_enum(domain, hunter_api_key=hunter_api_key)
    # subdomain_takeover needs subdomains — run after DNS + crtsh complete below

    (
        dns_r, whois_r, github_r, shodan_r,
        crtsh_r, wayback_r, tech_r, email_r,
    ) = await asyncio.gather(
        dns_task, whois_task, github_task, shodan_task,
        crtsh_task, wayback_task, tech_task, email_task,
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

    if isinstance(crtsh_r, Exception):
        result.errors.append(f"crtsh: {crtsh_r}")
    else:
        result.crtsh_subdomains = crtsh_r.subdomains
        result.errors.extend(crtsh_r.errors)
        # Merge crtsh subdomains into the main list
        result.subdomains = list(set(result.subdomains + crtsh_r.subdomains))

    if isinstance(wayback_r, Exception):
        result.errors.append(f"wayback: {wayback_r}")
    else:
        result.wayback_urls = wayback_r.urls
        result.wayback_interesting = wayback_r.interesting_paths
        result.errors.extend(wayback_r.errors)

    if isinstance(tech_r, Exception):
        result.errors.append(f"tech_fingerprint: {tech_r}")
    else:
        result.technologies = tech_r.technologies
        result.errors.extend(tech_r.errors)

    if isinstance(email_r, Exception):
        result.errors.append(f"email_enum: {email_r}")
    else:
        result.email_candidates = email_r.candidates
        result.errors.extend(email_r.errors)

    # Subdomain takeover — needs merged subdomain list from DNS + crtsh
    all_subdomains = result.subdomains
    if all_subdomains:
        try:
            takeover_r = await run_subdomain_takeover(all_subdomains)
            result.takeover_candidates = takeover_r.candidates
            result.errors.extend(takeover_r.errors)
        except Exception as exc:
            result.errors.append(f"subdomain_takeover: {exc}")

    return result
