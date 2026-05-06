"""Subdomain takeover detection via CNAME fingerprinting."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import List

__all__ = ["TakeoverCandidate", "SubdomainTakeoverResult", "run_subdomain_takeover"]

# Map CNAME suffix → service name.  More entries = better coverage.
_SERVICE_FINGERPRINTS: dict[str, str] = {
    "github.io": "github",
    "s3.amazonaws.com": "aws_s3",
    "s3-website": "aws_s3",
    "azurewebsites.net": "azure",
    "cloudapp.azure.com": "azure",
    "blob.core.windows.net": "azure_blob",
    "herokuapp.com": "heroku",
    "herokudns.com": "heroku",
    "netlify.app": "netlify",
    "netlify.com": "netlify",
    "pages.github.com": "github_pages",
    "readthedocs.io": "readthedocs",
    "fastly.net": "fastly",
    "pantheonsite.io": "pantheon",
    "wpengine.com": "wpengine",
    "ghost.io": "ghost",
    "surge.sh": "surge",
    "bitbucket.io": "bitbucket",
    "zendesk.com": "zendesk",
}


@dataclass
class TakeoverCandidate:
    subdomain: str
    cname: str
    service: str
    confidence: float


@dataclass
class SubdomainTakeoverResult:
    domain: str
    candidates: List[TakeoverCandidate] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


async def _check_subdomain(subdomain: str, timeout: int) -> TakeoverCandidate | None:
    """Resolve CNAME for *subdomain* and fingerprint it.

    Returns a TakeoverCandidate if the CNAME matches a known dangling-service
    pattern, else None.
    """
    try:
        import dns.asyncresolver
        import dns.exception

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = float(timeout)
        try:
            answer = await resolver.resolve(subdomain, "CNAME")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            return None

        cname_target = str(answer[0].target).rstrip(".")
        for suffix, service in _SERVICE_FINGERPRINTS.items():
            if suffix in cname_target:
                # Check whether the CNAME target itself resolves
                confidence = 0.7
                try:
                    await resolver.resolve(cname_target, "A")
                except (dns.resolver.NXDOMAIN, dns.exception.DNSException):
                    # NXDOMAIN on CNAME target → dangling, higher confidence
                    confidence = 0.9
                return TakeoverCandidate(
                    subdomain=subdomain,
                    cname=cname_target,
                    service=service,
                    confidence=confidence,
                )
    except Exception:
        pass
    return None


async def run_subdomain_takeover(
    subdomains: List[str],
    timeout: int = 10,
) -> SubdomainTakeoverResult:
    """Check each subdomain for potential takeover via dangling CNAME.

    Args:
        subdomains: List of FQDNs to check.
        timeout: Per-subdomain DNS resolution timeout in seconds.

    Returns:
        SubdomainTakeoverResult with any takeover candidates found.
    """
    domain = subdomains[0].split(".", 1)[-1] if subdomains else "unknown"
    result = SubdomainTakeoverResult(domain=domain)

    if not subdomains:
        return result

    try:
        tasks = [_check_subdomain(sub, timeout) for sub in subdomains]
        outcomes = await asyncio.gather(*tasks, return_exceptions=True)
        for outcome in outcomes:
            if isinstance(outcome, Exception):
                result.errors.append(f"takeover check: {outcome}")
            elif outcome is not None:
                result.candidates.append(outcome)
    except Exception as exc:
        result.errors.append(f"subdomain_takeover: {exc}")

    return result
