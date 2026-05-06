"""Build attack surface from OSINT recon results."""
from __future__ import annotations
import asyncio
from agent.bounty_models import AttackSurface


async def build_attack_surface(target: str, recon_result) -> AttackSurface:
    """Build AttackSurface from OSINT runner result.

    Args:
        target: Primary domain/IP being assessed.
        recon_result: Object returned by osint.runner.run_osint(). May be a
            dataclass, SimpleNamespace, or dict — handled uniformly via
            _list() / getattr() guards below.

    Returns:
        Populated AttackSurface ready for the active-probe stage.
    """

    # Safe extraction helper — recon_result may have varying structure
    def _list(obj, *keys):
        for k in keys:
            v = getattr(obj, k, None) or (obj.get(k) if isinstance(obj, dict) else None)
            if v:
                return list(v) if not isinstance(v, list) else v
        return []

    subdomains = _list(recon_result, "subdomains", "discovered_subdomains")

    # Build endpoint list from discovered subdomains + high-value common paths
    base_urls = [f"https://{s}" for s in subdomains] + [f"https://{target}"]
    common_paths = [
        "/login", "/api", "/admin", "/graphql", "/api/v1", "/api/v2",
        "/auth", "/oauth", "/token", "/signup", "/register", "/api/auth",
    ]
    endpoints = base_urls + [f"https://{target}{p}" for p in common_paths]

    auth_keywords = ["login", "auth", "token", "signin", "oauth", "session", "signup", "register"]
    auth_endpoints = [u for u in endpoints if any(k in u.lower() for k in auth_keywords)]

    tech_stack = _list(recon_result, "technologies", "tech_stack", "frameworks")
    github_leaks = _list(recon_result, "github_findings", "github_leaks", "leaked_secrets")
    shodan_info = getattr(recon_result, "shodan", {}) or {}
    open_ports = _list(recon_result, "open_ports", "ports")

    # WS2: new OSINT fields
    raw_tech = _list(recon_result, "technologies")
    technologies = [
        t.name if hasattr(t, "name") else str(t)
        for t in raw_tech
    ]

    raw_takeover = _list(recon_result, "takeover_candidates")
    takeover_candidates = [
        t.subdomain if hasattr(t, "subdomain") else str(t)
        for t in raw_takeover
    ]

    wayback_urls = _list(recon_result, "wayback_interesting", "wayback_urls")

    raw_emails = _list(recon_result, "email_candidates")
    email_candidates = [
        e.email if hasattr(e, "email") else str(e)
        for e in raw_emails
    ]

    # Merge wayback interesting paths into endpoints list for probing
    endpoints = list(set(endpoints + wayback_urls[:50]))  # cap to avoid explosion

    return AttackSurface(
        target=target,
        subdomains=subdomains,
        endpoints=endpoints,
        auth_endpoints=auth_endpoints,
        tech_stack=tech_stack,
        open_ports=[int(p) for p in open_ports if str(p).isdigit()],
        github_leaks=github_leaks,
        shodan_info=shodan_info if isinstance(shodan_info, dict) else {},
        technologies=technologies,
        takeover_candidates=takeover_candidates,
        wayback_urls=wayback_urls,
        email_candidates=email_candidates,
    )
