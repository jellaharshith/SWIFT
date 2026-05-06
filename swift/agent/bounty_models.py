"""Data models for SWIFT Bug Bounty pipeline."""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from agent.niche_classifier import NicheProfile


@dataclass
class WebFinding:
    """A confirmed vulnerability found via active web probing."""

    id: str                       # e.g. "WF-001"
    vuln_type: str                # xss, sqli, idor, auth_bypass, misconfig, ssrf, etc.
    url: str                      # target URL
    method: str                   # GET, POST, etc.
    payload: str                  # payload used
    request_raw: str              # full HTTP request (redacted headers ok)
    response_excerpt: str         # relevant part of response
    evidence_path: Optional[str]  # screenshot or response dump path
    severity: str                 # CRITICAL, HIGH, MEDIUM, LOW
    confidence: float             # 0.0-1.0
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp: Optional[str] = None
    remediation: Optional[str] = None
    impact: Optional[str] = None
    is_novel: bool = False        # True if found by LLM novel-method discovery


@dataclass
class AttackSurface:
    """Discovered attack surface for a target."""

    target: str
    subdomains: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)       # full URLs
    auth_endpoints: list[str] = field(default_factory=list)  # login/session endpoints
    tech_stack: list[str] = field(default_factory=list)      # e.g. ["nginx", "React", "PostgreSQL"]
    open_ports: list[int] = field(default_factory=list)
    github_leaks: list[str] = field(default_factory=list)    # leaked secrets/endpoints from GitHub
    shodan_info: dict = field(default_factory=dict)
    technologies: list[str] = field(default_factory=list)         # from tech_fingerprint
    takeover_candidates: list[str] = field(default_factory=list)  # subdomains at risk
    wayback_urls: list[str] = field(default_factory=list)         # historical endpoints
    email_candidates: list[str] = field(default_factory=list)     # guessed emails


@dataclass
class PostExploitResult:
    """Result of a sandboxed post-exploitation simulation."""

    finding_id: str          # WebFinding.id that triggered this
    sim_type: str            # c2, data_exfil, persistence
    feasibility: str         # high, medium, low
    attack_tree: str         # text description of attack path
    mitigations: list[str] = field(default_factory=list)
    simulate_only: bool = True  # ALWAYS True — never real execution


@dataclass
class BountyResult:
    """Final result of a bug bounty engagement run."""

    engagement_id: str
    target: str
    scope_path: Optional[str]
    roe_path: str
    findings: list[WebFinding] = field(default_factory=list)
    post_exploit: list[PostExploitResult] = field(default_factory=list)
    report_path: Optional[str] = None
    attack_surface: Optional[AttackSurface] = None
    vpn_egress_ip: Optional[str] = None
    autonomous: bool = False
    niche_profile: Optional["NicheProfile"] = None

    def to_dict(self) -> dict:
        import dataclasses
        d = dataclasses.asdict(self)
        # niche_profile is not a standard dataclass — serialize manually
        if self.niche_profile is not None:
            d["niche_profile"] = self.niche_profile.to_dict()
        return d
