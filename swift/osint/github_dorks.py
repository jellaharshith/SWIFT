"""GitHub dork search for leaked secrets and internal endpoints."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class GithubLeak:
    query: str
    repo_full_name: str
    file_path: str
    html_url: str
    snippet: str
    severity: str = "HIGH"


_DORK_PATTERNS = [
    ("password=", "CRITICAL"),
    ("aws_secret_access_key", "CRITICAL"),
    ("BEGIN RSA PRIVATE KEY", "CRITICAL"),
    ("BEGIN EC PRIVATE KEY", "CRITICAL"),
    ("Authorization: Bearer", "HIGH"),
    ("api_key", "HIGH"),
    ("secret_key", "HIGH"),
    ("STRIPE_SECRET", "CRITICAL"),
    ("SENDGRID_API_KEY", "HIGH"),
    ("DATABASE_URL", "HIGH"),
    ("filename:.env", "HIGH"),
    ("filename:.pem", "CRITICAL"),
]


def run_github_dorks(domain: str, github_token: Optional[str] = None) -> List[GithubLeak]:
    """Search GitHub for leaked secrets related to the domain.

    Requires GITHUB_TOKEN env var. Returns empty list if token absent (with warning).
    """
    token = github_token or os.environ.get("GITHUB_TOKEN")
    if not token:
        print("[osint/github_dorks] GITHUB_TOKEN not set — skipping GitHub dork search")
        return []

    try:
        from github import Github  # type: ignore
        gh = Github(token)
    except ImportError:
        print("[osint/github_dorks] PyGithub not installed — skipping")
        return []

    leaks: List[GithubLeak] = []
    base_domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    for pattern, severity in _DORK_PATTERNS:
        query = f'"{base_domain}" {pattern}'
        try:
            results = gh.search_code(query)
            for item in list(results)[:5]:  # cap at 5 per dork
                leaks.append(GithubLeak(
                    query=query,
                    repo_full_name=item.repository.full_name,
                    file_path=item.path,
                    html_url=item.html_url,
                    snippet=item.decoded_content.decode("utf-8", errors="replace")[:200]
                    if hasattr(item, "decoded_content") else "",
                    severity=severity,
                ))
        except Exception:
            continue  # Rate limit or search failure — continue to next dork

    return leaks
