"""Wayback Machine CDX API URL discovery for historical endpoint enumeration."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

import httpx

__all__ = ["WaybackResult", "run_wayback"]

_INTERESTING_PATTERNS = (
    "/api/", "/admin/", "/auth/", "/graphql", "/.git/",
    "/backup", "/config", "/upload", "/swagger", "/debug",
    "/internal/", "/private/", "/secret", "/.env",
)


@dataclass
class WaybackResult:
    domain: str
    urls: List[str] = field(default_factory=list)
    interesting_paths: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


async def run_wayback(domain: str, limit: int = 200, timeout: int = 30) -> WaybackResult:
    """Discover historical URLs via the Wayback Machine CDX API.

    Args:
        domain: Target domain (e.g. "example.com").
        limit: Maximum number of URLs to retrieve.
        timeout: HTTP request timeout in seconds.

    Returns:
        WaybackResult with unique URLs and flagged interesting paths.
    """
    result = WaybackResult(domain=domain)
    cdx_url = (
        f"http://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}&output=json&fl=original&collapse=urlkey&limit={limit}"
    )

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(cdx_url, follow_redirects=True)
            resp.raise_for_status()
            rows = resp.json()
    except httpx.TimeoutException:
        result.errors.append("wayback: request timed out")
        return result
    except Exception as exc:
        result.errors.append(f"wayback: {exc}")
        return result

    try:
        seen: set[str] = set()
        # CDX returns [["original"], ["url1"], ["url2"], ...]
        # First row is the header ["original"]
        for row in rows[1:]:
            if not row:
                continue
            url = row[0]
            if url and url not in seen:
                seen.add(url)
                result.urls.append(url)
                lower = url.lower()
                if any(pat in lower for pat in _INTERESTING_PATTERNS):
                    result.interesting_paths.append(url)
    except Exception as exc:
        result.errors.append(f"wayback parse: {exc}")

    return result
