"""Certificate transparency subdomain enumeration via crt.sh JSON API."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

import httpx

__all__ = ["CrtshResult", "run_crtsh"]


@dataclass
class CrtshResult:
    domain: str
    subdomains: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


async def run_crtsh(domain: str, timeout: int = 30) -> CrtshResult:
    """Enumerate subdomains via crt.sh certificate transparency logs.

    Args:
        domain: Target domain (e.g. "example.com").
        timeout: HTTP request timeout in seconds.

    Returns:
        CrtshResult with deduplicated subdomains.
    """
    result = CrtshResult(domain=domain)
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url, follow_redirects=True)
            resp.raise_for_status()
            data = resp.json()
    except httpx.TimeoutException:
        result.errors.append("crtsh: request timed out")
        return result
    except Exception as exc:
        result.errors.append(f"crtsh: {exc}")
        return result

    try:
        seen: set[str] = set()
        for entry in data:
            raw = entry.get("name_value", "")
            for name in raw.splitlines():
                name = name.strip().lstrip("*.")
                if name and domain in name and name not in seen:
                    seen.add(name)
                    result.subdomains.append(name)
    except Exception as exc:
        result.errors.append(f"crtsh parse: {exc}")

    return result
