"""Shodan host intelligence for authorized target recon."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ShodanService:
    ip: str
    port: int
    transport: str
    product: Optional[str] = None
    version: Optional[str] = None
    cpe: List[str] = field(default_factory=list)
    vulns: List[str] = field(default_factory=list)   # CVE IDs from Shodan
    banner: str = ""


def run_shodan_query(target: str, shodan_key: Optional[str] = None) -> List[ShodanService]:
    """Query Shodan for services on the target host.

    Requires SHODAN_API_KEY. Returns empty list with warning if key absent.
    """
    key = shodan_key or os.environ.get("SHODAN_API_KEY")
    if not key:
        print("[osint/shodan] SHODAN_API_KEY not set — skipping Shodan query")
        return []

    try:
        import shodan  # type: ignore
    except ImportError:
        print("[osint/shodan] shodan package not installed — skipping")
        return []

    api = shodan.Shodan(key)
    host_ip = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    try:
        host = api.host(host_ip)
    except Exception as e:
        print(f"[osint/shodan] query failed: {e}")
        return []

    services = []
    for item in host.get("data", []):
        services.append(ShodanService(
            ip=host_ip,
            port=item.get("port", 0),
            transport=item.get("transport", "tcp"),
            product=item.get("product"),
            version=item.get("version"),
            cpe=list(item.get("cpe", [])),
            vulns=list(item.get("vulns", {}).keys()),
            banner=item.get("data", "")[:300],
        ))
    return services
