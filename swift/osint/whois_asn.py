"""WHOIS and ASN lookup for target intel."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class WhoisResult:
    target: str
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiry_date: Optional[str] = None
    name_servers: list = field(default_factory=list)
    asn: Optional[str] = None
    asn_org: Optional[str] = None
    raw: str = ""
    errors: list = field(default_factory=list)


def run_whois(domain: str, workbench=None) -> WhoisResult:
    """Run WHOIS + ASN lookup on a domain."""
    result = WhoisResult(target=domain)

    if workbench:
        try:
            raw = workbench.run(f"whois {domain} 2>/dev/null | head -60", timeout=30)
            result.raw = raw
            for line in raw.splitlines():
                ll = line.lower()
                if "registrar:" in ll:
                    result.registrar = line.split(":", 1)[-1].strip()
                elif "creation date:" in ll or "created:" in ll:
                    result.creation_date = line.split(":", 1)[-1].strip()
                elif "expiry date:" in ll or "expiration" in ll:
                    result.expiry_date = line.split(":", 1)[-1].strip()
                elif "name server:" in ll:
                    result.name_servers.append(line.split(":", 1)[-1].strip())
        except Exception as e:
            result.errors.append(f"whois: {e}")
    else:
        try:
            import whois as python_whois  # type: ignore
            w = python_whois.whois(domain)
            result.registrar = str(w.registrar or "")
            result.creation_date = str(w.creation_date or "")
            result.expiry_date = str(w.expiration_date or "")
            result.name_servers = list(w.name_servers or [])
            result.raw = str(w)
        except Exception as e:
            result.errors.append(f"python-whois: {e}")

    return result
