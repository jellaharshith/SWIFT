"""DNS recon: AXFR, subdomain enumeration, cert transparency."""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from typing import List


@dataclass
class DnsReconResult:
    domain: str
    subdomains: List[str] = field(default_factory=list)
    txt_records: List[str] = field(default_factory=list)
    mx_records: List[str] = field(default_factory=list)
    axfr_success: bool = False
    errors: List[str] = field(default_factory=list)


def run_dns_recon(domain: str, workbench=None, timeout: int = 120) -> DnsReconResult:
    """Enumerate DNS records and subdomains for a domain.

    Uses subfinder + dnsx if available (inside workbench), else falls back to
    system dig/host commands.
    """
    result = DnsReconResult(domain=domain)

    if workbench:
        # Subfinder for passive subdomain enumeration
        try:
            out = workbench.run(
                f"subfinder -d {domain} -silent 2>/dev/null || echo 'subfinder_unavailable'",
                timeout=timeout,
            )
            if "subfinder_unavailable" not in out:
                result.subdomains = [s.strip() for s in out.splitlines() if s.strip()]
        except Exception as e:
            result.errors.append(f"subfinder: {e}")

        # crt.sh via curl for cert transparency
        try:
            crt = workbench.run(
                f"curl -s 'https://crt.sh/?q=%.{domain}&output=json' 2>/dev/null | "
                f"python3 -c \"import sys,json; data=json.load(sys.stdin); "
                f"print('\\n'.join(set(d['name_value'].replace('*.','') for d in data)))\" 2>/dev/null || true",
                timeout=60,
            )
            crt_subs = [s.strip() for s in crt.splitlines() if s.strip() and domain in s]
            result.subdomains = list(set(result.subdomains + crt_subs))
        except Exception as e:
            result.errors.append(f"crt.sh: {e}")

        # TXT records
        try:
            txt = workbench.run(f"dig TXT {domain} +short 2>/dev/null || true", timeout=30)
            result.txt_records = [r.strip() for r in txt.splitlines() if r.strip()]
        except Exception as e:
            result.errors.append(f"dig TXT: {e}")

        # AXFR attempt (usually fails, documents the attempt)
        try:
            axfr = workbench.run(
                f"dig AXFR {domain} 2>/dev/null || true", timeout=30
            )
            result.axfr_success = "Transfer failed" not in axfr and len(axfr) > 100
        except Exception:
            pass
    else:
        # Fallback: system subprocess
        try:
            proc = subprocess.run(
                ["dig", "+short", "TXT", domain],
                capture_output=True, text=True, timeout=30,
            )
            result.txt_records = proc.stdout.splitlines()
        except Exception as e:
            result.errors.append(f"dig fallback: {e}")

    return result
