"""Email enumeration via common pattern guessing and optional hunter.io integration."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

import httpx

__all__ = ["EmailCandidate", "EmailEnumResult", "run_email_enum"]

_DEFAULT_MAILBOXES = [
    "admin", "info", "security", "support", "dev", "api", "contact",
    "webmaster", "abuse", "noreply", "hello", "team", "jobs", "hr",
    "sales", "billing", "legal",
]


def _guess_patterns(name: str, domain: str) -> List[tuple[str, str]]:
    """Return (email, pattern_label) guesses for a single name token."""
    parts = name.lower().replace("-", ".").replace("_", ".").split(".")
    if len(parts) == 1:
        # Treat as a standalone mailbox (admin, info, …)
        return [(f"{parts[0]}@{domain}", "mailbox")]
    first, last = parts[0], parts[-1]
    return [
        (f"{first}.{last}@{domain}", "first.last"),
        (f"{first[0]}{last}@{domain}", "flast"),
        (f"{first}@{domain}", "first"),
        (f"{first}{last[0]}@{domain}", "firstl"),
    ]


@dataclass
class EmailCandidate:
    email: str
    pattern: str
    confidence: float


@dataclass
class EmailEnumResult:
    domain: str
    candidates: List[EmailCandidate] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


async def run_email_enum(
    domain: str,
    names: Optional[List[str]] = None,
    hunter_api_key: Optional[str] = None,
    timeout: int = 20,
) -> EmailEnumResult:
    """Enumerate likely email addresses for *domain*.

    Args:
        domain: Target domain (e.g. "example.com").
        names: Person names or mailbox names to generate patterns from.
            Defaults to common role-based mailboxes if None.
        hunter_api_key: Optional hunter.io API key for verified lookup.
        timeout: HTTP request timeout in seconds.

    Returns:
        EmailEnumResult with guessed and/or verified candidates.
    """
    result = EmailEnumResult(domain=domain)
    source_names = names if names is not None else _DEFAULT_MAILBOXES

    # Pattern-guessed candidates (confidence 0.3)
    seen: set[str] = set()
    for name in source_names:
        for email, pattern in _guess_patterns(name, domain):
            if email not in seen:
                seen.add(email)
                result.candidates.append(
                    EmailCandidate(email=email, pattern=pattern, confidence=0.3)
                )

    # hunter.io enrichment (confidence 0.8 for verified emails)
    if hunter_api_key:
        hunter_url = (
            f"https://api.hunter.io/v2/domain-search"
            f"?domain={domain}&api_key={hunter_api_key}"
        )
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(hunter_url)
                resp.raise_for_status()
                data = resp.json()
            for entry in data.get("data", {}).get("emails", []):
                email = entry.get("value", "")
                if email and email not in seen:
                    seen.add(email)
                    result.candidates.append(
                        EmailCandidate(
                            email=email,
                            pattern="hunter.io",
                            confidence=0.8,
                        )
                    )
        except httpx.TimeoutException:
            result.errors.append("email_enum hunter.io: timed out")
        except Exception as exc:
            result.errors.append(f"email_enum hunter.io: {exc}")

    return result
