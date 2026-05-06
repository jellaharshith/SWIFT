"""API key discovery via bounded wordlist — ROE-gated, rate-limited."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

from log.audit import log_step

# Bounded wordlist — max 50 entries; covers common weak/default API keys
_API_KEY_WORDLIST: list[str] = [
    "test", "dev", "debug", "admin", "secret", "api_key", "apikey",
    "key123", "test123", "password", "letmein", "changeme", "default",
    "sample", "demo", "staging", "prod", "production", "master",
    "token", "access", "key", "auth", "12345", "123456", "qwerty",
    "abc123", "pass", "guest", "root", "toor", "system", "user",
    "api", "service", "internal", "public", "private", "local",
    "development", "testing", "integration", "sandbox", "preview",
    "api-key-1", "apiv1", "v1", "v2", "supersecret", "mykey",
]

_HEADERS_TO_TRY = ["Authorization", "X-API-Key", "api-key", "x-api-token", "api_key"]


@dataclass
class ApiKeyFinding:
    url: str
    header_name: str
    key_value: str
    response_code: int
    confidence: float


async def probe_api_keys(
    url: str,
    roe=None,
    rate_limit: float = 0.5,
    timeout: int = 10,
) -> list[ApiKeyFinding]:
    """Attempt to discover weak API keys via bounded wordlist attack.

    ROE gate: if roe provided, requires "active_scan" in roe.allowed_techniques.
    Rate-limited to rate_limit seconds between attempts. Detects success by
    comparing response codes: baseline 401/403 shifting to 200/201.

    Args:
        url: Target URL to probe.
        roe: Optional ROE object with allowed_techniques set.
        rate_limit: Seconds to sleep between attempts.
        timeout: Per-request timeout.

    Returns:
        List of ApiKeyFinding for any keys that changed the response code.
    """
    if not _HTTPX_AVAILABLE:
        log_step("api_brute.skip", url=url, reason="httpx not installed")
        return []

    # ROE gate: fail-closed if roe provided and active_scan not allowed
    if roe is not None:
        allowed = getattr(roe, "allowed_techniques", set())
        if "active_scan" not in allowed:
            log_step("api_brute.deny", url=url, reason="active_scan not in ROE allowed_techniques")
            return []

    log_step("api_brute.start", url=url, wordlist_size=len(_API_KEY_WORDLIST))

    findings: list[ApiKeyFinding] = []

    async with httpx.AsyncClient(verify=False, timeout=timeout) as client:  # noqa: S501
        # Establish baseline: GET with no auth header
        try:
            baseline_resp = await client.get(url)
            baseline_code = baseline_resp.status_code
        except Exception as exc:  # noqa: BLE001
            log_step("api_brute.baseline_error", url=url, err=str(exc), level="warning")
            return []

        log_step("api_brute.baseline", url=url, baseline_code=baseline_code)

        for header_name in _HEADERS_TO_TRY:
            for key in _API_KEY_WORDLIST:
                # Build the Authorization: Bearer variant or raw key variant
                if header_name == "Authorization":
                    header_value = f"Bearer {key}"
                else:
                    header_value = key

                try:
                    resp = await client.get(url, headers={header_name: header_value})
                    code = resp.status_code
                except Exception as exc:  # noqa: BLE001
                    log_step("api_brute.req_error", url=url, header=header_name, err=str(exc), level="warning")
                    await asyncio.sleep(rate_limit)
                    continue

                # Detect: baseline was 401/403, now 200/201
                if (
                    baseline_code in (401, 403)
                    and code in (200, 201)
                ):
                    finding = ApiKeyFinding(
                        url=url,
                        header_name=header_name,
                        key_value=key,
                        response_code=code,
                        confidence=0.95,
                    )
                    findings.append(finding)
                    log_step(
                        "api_brute.finding",
                        url=url,
                        header=header_name,
                        key=key,
                        code=code,
                    )
                    # Don't stop — enumerate all working keys

                await asyncio.sleep(rate_limit)

    log_step("api_brute.finish", url=url, findings=len(findings))
    return findings
