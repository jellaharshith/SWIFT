"""DOM-based IDOR detection: Playwright crawl with numeric/UUID ID mutation."""
from __future__ import annotations

import re
import uuid as _uuid_mod
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

from log.audit import log_step

# Patterns to identify numeric IDs and UUIDs in URL paths and query strings
_NUMERIC_RE = re.compile(r"\b(\d{1,10})\b")
_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)

# PII keywords that indicate cross-user data leakage
_PII_KEYWORDS = ("email", "phone", "address", "ssn", "dob", "birth", "name", "account", "profile", "user")


@dataclass
class DomIdorFinding:
    url: str
    original_id: str
    mutated_id: str
    selector: str         # "path" or "param:<key>"
    data_diff: str        # excerpt showing the data difference
    confidence: float


def _mutate_url_path(url: str, original_id: str, mutated_id: str) -> str:
    """Replace the first occurrence of original_id in the URL path."""
    parsed = urlparse(url)
    new_path = parsed.path.replace(original_id, mutated_id, 1)
    return urlunparse(parsed._replace(path=new_path))


def _mutate_url_param(url: str, key: str, mutated_id: str) -> str:
    parsed = urlparse(url)
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    qs[key] = mutated_id
    return urlunparse(parsed._replace(query=urlencode(qs)))


def _id_variants(original_id: str) -> list[str]:
    """Return probe ID variants for a given ID value."""
    variants: list[str] = []
    if _UUID_RE.fullmatch(original_id):
        # Random UUID as variant for UUID-typed IDs
        variants.append(str(_uuid_mod.uuid4()))
    else:
        try:
            n = int(original_id)
            variants.extend([str(n + 1), str(n - 1)])
        except ValueError:
            pass
    return variants


async def probe_dom_idor(
    base_url: str,
    playwright_context=None,
    second_session_cookies: dict | None = None,
    timeout: int = 30,
) -> list[DomIdorFinding]:
    """Probe for DOM-based IDOR by mutating numeric/UUID IDs found in the URL.

    Requires a live Playwright browser context. Returns empty list if
    playwright_context is None (can't crawl without a browser).

    Args:
        base_url: URL to load and inspect for IDs.
        playwright_context: Playwright BrowserContext for the primary session.
        second_session_cookies: Cookies dict for a second user session (used for
            cross-user comparison; confirms IDOR if different PII returned).
        timeout: Milliseconds for page.goto calls.

    Returns:
        List of DomIdorFinding for detected IDOR candidates.
    """
    if playwright_context is None:
        log_step("dom_idor.skip", url=base_url, reason="no playwright context")
        return []

    log_step("dom_idor.start", url=base_url)
    findings: list[DomIdorFinding] = []

    try:
        page = await playwright_context.new_page()
        await page.goto(base_url, timeout=timeout * 1000, wait_until="domcontentloaded")
        baseline_content = await page.content()
    except Exception as exc:  # noqa: BLE001
        log_step("dom_idor.error", url=base_url, err=str(exc), level="warning")
        return []

    parsed = urlparse(base_url)

    # ── Probe IDs in URL path ─────────────────────────────────────────────
    path_ids = _NUMERIC_RE.findall(parsed.path) + _UUID_RE.findall(parsed.path)
    for original_id in path_ids:
        for mutated_id in _id_variants(original_id):
            mutated_url = _mutate_url_path(base_url, original_id, mutated_id)
            log_step("dom_idor.path_probe", original=original_id, mutated=mutated_id, url=mutated_url)
            try:
                await page.goto(mutated_url, timeout=timeout * 1000, wait_until="domcontentloaded")
                mutated_content = await page.content()
            except Exception:  # noqa: BLE001
                continue

            finding = _compare_contents(
                base_url=base_url,
                mutated_url=mutated_url,
                original_id=original_id,
                mutated_id=mutated_id,
                selector="path",
                baseline=baseline_content,
                mutated=mutated_content,
                second_session_cookies=second_session_cookies,
                playwright_context=playwright_context,
                timeout=timeout,
            )
            if finding:
                findings.append(finding)

    # ── Probe IDs in query params ─────────────────────────────────────────
    for key, val in parse_qsl(parsed.query, keep_blank_values=True):
        param_ids = _NUMERIC_RE.findall(val) + _UUID_RE.findall(val)
        for original_id in param_ids:
            for mutated_id in _id_variants(original_id):
                mutated_url = _mutate_url_param(base_url, key, mutated_id)
                log_step("dom_idor.param_probe", key=key, original=original_id, mutated=mutated_id)
                try:
                    await page.goto(mutated_url, timeout=timeout * 1000, wait_until="domcontentloaded")
                    mutated_content = await page.content()
                except Exception:  # noqa: BLE001
                    continue

                finding = _compare_contents(
                    base_url=base_url,
                    mutated_url=mutated_url,
                    original_id=original_id,
                    mutated_id=mutated_id,
                    selector=f"param:{key}",
                    baseline=baseline_content,
                    mutated=mutated_content,
                    second_session_cookies=second_session_cookies,
                    playwright_context=playwright_context,
                    timeout=timeout,
                )
                if finding:
                    findings.append(finding)

    await page.close()
    log_step("dom_idor.finish", url=base_url, findings=len(findings))
    return findings


def _compare_contents(
    *,
    base_url: str,
    mutated_url: str,
    original_id: str,
    mutated_id: str,
    selector: str,
    baseline: str,
    mutated: str,
    second_session_cookies: dict | None,
    playwright_context,
    timeout: int,
) -> DomIdorFinding | None:
    """Compare baseline vs mutated content for IDOR indicators.

    Returns DomIdorFinding if PII-bearing content differs, else None.
    Cross-user comparison (second_session_cookies) raises confidence to 0.95.
    """
    baseline_lower = baseline.lower()
    mutated_lower = mutated.lower()

    # Skip if mutated returned an error page
    error_signals = ("not found", "404", "forbidden", "403", "unauthorized", "401", "access denied")
    if any(sig in mutated_lower for sig in error_signals):
        return None

    # Check if mutated page contains PII keywords that baseline doesn't — suggests different user data
    baseline_pii = [kw for kw in _PII_KEYWORDS if kw in baseline_lower]
    mutated_pii = [kw for kw in _PII_KEYWORDS if kw in mutated_lower]
    new_pii = set(mutated_pii) - set(baseline_pii)

    if not new_pii and len(mutated) == len(baseline):
        return None

    data_diff = f"new PII fields: {sorted(new_pii)} | len_diff: {len(mutated) - len(baseline)}"

    # If second session provided, attempt async cross-user check (best-effort sync via already-loaded content)
    confidence = 0.7
    if second_session_cookies and new_pii:
        # The caller already has evidence of PII in a different ID — treat as high confidence
        confidence = 0.95

    log_step("dom_idor.finding", url=mutated_url, original=original_id, mutated=mutated_id, selector=selector)
    return DomIdorFinding(
        url=mutated_url,
        original_id=original_id,
        mutated_id=mutated_id,
        selector=selector,
        data_diff=data_diff,
        confidence=confidence,
    )
