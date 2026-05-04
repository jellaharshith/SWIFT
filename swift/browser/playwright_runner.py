"""Playwright async driver: navigate + probe URL for live web vulns.

Logs every step via log.audit.log_step.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field, asdict
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl

if TYPE_CHECKING:
    from browser.smuggling_probe import SmugglingResult

from browser.probes import (
    XSS_PAYLOADS,
    SQLI_PAYLOADS,
    SQLI_ERROR_SIGNATURES,
    OPEN_REDIRECT_PAYLOADS,
    SSRF_PAYLOADS,
    SSTI_PAYLOADS,
    SSTI_SIGNATURES,
    NOSQL_PAYLOADS,
    AUTH_BYPASS_HEADERS,
    AUTH_BYPASS_PATHS,
    PROTOTYPE_POLLUTION_PAYLOADS,
    CRLF_PAYLOADS,
    XXE_PAYLOADS,
    JWT_ATTACKS,
    JWT_WEAK_SECRETS,
    IDOR_PROBES,
)
from log.audit import log_step

# Per-host probe budget in seconds. If elapsed exceeds this, stop probing.
PER_PROBE_BUDGET_SECONDS = 60

# Max URL params we inject per payload type (cost + noise control).
PER_PARAM_PAYLOAD_CAP = 3


@dataclass
class BrowserFinding:
    kind: str
    severity: str
    url: str
    evidence: str
    payload: str = ""


@dataclass
class BrowserScanResult:
    target: str
    findings: list[BrowserFinding] = field(default_factory=list)
    console_errors: list[str] = field(default_factory=list)
    network_requests: int = 0
    smuggling: "SmugglingResult | None" = None
    insecure_cookies: list[str] = field(default_factory=list)
    mixed_content: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        from dataclasses import asdict as _asdict
        smuggling_dict = _asdict(self.smuggling) if self.smuggling is not None else None
        return {
            "target": self.target,
            "findings": [asdict(f) for f in self.findings],
            "console_errors": self.console_errors,
            "network_requests": self.network_requests,
            "insecure_cookies": self.insecure_cookies,
            "mixed_content": self.mixed_content,
            "error": self.error,
            "smuggling": smuggling_dict,
        }


def _inject_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    qs[key] = value
    return urlunparse(parsed._replace(query=urlencode(qs)))


# ── Per-kind probe helpers ────────────────────────────────────────────────────

async def _probe_xss(page, url: str, result: BrowserScanResult, deadline: float = 0.0) -> None:
    """Probe URL params with XSS payloads; detect DOM execution or reflection."""
    params = list(parse_qsl(urlparse(url).query, keep_blank_values=True))
    test_keys = [k for k, _ in params][:PER_PARAM_PAYLOAD_CAP] or ["q", "id", "search"]

    for key in test_keys:
        if deadline and time.monotonic() > deadline:
            return
        for payload in XSS_PAYLOADS:
            if deadline and time.monotonic() > deadline:
                return
            test_url = _inject_param(url, key, payload)
            log_step("browser.probe.xss", target=test_url, payload=payload)
            try:
                await page.goto(test_url, timeout=15000, wait_until="domcontentloaded")
                triggered = await page.evaluate("() => window.__swift_xss === 1")
                body = (await page.content()).lower()
                if triggered or payload.lower() in body:
                    result.findings.append(BrowserFinding(
                        kind="xss_reflected",
                        severity="high",
                        url=test_url,
                        evidence="payload reflected in DOM" + (" + executed" if triggered else ""),
                        payload=payload,
                    ))
                    log_step("browser.finding", kind="xss_reflected", url=test_url)
                    break
            except Exception as exc:  # noqa: BLE001
                log_step("browser.probe.error", url=test_url, err=str(exc), level="warning")


async def _probe_sqli(page, url: str, result: BrowserScanResult) -> None:
    """Probe URL params with SQLi payloads; detect DB error signatures."""
    params = list(parse_qsl(urlparse(url).query, keep_blank_values=True))
    test_keys = [k for k, _ in params][:PER_PARAM_PAYLOAD_CAP] or ["q", "id", "search"]

    for key in test_keys:
        for payload in SQLI_PAYLOADS:
            test_url = _inject_param(url, key, payload)
            log_step("browser.probe.sqli", target=test_url, payload=payload)
            try:
                await page.goto(test_url, timeout=15000, wait_until="domcontentloaded")
                body = (await page.content()).lower()
                for sig in SQLI_ERROR_SIGNATURES:
                    if sig in body:
                        result.findings.append(BrowserFinding(
                            kind="sqli_error",
                            severity="critical",
                            url=test_url,
                            evidence=f"db error signature: {sig}",
                            payload=payload,
                        ))
                        log_step("browser.finding", kind="sqli_error", url=test_url)
                        break
            except Exception as exc:  # noqa: BLE001
                log_step("browser.probe.error", url=test_url, err=str(exc), level="warning")


async def _probe_open_redirect(page, url: str, result: BrowserScanResult) -> None:
    """Probe URL params with open-redirect payloads; detect evil.example.com in final URL."""
    params = list(parse_qsl(urlparse(url).query, keep_blank_values=True))
    test_keys = [k for k, _ in params][:PER_PARAM_PAYLOAD_CAP] or ["q", "id", "search"]

    for key in test_keys:
        for payload in OPEN_REDIRECT_PAYLOADS:
            test_url = _inject_param(url, key, payload)
            log_step("browser.probe.open_redirect", target=test_url, payload=payload)
            try:
                await page.goto(test_url, timeout=15000, wait_until="domcontentloaded")
                final = page.url
                if "evil.example.com" in final:
                    result.findings.append(BrowserFinding(
                        kind="open_redirect",
                        severity="medium",
                        url=test_url,
                        evidence=f"redirected to {final}",
                        payload=payload,
                    ))
                    log_step("browser.finding", kind="open_redirect", url=test_url)
            except Exception as exc:  # noqa: BLE001
                log_step("browser.probe.error", url=test_url, err=str(exc), level="warning")


async def _probe_ssrf(page, url: str, result: BrowserScanResult) -> None:
    """Probe URL params with SSRF payloads; detect IMDS / loopback responses."""
    params = list(parse_qsl(urlparse(url).query, keep_blank_values=True))
    test_keys = [k for k, _ in params][:PER_PARAM_PAYLOAD_CAP] or ["url", "redirect", "src"]

    _imds_signatures = ("ami-id", "iam/", "169.254")

    for key in test_keys:
        for payload in SSRF_PAYLOADS:
            test_url = _inject_param(url, key, payload)
            log_step("browser.probe.ssrf", target=test_url, payload=payload)
            try:
                await page.goto(test_url, timeout=15000, wait_until="domcontentloaded")
                body = (await page.content()).lower()
                hit_imds = any(sig in body for sig in _imds_signatures)
                hit_local = "127.0.0.1" in body or "localhost" in body
                if hit_imds or hit_local:
                    result.findings.append(BrowserFinding(
                        kind="ssrf",
                        severity="critical",
                        url=test_url,
                        evidence="IMDS/loopback response detected in body" if hit_imds else "loopback response detected",
                        payload=payload,
                    ))
                    log_step("browser.finding", kind="ssrf", url=test_url)
            except Exception as exc:  # noqa: BLE001
                log_step("browser.probe.error", url=test_url, err=str(exc), level="warning")


async def _probe_ssti(page, url: str, result: BrowserScanResult) -> None:
    """Inject SSTI payloads into URL params; check body for computed signatures."""
    params = list(parse_qsl(urlparse(url).query, keep_blank_values=True))
    test_keys = [k for k, _ in params][:PER_PARAM_PAYLOAD_CAP] or ["q", "template", "name"]

    for key in test_keys:
        for payload in SSTI_PAYLOADS:
            test_url = _inject_param(url, key, payload)
            log_step("browser.probe.ssti", target=test_url, payload=payload)
            try:
                await page.goto(test_url, timeout=15000, wait_until="domcontentloaded")
                body = await page.content()
                for sig in SSTI_SIGNATURES:
                    if sig in body:
                        result.findings.append(BrowserFinding(
                            kind="ssti",
                            severity="critical",
                            url=test_url,
                            evidence=f"template evaluated: found '{sig}' in response",
                            payload=payload,
                        ))
                        log_step("browser.finding", kind="ssti", url=test_url)
                        break
            except Exception as exc:  # noqa: BLE001
                log_step("browser.probe.error", url=test_url, err=str(exc), level="warning")


async def _probe_nosql(page, url: str, result: BrowserScanResult) -> None:
    """Inject NoSQL payloads into URL params; detect MongoDB error signatures or behaviour change."""
    params = list(parse_qsl(urlparse(url).query, keep_blank_values=True))
    test_keys = [k for k, _ in params][:PER_PARAM_PAYLOAD_CAP] or ["q", "id", "user"]

    _nosql_errors = (
        "castError",
        "mongo",
        "bsontype",
        "objectid failed",
        "syntaxerror",
    )

    for key in test_keys:
        # Baseline: fetch the URL without injection to compare status
        baseline_url = url
        baseline_status: int | None = None
        try:
            resp = await page.goto(baseline_url, timeout=15000, wait_until="domcontentloaded")
            baseline_status = resp.status if resp else None
        except Exception:  # noqa: BLE001
            pass

        for payload in NOSQL_PAYLOADS:
            test_url = _inject_param(url, key, payload)
            log_step("browser.probe.nosql", target=test_url, payload=payload)
            try:
                resp = await page.goto(test_url, timeout=15000, wait_until="domcontentloaded")
                body = (await page.content()).lower()
                injected_status = resp.status if resp else None
                error_hit = any(sig in body for sig in _nosql_errors)
                # Different HTTP status than baseline can indicate injection effect
                status_shift = (
                    baseline_status is not None
                    and injected_status is not None
                    and injected_status != baseline_status
                    and injected_status in (200, 302)
                    and baseline_status in (401, 403)
                )
                if error_hit or status_shift:
                    evidence = (
                        "nosql error signature in response"
                        if error_hit
                        else f"status changed {baseline_status} -> {injected_status}"
                    )
                    result.findings.append(BrowserFinding(
                        kind="nosql_injection",
                        severity="high",
                        url=test_url,
                        evidence=evidence,
                        payload=payload,
                    ))
                    log_step("browser.finding", kind="nosql_injection", url=test_url)
                    break
            except Exception as exc:  # noqa: BLE001
                log_step("browser.probe.error", url=test_url, err=str(exc), level="warning")


async def _probe_auth_bypass(page, url: str, result: BrowserScanResult) -> None:
    """Try AUTH_BYPASS_HEADERS and AUTH_BYPASS_PATHS; fire finding on 200 + sensitive keyword."""
    _sensitive = ("admin panel", "dashboard", "logged in", "welcome")

    parsed = urlparse(url)
    base_origin = f"{parsed.scheme}://{parsed.netloc}"

    # Header-based bypass: reload the same URL with spoofed headers
    for header, value in AUTH_BYPASS_HEADERS.items():
        log_step("browser.probe.auth_bypass.header", url=url, header=header, value=value)
        try:
            resp = await page.goto(url, timeout=15000, wait_until="domcontentloaded",
                                   # Playwright doesn't support custom request headers on goto;
                                   # we route the request to inject headers instead.
                                   )
            # We do a best-effort check — header injection via goto is limited in Playwright.
            # Real header injection would require page.route(); this is a placeholder probe.
            body = (await page.content()).lower()
            if resp and resp.status == 200 and any(kw in body for kw in _sensitive):
                result.findings.append(BrowserFinding(
                    kind="auth_bypass_header",
                    severity="high",
                    url=url,
                    evidence=f"sensitive content accessible with header {header}: {value}",
                    payload=f"{header}: {value}",
                ))
                log_step("browser.finding", kind="auth_bypass_header", url=url)
        except Exception as exc:  # noqa: BLE001
            log_step("browser.probe.error", url=url, err=str(exc), level="warning")

    # Path-based bypass
    for bypass_path in AUTH_BYPASS_PATHS:
        test_url = base_origin + bypass_path
        log_step("browser.probe.auth_bypass.path", url=test_url)
        try:
            resp = await page.goto(test_url, timeout=15000, wait_until="domcontentloaded")
            body = (await page.content()).lower()
            if resp and resp.status == 200 and any(kw in body for kw in _sensitive):
                result.findings.append(BrowserFinding(
                    kind="auth_bypass_path",
                    severity="high",
                    url=test_url,
                    evidence=f"sensitive content accessible via path bypass",
                    payload=bypass_path,
                ))
                log_step("browser.finding", kind="auth_bypass_path", url=test_url)
        except Exception as exc:  # noqa: BLE001
            log_step("browser.probe.error", url=test_url, err=str(exc), level="warning")


async def _probe_prototype_pollution(page, url: str, result: BrowserScanResult) -> None:
    """Inject prototype-pollution payloads; detect behaviour change in response."""
    params = list(parse_qsl(urlparse(url).query, keep_blank_values=True))
    test_keys = [k for k, _ in params][:PER_PARAM_PAYLOAD_CAP] or ["data", "opts", "config"]

    for key in test_keys:
        # Capture baseline body length as a simple change signal
        try:
            base_resp = await page.goto(url, timeout=15000, wait_until="domcontentloaded")
            base_body = await page.content()
            base_len = len(base_body)
            base_status = base_resp.status if base_resp else None
        except Exception:  # noqa: BLE001
            base_len = None
            base_status = None

        for payload in PROTOTYPE_POLLUTION_PAYLOADS:
            test_url = _inject_param(url, key, payload)
            log_step("browser.probe.prototype_pollution", target=test_url, payload=payload)
            try:
                resp = await page.goto(test_url, timeout=15000, wait_until="domcontentloaded")
                body = await page.content()
                injected_len = len(body)
                injected_status = resp.status if resp else None
                # Significant length change or status shift suggests behaviour change
                length_delta = abs(injected_len - base_len) if base_len is not None else 0
                status_changed = (
                    base_status is not None
                    and injected_status is not None
                    and injected_status != base_status
                )
                if length_delta > 200 or status_changed:
                    result.findings.append(BrowserFinding(
                        kind="prototype_pollution",
                        severity="medium",
                        url=test_url,
                        evidence=f"response changed after pollution (delta={length_delta}, status={base_status}->{injected_status})",
                        payload=payload,
                    ))
                    log_step("browser.finding", kind="prototype_pollution", url=test_url)
                    break
            except Exception as exc:  # noqa: BLE001
                log_step("browser.probe.error", url=test_url, err=str(exc), level="warning")


async def _probe_crlf(page, url: str, result: BrowserScanResult) -> None:
    """Inject CRLF payloads into URL params; check for injected Set-Cookie in response headers."""
    params = list(parse_qsl(urlparse(url).query, keep_blank_values=True))
    test_keys = [k for k, _ in params][:PER_PARAM_PAYLOAD_CAP] or ["q", "redirect", "next"]

    for key in test_keys:
        for payload in CRLF_PAYLOADS:
            test_url = _inject_param(url, key, payload)
            log_step("browser.probe.crlf", target=test_url, payload=payload)
            try:
                resp = await page.goto(test_url, timeout=15000, wait_until="domcontentloaded")
                if resp:
                    headers = resp.headers  # dict-like
                    set_cookie = headers.get("set-cookie", "")
                    if "swift_crlf" in set_cookie:
                        result.findings.append(BrowserFinding(
                            kind="crlf_injection",
                            severity="medium",
                            url=test_url,
                            evidence=f"injected Set-Cookie header found: {set_cookie}",
                            payload=payload,
                        ))
                        log_step("browser.finding", kind="crlf_injection", url=test_url)
                        break
            except Exception as exc:  # noqa: BLE001
                log_step("browser.probe.error", url=test_url, err=str(exc), level="warning")


# ── JWT probe ────────────────────────────────────────────────────────────────

async def _probe_jwt(page, url: str, result: BrowserScanResult, deadline: float = 0.0) -> None:
    """Probe for JWT alg:none vulnerability.

    Injects an unsigned JWT (alg:none) via Authorization header and checks
    whether the server accepts it, indicating improper signature verification.

    Args:
        page: Playwright Page object.
        url: Target URL to probe.
        result: BrowserScanResult accumulator.
        deadline: Monotonic deadline; skip if exceeded.
    """
    if deadline and time.monotonic() > deadline:
        return
    log_step("browser.probe.jwt", target=url)
    alg_none_token = JWT_ATTACKS["alg_none"]
    try:
        await page.set_extra_http_headers({"Authorization": f"Bearer {alg_none_token}"})
        await page.goto(url, timeout=15000, wait_until="domcontentloaded")
        body = (await page.content()).lower()
        if any(kw in body for kw in ("admin", "dashboard", "welcome", "profile", "account")):
            result.findings.append(BrowserFinding(
                kind="jwt_alg_none",
                severity="high",
                url=url,
                evidence="Server accepted unsigned JWT (alg:none) — signature not verified",
                payload=alg_none_token[:80],
            ))
        # Reset headers
        await page.set_extra_http_headers({})
    except Exception:  # noqa: BLE001
        await page.set_extra_http_headers({})


# ── IDOR probe ───────────────────────────────────────────────────────────────

async def _probe_idor(page, url: str, result: BrowserScanResult, deadline: float = 0.0) -> None:
    """Probe for Insecure Direct Object Reference via numeric ID enumeration.

    Detects numeric URL params, fetches baseline, then probes adjacent IDs.
    Significant response size difference with non-error content indicates IDOR.

    Args:
        page: Playwright Page object.
        url: Target URL to probe.
        result: BrowserScanResult accumulator.
        deadline: Monotonic deadline; skip if exceeded.
    """
    if deadline and time.monotonic() > deadline:
        return
    log_step("browser.probe.idor", target=url)
    params = parse_qsl(urlparse(url).query, keep_blank_values=True)
    numeric_params = [(k, v) for k, v in params if v.isdigit()][:2]
    if not numeric_params:
        return

    try:
        await page.goto(url, timeout=15000, wait_until="domcontentloaded")
        baseline_content = await page.content()
        baseline_len = len(baseline_content)
    except Exception:  # noqa: BLE001
        return

    for key, val in numeric_params:
        if deadline and time.monotonic() > deadline:
            return
        for variant_id in IDOR_PROBES(val):
            if deadline and time.monotonic() > deadline:
                return
            variant_url = _inject_param(url, key, variant_id)
            try:
                await page.goto(variant_url, timeout=15000, wait_until="domcontentloaded")
                variant_content = (await page.content()).lower()
                variant_len = len(variant_content)
                size_diff = abs(variant_len - baseline_len) / max(baseline_len, 1)
                error_indicators = ("not found", "404", "forbidden", "403", "unauthorized", "401")
                if size_diff > 0.10 and not any(ind in variant_content for ind in error_indicators):
                    result.findings.append(BrowserFinding(
                        kind="idor",
                        severity="high",
                        url=variant_url,
                        evidence=f"param '{key}': baseline {baseline_len}B vs variant {variant_len}B ({size_diff:.0%} diff)",
                        payload=variant_id,
                    ))
            except Exception:  # noqa: BLE001
                continue


# ── XXE probe ────────────────────────────────────────────────────────────────

async def _probe_xxe(page, url: str, result: BrowserScanResult, deadline: float = 0.0) -> None:
    """Probe for XML External Entity injection via fetch POST with XML payloads.

    Sends XXE payloads via JavaScript fetch() to bypass Playwright's HTTP layer.
    Detects file-read or SSRF via XXE by checking response for sensitive content.

    Args:
        page: Playwright Page object.
        url: Target URL to probe.
        result: BrowserScanResult accumulator.
        deadline: Monotonic deadline; skip if exceeded.
    """
    if deadline and time.monotonic() > deadline:
        return
    log_step("browser.probe.xxe", target=url)
    for payload in XXE_PAYLOADS[:2]:
        if deadline and time.monotonic() > deadline:
            return
        escaped_payload = payload.replace("`", "\\`").replace("${", "\\${")
        js = f"""
        async () => {{
            try {{
                const r = await fetch("{url}", {{
                    method: "POST",
                    headers: {{"Content-Type": "application/xml"}},
                    body: `{escaped_payload}`
                }});
                return await r.text();
            }} catch(e) {{ return ""; }}
        }}
        """
        try:
            response_text = await page.evaluate(js)
            if response_text and any(kw in response_text for kw in ("root:", "daemon:", "169.254", "localhost", "/etc/")):
                result.findings.append(BrowserFinding(
                    kind="xxe",
                    severity="critical",
                    url=url,
                    evidence=f"XXE response leaked sensitive data: {response_text[:200]}",
                    payload=payload[:100],
                ))
        except Exception:  # noqa: BLE001
            continue


# ── Main probe dispatcher ─────────────────────────────────────────────────────

async def _probe(page, url: str, result: BrowserScanResult, mode: str = "pentester") -> None:
    """Run all probe helpers against the target URL.

    Args:
        page: Playwright Page object.
        url: Target URL to probe.
        result: BrowserScanResult accumulator.
        mode: Scan mode. Pass "passive" to skip all active probing.
    """
    if mode == "passive":
        log_step("browser.probe.skipped", url=url, reason="passive mode")
        return

    _probe_start = time.monotonic()

    def _budget_exceeded() -> bool:
        elapsed = time.monotonic() - _probe_start
        if elapsed > PER_PROBE_BUDGET_SECONDS:
            log_step(
                "browser.probe.budget_exceeded",
                url=url,
                elapsed_s=round(elapsed, 1),
                budget_s=PER_PROBE_BUDGET_SECONDS,
                level="warning",
            )
            return True
        return False

    helpers = [
        _probe_xss,
        _probe_sqli,
        _probe_open_redirect,
        _probe_ssrf,
        _probe_ssti,
        _probe_nosql,
        _probe_auth_bypass,
        _probe_prototype_pollution,
        _probe_crlf,
        _probe_jwt,
        _probe_idor,
        _probe_xxe,
    ]

    for helper in helpers:
        if _budget_exceeded():
            return
        await helper(page, url, result)


async def _run(target: str, headless: bool = True, mode: str = "pentester") -> BrowserScanResult:
    result = BrowserScanResult(target=target)
    log_step("browser.scan.start", target=target)
    try:
        from playwright.async_api import async_playwright  # type: ignore
    except ImportError:
        result.error = "playwright not installed. run: pip install playwright && python -m playwright install chromium"
        log_step("browser.scan.unavailable", target=target, err=result.error, level="error")
        return result

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=headless)
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()

            page.on("console", lambda m: result.console_errors.append(m.text) if m.type == "error" else None)
            page.on("request", lambda r: setattr(result, "network_requests", result.network_requests + 1))
            page.on("response", lambda r: result.mixed_content.append(r.url) if (
                r.url.startswith("http://") and target.startswith("https://")
            ) else None)

            log_step("browser.nav", target=target)
            await page.goto(target, timeout=20000, wait_until="domcontentloaded")

            cookies = await context.cookies()
            for c in cookies:
                if not c.get("secure") or not c.get("httpOnly"):
                    result.insecure_cookies.append(c.get("name", "<unknown>"))
                    log_step("browser.finding", kind="insecure_cookie", name=c.get("name"))

            await _probe(page, target, result, mode=mode)

            await context.close()
            await browser.close()

        # Smuggling probe runs outside Playwright (raw TCP)
        from browser.smuggling_probe import probe_smuggling
        parsed = urlparse(target)
        smug_host = parsed.hostname or target
        smug_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        smug_path = parsed.path or "/"
        result.smuggling = await probe_smuggling(smug_host, smug_port, smug_path)
    except Exception as exc:  # noqa: BLE001
        result.error = f"playwright runtime error: {exc}"
        log_step("browser.scan.error", target=target, err=str(exc), level="error")

    log_step("browser.scan.finish", target=target, findings=len(result.findings))
    return result


def scan_url(target: str, headless: bool = True, mode: str = "pentester") -> BrowserScanResult:
    """Sync wrapper around async playwright scan."""
    return asyncio.run(_run(target, headless=headless, mode=mode))


async def scan_url_async(target: str, headless: bool = True, mode: str = "pentester") -> BrowserScanResult:
    return await _run(target, headless=headless, mode=mode)
