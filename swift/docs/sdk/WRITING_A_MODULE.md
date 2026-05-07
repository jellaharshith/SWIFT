# Writing a SWIFT Module

A SWIFT module is a Python class (~50 lines) that detects one vulnerability class.
This guide walks you through building, testing, and publishing one.

---

## Minimal Working Example: CSRF Check

```python
# my_swift_modules/csrf_probe.py
import httpx
from sdk.base import BaseModule, Finding, Phase, VulnType, Severity
from sdk.decorators import roe_gated

class CsrfProbe(BaseModule):
    name = "csrf"
    phase = Phase.ACTIVE
    vuln_types = [VulnType.CSRF]
    author = "your-github-handle"
    version = "1.0.0"

    @roe_gated("active_scan")
    async def probe(self, target, session, roe) -> list[Finding]:
        findings = []
        url = str(target)
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            # GET the form page
            resp = await client.get(url)
            if resp.status_code != 200:
                return []
            # Look for forms without CSRF tokens
            has_csrf = any(
                keyword in resp.text.lower()
                for keyword in ("csrf", "_token", "authenticity_token", "__requestverificationtoken")
            )
            if not has_csrf and "<form" in resp.text.lower():
                findings.append(Finding(
                    module=self.name,
                    vuln_type=VulnType.CSRF,
                    severity=Severity.MEDIUM,
                    title="Potential CSRF: form missing CSRF token",
                    description="Form found with no CSRF protection token in response.",
                    target_url=url,
                    confidence=0.75,
                    cwe_id=352,
                    remediation="Add CSRF tokens to all state-changing forms.",
                    request_evidence=f"GET {url}",
                    response_evidence=resp.text[:500],
                ))
        return findings
```

---

## Using SessionManager for Credential Chaining

When your probe obtains credentials (OAuth token, session cookie), store them
in `SessionManager` so subsequent probes can reuse them:

```python
# After finding a valid OAuth token:
await session.set_oauth_token(token="eyJ...", expires_at=None)
# Mark the finding as a chain primitive:
finding.chain_primitive = "oauth_token"
```

Available methods:
- `session.set_oauth_token(token, expires_at=None)` — sets Authorization header
- `session.set_ws_token(token)` — stores WebSocket auth token
- `session.set_header(key, value)` — sets arbitrary header
- `session.get_headers()` → `dict[str, str]`

---

## Using Playwright Inside a Module

```python
from playwright.async_api import async_playwright

async def _playwright_check(self, url: str) -> str:
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()
        try:
            await page.goto(url, timeout=15000)
            return await page.content()
        finally:
            await browser.close()
```

Always close the browser in a `finally` block.

---

## Calling Claude Haiku from a Module

Use prompt caching to avoid re-sending the system prompt on every call:

```python
import anthropic
import os

_CLIENT = None

def _get_client() -> anthropic.Anthropic:
    global _CLIENT
    if _CLIENT is None:
        _CLIENT = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    return _CLIENT

SYSTEM_PROMPT = "You are a security researcher. Analyse this HTTP response for vulnerabilities."

async def _ask_haiku(response_body: str) -> str:
    import asyncio
    loop = asyncio.get_event_loop()
    def _call():
        return _get_client().messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=512,
            system=[{
                "type": "text",
                "text": SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},  # prompt caching
            }],
            messages=[{"role": "user", "content": response_body[:4000]}],
        )
    msg = await loop.run_in_executor(None, _call)
    return msg.content[0].text
```

---

## Testing with SwiftTestHarness

```python
# test_csrf_probe.py
import pytest
from sdk.testing import SwiftTestHarness
from my_swift_modules.csrf_probe import CsrfProbe

async def test_csrf_detected():
    harness = SwiftTestHarness(CsrfProbe())
    # The real probe uses httpx — mock it with respx or patch at the httpx level
    # For a quick unit test, just call run() against a test server or mock:
    harness.mock_http("http://target.com", 200,
                      "<html><form method='POST'><input type='text'/></form></html>")
    # With no mock_http plumbing yet (see roadmap), use a real local server:
    # findings = await harness.run("http://localhost:8080/form")
    # harness.assert_finding(vuln_type="csrf", severity="MEDIUM", min_confidence=0.7)
    # harness.assert_roe_respected("active_scan")
    pass  # placeholder until mock_http httpx integration lands in v6.1

async def test_no_csrf_issue_on_safe_form():
    harness = SwiftTestHarness(CsrfProbe())
    # harness.mock_http("http://safe.com", 200,
    #     "<form><input name='_token' value='abc'/></form>")
    # findings = await harness.run("http://safe.com")
    # harness.assert_no_findings()
    pass
```

---

## Publishing to PyPI

1. Create `pyproject.toml`:

```toml
[project]
name = "swift-csrf-probe"
version = "1.0.0"
dependencies = ["httpx>=0.24"]

[project.entry-points."swift.modules"]
csrf = "my_swift_modules.csrf_probe:CsrfProbe"
```

2. Build + publish:

```bash
pip install build twine
python -m build
twine upload dist/*
```

3. Install in SWIFT:

```bash
swiftsec plugin install swift-csrf-probe
swiftsec plugin list
```

---

## Security Review Checklist Before Publishing

Before publishing a module, verify:

- [ ] **Input validation:** All probe parameters validated; no shell injection via `subprocess`
- [ ] **ROE compliance:** `@roe_gated("technique")` applied to `probe()` method
- [ ] **Rate limiting:** No unbounded loops; max request count enforced
- [ ] **Redaction:** No passwords/tokens/CC numbers written to logs
- [ ] **No `eval()`:** No dynamic code execution on attacker-controlled input
- [ ] **Timeout:** All HTTP calls have explicit `timeout=10` (or less)
- [ ] **Confidence gate:** Only report findings with `confidence >= 0.5`; prefer `>= 0.9`
- [ ] **simulate_only honoured:** `@roe_gated` handles this automatically
- [ ] **No destructive side-effects:** Module must not delete data, send emails, or call payment APIs
- [ ] **Tests pass:** `swiftsec plugin validate <path>` returns ✓ for all classes
