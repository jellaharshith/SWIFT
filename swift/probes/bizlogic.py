"""Business Logic vulnerability probe (Module 4)."""
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field

import httpx  # module-level for test patching

from audit.decorators import audit_logged
from sdk.base import BaseModule, Finding, Phase, Severity, VulnType
from sdk.decorators import roe_gated

# Embed verbatim from spec — do NOT paraphrase
ANALYZER_PROMPT = """You are a CISSP-certified penetration tester analyzing an application workflow for business logic vulnerabilities. Given this application flow graph, identify the 5 most promising attack scenarios. For each: specify exact HTTP parameters to manipulate, expected normal value, attack value, and what the vulnerability enables. Focus on: negative quantities, price manipulation, workflow step skipping, race conditions in state transitions, coupon stacking, privilege boundaries between steps. Respond as a JSON array only, no prose."""

_CLIENT = None

def _get_client():
    global _CLIENT
    if _CLIENT is None:
        import os

        import anthropic
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if api_key:
            _CLIENT = anthropic.Anthropic(api_key=api_key)
    return _CLIENT


@dataclass
class Field:
    name: str
    type: str
    value: str = ""
    is_numeric: bool = False
    is_hidden: bool = False


@dataclass
class FlowStep:
    url: str
    method: str
    fields: list[Field] = field(default_factory=list)
    step_number: int | None = None
    total_steps: int | None = None


@dataclass
class AppFlow:
    steps: list[FlowStep] = field(default_factory=list)
    numeric_fields: list[Field] = field(default_factory=list)
    state_graph: dict[str, list[str]] = field(default_factory=dict)
    multi_step_flows: list[list[FlowStep]] = field(default_factory=list)


@dataclass
class BusinessLogicAttack:
    attack_type: str
    target_step: int
    target_field: str
    normal_value: str
    attack_value: str
    hypothesis: str
    severity_estimate: str


class AppFlowMapper:
    """Crawl app with Playwright to map forms and multi-step flows."""

    async def map(self, base_url: str, session=None) -> AppFlow:
        flow = AppFlow()
        try:
            from playwright.async_api import async_playwright
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                context = await browser.new_context()
                page = await context.new_page()
                try:
                    await page.goto(base_url, timeout=15000)
                    # Dismiss cookie banners
                    for sel in ["button:has-text('Accept')", "button:has-text('OK')",
                                 "button:has-text('Agree')", "[id*='cookie'] button"]:
                        try:
                            await page.click(sel, timeout=2000)
                        except Exception:
                            pass
                    # Extract forms
                    forms = await page.query_selector_all("form")
                    for form in forms:
                        action = await form.get_attribute("action") or base_url
                        method = (await form.get_attribute("method") or "GET").upper()
                        inputs = await form.query_selector_all("input, select, textarea")
                        fields = []
                        for inp in inputs:
                            name = await inp.get_attribute("name") or ""
                            itype = await inp.get_attribute("type") or "text"
                            value = await inp.get_attribute("value") or ""
                            is_hidden = itype == "hidden"
                            is_numeric = any(kw in name.lower() for kw in
                                           ("price", "qty", "quantity", "amount", "count",
                                            "balance", "discount", "coupon", "total"))
                            fields.append(Field(name=name, type=itype, value=value,
                                               is_numeric=is_numeric, is_hidden=is_hidden))
                        step = FlowStep(url=action, method=method, fields=fields)
                        # Detect step indicators
                        content = await page.content()
                        m = re.search(r"step\s+(\d+)\s+of\s+(\d+)", content, re.IGNORECASE)
                        if m:
                            step.step_number = int(m.group(1))
                            step.total_steps = int(m.group(2))
                        flow.steps.append(step)
                        flow.numeric_fields.extend(f for f in fields if f.is_numeric)
                    # Build state graph
                    for i, step in enumerate(flow.steps):
                        next_url = flow.steps[i + 1].url if i + 1 < len(flow.steps) else None
                        if next_url:
                            flow.state_graph.setdefault(step.url, []).append(next_url)
                    # Detect multi-step flows
                    if any(s.total_steps for s in flow.steps):
                        flow.multi_step_flows.append(flow.steps)
                finally:
                    await browser.close()
        except Exception:
            pass
        return flow


class FlowAnalyzer:
    """Use Sonnet to identify business logic attack scenarios."""

    def __init__(self) -> None:
        self._sonnet_calls = 0
        self._max_sonnet_calls = 3

    async def analyze(self, flow: AppFlow) -> list[BusinessLogicAttack]:
        if self._sonnet_calls >= self._max_sonnet_calls:
            return []
        client = _get_client()
        if not client:
            return []
        flow_summary = {
            "steps": len(flow.steps),
            "numeric_fields": [f.name for f in flow.numeric_fields],
            "state_graph": flow.state_graph,
            "multi_step": bool(flow.multi_step_flows),
            "urls": [s.url for s in flow.steps],
        }
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            def _call():
                return client.messages.create(
                    model="claude-sonnet-4-6",
                    max_tokens=2048,
                    system=[{
                        "type": "text",
                        "text": ANALYZER_PROMPT,
                        "cache_control": {"type": "ephemeral"},
                    }],
                    messages=[{"role": "user", "content": json.dumps(flow_summary)}],
                )
            msg = await loop.run_in_executor(None, _call)
            self._sonnet_calls += 1
            raw = msg.content[0].text.strip()
            # Strip markdown fences if present
            if raw.startswith("```"):
                raw = re.sub(r"^```[a-z]*\n?", "", raw)
                raw = re.sub(r"\n?```$", "", raw)
            attacks_data = json.loads(raw)
            return [BusinessLogicAttack(**a) for a in attacks_data
                    if all(k in a for k in ("attack_type", "target_step", "target_field",
                                             "normal_value", "attack_value", "hypothesis",
                                             "severity_estimate"))]
        except Exception:
            return []


class BusinessLogicProbe(BaseModule):
    name = "bizlogic"
    phase = Phase.ACTIVE
    vuln_types = [VulnType.BIZLOGIC]  # noqa: RUF012
    author = "swift-core"
    version = "1.0"

    def __init__(self) -> None:
        self._analyzer = FlowAnalyzer()

    @roe_gated("bizlogic")
    @audit_logged("probe_executed")
    async def probe(self, target, session, roe) -> list[Finding]:
        base_url = str(target)
        findings: list[Finding] = []

        flow = await AppFlowMapper().map(base_url, session)
        await self._analyzer.analyze(flow)

        tasks = [
            self._negative_quantity(flow, base_url),
            self._price_tampering(flow, base_url, session),
            self._workflow_step_skip(flow, base_url, session),
            self._coupon_stacking(flow, base_url, session),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)

        return findings

    async def _negative_quantity(self, flow: AppFlow, base_url: str) -> list[Finding]:
        findings = []
        if not flow.numeric_fields:
            return []
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                for attack_val in ["-1", "-99", "0", "9999999", "1.5"]:
                    for step in flow.steps:
                        for f in step.fields:
                            if not f.is_numeric:
                                continue
                            payload = {fi.name: fi.value for fi in step.fields}
                            payload[f.name] = attack_val
                            try:
                                if step.method == "POST":
                                    resp = await client.post(step.url, data=payload)
                                else:
                                    resp = await client.get(step.url, params=payload)
                                body = resp.text.lower()
                                if any(kw in body for kw in
                                       ("order", "success", "confirmed", "credit", "thank")):
                                    findings.append(Finding(
                                        module=self.name,
                                        vuln_type=VulnType.BIZLOGIC,
                                        severity=Severity.CRITICAL,
                                        title=f"Negative quantity accepted: {f.name}={attack_val}",
                                        description=f"Application accepted {f.name}={attack_val} and appears to have processed it.",
                                        target_url=step.url,
                                        confidence=0.8,
                                        request_evidence=json.dumps(payload),
                                        response_evidence=resp.text[:300],
                                        remediation="Validate quantity/amount fields server-side. Reject values ≤ 0.",
                                    ))
                            except Exception:
                                pass
        except Exception:
            pass
        return findings

    async def _price_tampering(self, flow: AppFlow, base_url: str, session) -> list[Finding]:
        """Intercept POST requests and replace price/amount fields."""
        findings = []
        try:
            from playwright.async_api import async_playwright
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                context = await browser.new_context()
                page = await context.new_page()
                try:
                    tampered = {}
                    async def intercept(route, request):
                        if request.method == "POST":
                            post_data = request.post_data or ""
                            # Replace price/amount values
                            for kw in ("price", "amount", "total", "cost"):
                                post_data = re.sub(
                                    rf"({kw}=)[^&]+", r"\g<1>0.01", post_data, flags=re.IGNORECASE
                                )
                            tampered["intercepted"] = True
                            await route.continue_(post_data=post_data)
                        else:
                            await route.continue_()

                    await page.route("**/*", intercept)
                    await page.goto(base_url, timeout=10000)
                    await asyncio.sleep(1)
                    content = await page.content()
                    if tampered.get("intercepted") and any(
                        kw in content.lower() for kw in ("success", "order", "thank", "confirmed")
                    ):
                        findings.append(Finding(
                            module=self.name,
                            vuln_type=VulnType.BIZLOGIC,
                            severity=Severity.HIGH,
                            title="Price tampering: order completed at $0.01",
                            description="Intercepted POST and replaced price with 0.01. Order appears to have succeeded.",
                            target_url=base_url,
                            confidence=0.75,
                            remediation="Validate prices server-side against product catalog. Never trust client-submitted prices.",
                        ))
                finally:
                    await browser.close()
        except Exception:
            pass
        return findings

    async def _workflow_step_skip(self, flow: AppFlow, base_url: str, session) -> list[Finding]:
        """Attempt to access final-step URL without completing prior steps."""
        findings = []
        if len(flow.steps) < 2:
            return []
        final = flow.steps[-1]
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                resp = await client.get(final.url)
                if resp.status_code == 200 and "error" not in resp.text.lower():
                    findings.append(Finding(
                        module=self.name,
                        vuln_type=VulnType.BIZLOGIC,
                        severity=Severity.HIGH,
                        title=f"Workflow step skip: final step accessible at {final.url}",
                        description="Final workflow step reachable without completing prior steps. Server-side state not validated.",
                        target_url=final.url,
                        confidence=0.7,
                        remediation="Enforce server-side workflow state. Store step completion in session, not client.",
                    ))
        except Exception:
            pass
        return findings

    async def _coupon_stacking(self, flow: AppFlow, base_url: str, session) -> list[Finding]:
        """Apply same coupon code N=10 times concurrently."""
        findings = []
        coupon_fields = [f for s in flow.steps for f in s.fields
                         if any(kw in f.name.lower() for kw in ("coupon", "promo", "code", "voucher"))]
        if not coupon_fields:
            return []
        cf = coupon_fields[0]
        step = next(s for s in flow.steps if cf in s.fields)
        try:
            import httpx
            payload = {fi.name: fi.value for fi in step.fields}
            payload[cf.name] = "SAVE10"
            async def apply_once(client: httpx.AsyncClient):
                try:
                    if step.method == "POST":
                        return await client.post(step.url, data=payload)
                    return await client.get(step.url, params=payload)
                except Exception:
                    return None
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                responses = await asyncio.gather(*[apply_once(client) for _ in range(10)])
            successes = sum(
                1 for r in responses
                if r and r.status_code == 200 and "discount" in r.text.lower()
            )
            if successes > 1:
                findings.append(Finding(
                    module=self.name,
                    vuln_type=VulnType.BIZLOGIC,
                    severity=Severity.MEDIUM,
                    title=f"Coupon stacking: same code applied {successes}x concurrently",
                    description=f"Concurrent coupon applications returned {successes} successes. Race condition allows stacking discounts.",
                    target_url=step.url,
                    confidence=0.8,
                    remediation="Apply distributed lock on coupon redemption. Check redemption count atomically.",
                ))
        except Exception:
            pass
        return findings
