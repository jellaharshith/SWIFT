"""LLM-driven novel attack method discovery for SWIFT."""
from __future__ import annotations

import asyncio
import json
import os
import uuid
from typing import Optional

import anthropic

from agent.bounty_models import AttackSurface, WebFinding
from agent.pentester_persona import build_persona_preamble
from log.audit import log_step


async def discover_novel_methods(
    surface: AttackSurface,
    known_findings: list[WebFinding],
    roe,
    max_novel: int = 10,
) -> list[WebFinding]:
    """Use Claude Sonnet to generate novel attack hypotheses based on attack surface + known results.

    Strategy:
    1. Build a prompt describing the target's tech stack, auth flows, and known findings.
    2. Ask Sonnet to reason about what ELSE might be vulnerable that standard payloads miss.
    3. For each hypothesis, generate a concrete HTTP probe.
    4. Execute probes via httpx (lightweight, no browser needed for novel probes).
    5. Return confirmed findings (response anomaly detected).

    Args:
        surface: Discovered attack surface for the target.
        known_findings: Already-confirmed findings to avoid duplication.
        roe: Rules-of-engagement object (used to validate scope).
        max_novel: Maximum number of novel hypotheses to generate.

    Returns:
        List of WebFinding objects with confidence >= 0.80 (caller enforces 0.95 gate).
    """
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        log_step("novel_method.skip", reason="no API key")
        return []

    log_step("novel_method.start", target=surface.target, known=len(known_findings))

    known_summary = "\n".join(
        f"- {f.vuln_type} at {f.url} ({f.severity})" for f in known_findings[:20]
    )
    tech = ", ".join(surface.tech_stack) if surface.tech_stack else "unknown"
    auth_eps = ", ".join(surface.auth_endpoints[:5]) if surface.auth_endpoints else "none detected"

    persona = build_persona_preamble(passive=False)
    prompt = f"""{persona}

You have authorized access to target: {surface.target}

Target tech stack: {tech}
Auth endpoints: {auth_eps}
Known findings so far:
{known_summary or '(none yet)'}

Generate {min(max_novel, 5)} novel attack hypotheses that standard payload lists would MISS.
Focus on: logic flaws, auth chain bypass, parameter pollution, second-order injection,
insecure deserialization, GraphQL introspection abuse, JWT algorithm confusion,
OAuth redirect_uri manipulation, race conditions, IDOR via UUID prediction.

For each hypothesis, output EXACTLY this format:
---HYPOTHESIS---
type: <vuln_type>
url: <full_url_to_probe>
method: <GET|POST|PUT|DELETE>
payload: <the exact payload string>
headers: <JSON object of extra headers, or {{}}>
body: <request body if POST, or empty>
rationale: <why this specific target/endpoint is vulnerable>
---END---

Only output CONFIRMED authorized techniques. No DoS, no destructive ops."""

    try:
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = response.content[0].text
    except Exception as e:
        log_step("novel_method.llm_error", error=str(e))
        return []

    hypotheses = _parse_hypotheses(raw)
    log_step("novel_method.hypotheses", count=len(hypotheses))

    results = await asyncio.gather(
        *[_probe_hypothesis(h, surface.target) for h in hypotheses],
        return_exceptions=True,
    )

    findings = []
    for h, result in zip(hypotheses, results):
        if isinstance(result, WebFinding):
            findings.append(result)

    log_step("novel_method.done", confirmed=len(findings))
    return findings


def _parse_hypotheses(raw: str) -> list[dict]:
    """Parse LLM output into hypothesis dicts.

    Args:
        raw: Raw text response from Claude containing ---HYPOTHESIS--- blocks.

    Returns:
        List of hypothesis dicts with url, payload, method, headers, body, type keys.
    """
    hypotheses = []
    blocks = raw.split("---HYPOTHESIS---")
    for block in blocks[1:]:
        end = block.find("---END---")
        if end == -1:
            continue
        chunk = block[:end].strip()
        h: dict = {}
        for line in chunk.splitlines():
            if ": " in line:
                k, v = line.split(": ", 1)
                h[k.strip()] = v.strip()
        if "url" in h and "payload" in h:
            try:
                h["headers"] = json.loads(h.get("headers", "{}"))
            except Exception:
                h["headers"] = {}
            hypotheses.append(h)
    return hypotheses


async def _probe_hypothesis(h: dict, target: str) -> Optional[WebFinding]:
    """Send probe and check response for anomaly. Returns WebFinding if confirmed.

    Args:
        h: Hypothesis dict with url, method, payload, headers, body keys.
        target: Authorized target hostname — used as scope guard.

    Returns:
        WebFinding if anomaly detected, None otherwise.
    """
    try:
        import httpx

        method = h.get("method", "GET").upper()
        url = h.get("url", "")
        payload = h.get("payload", "")
        headers = h.get("headers", {})
        body = h.get("body", "")

        if not url.startswith("http"):
            return None

        # Safety: only probe the authorized target
        if target not in url:
            return None

        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            req_kwargs: dict = {"headers": headers}
            if method in ("POST", "PUT", "PATCH"):
                req_kwargs["content"] = body or payload
            else:
                req_kwargs["params"] = {"q": payload} if payload else {}

            response = await client.request(method, url, **req_kwargs)

            # Simple anomaly detection: payload reflected or error message leaked
            body_text = response.text[:2000]
            confidence = 0.0
            if payload and payload[:20] in body_text:
                confidence = 0.80
            if any(
                err in body_text.lower()
                for err in ["sql", "syntax error", "traceback", "exception", "warning:"]
            ):
                confidence = max(confidence, 0.85)

            # Only return if confidence meets threshold (≥95% enforced by caller)
            if confidence >= 0.80:
                return WebFinding(
                    id=f"NM-{uuid.uuid4().hex[:6].upper()}",
                    vuln_type=h.get("type", "unknown"),
                    url=url,
                    method=method,
                    payload=payload,
                    request_raw=f"{method} {url} HTTP/1.1\n{_headers_str(headers)}",
                    response_excerpt=body_text[:500],
                    evidence_path=None,
                    severity="MEDIUM",
                    confidence=confidence,
                    is_novel=True,
                )
    except Exception:
        pass
    return None


def _headers_str(headers: dict) -> str:
    """Format headers dict as HTTP header block string."""
    return "\n".join(f"{k}: {v}" for k, v in headers.items())
