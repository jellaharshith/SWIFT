"""LLM-powered payload mutation via Claude Haiku.

Generates context-aware payloads based on the detected tech stack and
previously failed payload attempts. Falls back to hardcoded payloads
when API is unavailable or --no-llm-payloads is set.

Uses prompt caching (cache_control: ephemeral) on the system prompt to
reduce cost on repeated calls (~75% savings on second call+).
"""
from __future__ import annotations

import hashlib
import json
from typing import Dict, List, Optional

_CACHE: Dict[str, List[str]] = {}

_SYSTEM_PROMPT = """You are an expert web application penetration tester.
Your task is to generate precise exploit payloads for a specific vulnerability type.

Rules:
- Generate exactly N payloads, one per line, no numbering, no explanation
- Payloads must be URL-safe strings or valid inputs for the vulnerability type
- Vary encoding, capitalization, whitespace tricks to bypass common WAF patterns
- If context mentions a specific framework (Django, Rails, Spring, Express), target its quirks
- If previous_failures are given, generate payloads that DIFFER from those patterns
- Never include shell commands that would damage the target system
- Focus on detection/proof-of-concept only (not destructive exploits)"""

_TYPE_INSTRUCTIONS = {
    "xss": "XSS payloads that execute JavaScript and set window.__swift_xss=1. Bypass HTML encoding, attribute context, JS string context, CSP where possible.",
    "sqli": "SQL injection payloads for boolean/time-based/error-based detection. Vary quote style, comment syntax, encoding.",
    "ssrf": "SSRF payloads targeting internal services: localhost, 127.0.0.1, 169.254.169.254 (AWS IMDS), 0.0.0.0, [::1]. Include URL schemes: http, https, dict, file.",
    "ssti": "SSTI payloads for Jinja2, Twig, Freemarker, ERB, Velocity. Use math expressions like {{7*7}} that produce deterministic output.",
    "idor": "IDOR ID variants: increment/decrement, UUID guessing, object type confusion (numeric→string), negative IDs.",
    "crlf": "CRLF injection: URL-encoded \\r\\n, double-encoded, partial encoding. Set-Cookie and Location headers.",
    "xxe": "XXE payloads: file read (/etc/passwd), SSRF, entity reference loops for OOB. Both SYSTEM and PUBLIC identifiers.",
    "nosql": "NoSQL injection for MongoDB: $ne, $gt, $where, regex operators. Both JSON body and query string formats.",
    "prototype_pollution": "Prototype pollution via query string (__proto__, constructor.prototype, __defineGetter__) and JSON body.",
    "auth_bypass": "Auth bypass: header injection (X-Forwarded-For, X-Original-URL), path traversal (%2e%2e, ..;/), case variations, extension tricks.",
    "jwt": "JWT attacks: alg:none (empty signature), weak HMAC secrets (password, secret, ''), kid injection.",
}


def generate_payloads(
    vuln_type: str,
    n: int = 8,
    framework_hints: Optional[List[str]] = None,
    previous_failures: Optional[List[str]] = None,
    anthropic_client=None,
    model: str = "claude-haiku-4-5-20251001",
    payload_library=None,
) -> List[str]:
    """Generate N payloads for vuln_type via Claude Haiku.

    Merge order: user (payload_library) > LLM > builtin.
    Falls back to empty list (caller should use hardcoded library) if:
    - anthropic_client is None
    - API call fails
    - Cached result exists for this exact context

    Args:
        vuln_type: Vulnerability type key.
        n: Number of LLM-generated payloads to request.
        framework_hints: Detected tech stack hints.
        previous_failures: Payloads that already failed (avoid regenerating).
        anthropic_client: Anthropic SDK client instance.
        model: Claude model ID for generation.
        payload_library: Optional PayloadLibrary instance for user payloads.

    Returns:
        Merged list: user payloads first, then LLM payloads.
    """
    user_payloads: List[str] = []
    if payload_library is not None:
        try:
            user_payloads = payload_library.get_user_payloads(vuln_type)
        except Exception:
            pass

    if anthropic_client is None:
        return user_payloads

    cache_key = hashlib.sha256(
        json.dumps({
            "type": vuln_type, "n": n,
            "hints": framework_hints or [],
            "failures": (previous_failures or [])[:5],
        }, sort_keys=True).encode()
    ).hexdigest()

    if cache_key in _CACHE:
        return _CACHE[cache_key]

    type_instruction = _TYPE_INSTRUCTIONS.get(vuln_type.lower(), f"Payloads for {vuln_type}")

    context_parts = [type_instruction]
    if framework_hints:
        context_parts.append(f"Detected stack: {', '.join(framework_hints)}")
    if previous_failures:
        context_parts.append(f"These patterns already FAILED (avoid): {'; '.join(previous_failures[:5])}")
    context_parts.append(f"Generate exactly {n} payloads:")

    user_message = "\n".join(context_parts)

    try:
        resp = anthropic_client.messages.create(
            model=model,
            max_tokens=512,
            system=[
                {
                    "type": "text",
                    "text": _SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},  # cache system prompt
                }
            ],
            messages=[{"role": "user", "content": user_message}],
        )
        raw = resp.content[0].text.strip()
        llm_payloads = [line.strip() for line in raw.splitlines() if line.strip()][:n]
        _CACHE[cache_key] = llm_payloads
        return user_payloads + llm_payloads
    except Exception as e:
        print(f"[payload_generator] Haiku call failed ({vuln_type}): {e} — using hardcoded fallback")
        return user_payloads


def generate_payloads_async_safe(
    vuln_type: str,
    n: int = 8,
    framework_hints: Optional[List[str]] = None,
    previous_failures: Optional[List[str]] = None,
    anthropic_client=None,
) -> List[str]:
    """Synchronous wrapper for use in non-async probe contexts."""
    return generate_payloads(
        vuln_type=vuln_type,
        n=n,
        framework_hints=framework_hints,
        previous_failures=previous_failures,
        anthropic_client=anthropic_client,
    )
