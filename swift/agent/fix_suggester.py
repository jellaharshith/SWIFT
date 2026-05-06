"""LLM-powered remediation suggestion generator for WebFindings."""
from __future__ import annotations
import os
import anthropic
from agent.bounty_models import WebFinding
from agent.pentester_persona import build_persona_preamble

# Offline fallback templates — used when ANTHROPIC_API_KEY is absent or the
# API call fails.  Keep these authoritative enough to stand alone.
_REMEDIATION_TEMPLATES: dict[str, str] = {
    "sqli": (
        "Use parameterized queries / prepared statements. "
        "Never concatenate user input into SQL."
    ),
    "xss": (
        "HTML-encode all user-controlled output. "
        "Use Content-Security-Policy header. Avoid innerHTML."
    ),
    "idor": (
        "Implement server-side authorization checks on every object access. "
        "Verify ownership against session user."
    ),
    "ssrf": (
        "Validate and whitelist allowed URL schemes/hosts. "
        "Block internal IP ranges (169.254.0.0/16, 10.0.0.0/8, etc.)."
    ),
    "auth_bypass": (
        "Enforce authentication on all protected routes. "
        "Implement server-side session validation."
    ),
    "misconfig": (
        "Review server configuration. "
        "Disable directory listing, debug modes, and unnecessary HTTP methods."
    ),
    "jwt": (
        "Verify JWT signature on every request. "
        "Reject 'none' algorithm. Use short expiry + refresh tokens."
    ),
}


async def suggest_fix(finding: WebFinding) -> str:
    """Generate a remediation recommendation for a WebFinding.

    Calls Claude Haiku for a concise, context-aware fix suggestion.
    Falls back to the offline template table if the API key is absent or the
    call fails — so the pipeline never blocks on an LLM.

    Args:
        finding: The confirmed vulnerability that needs remediation guidance.

    Returns:
        Plain-text remediation string (1–2 paragraphs + code example when LLM
        is available, or a single-sentence template otherwise).
    """
    template = _REMEDIATION_TEMPLATES.get(finding.vuln_type.lower())

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return template or "Review and apply OWASP remediation guidance for this vulnerability type."

    try:
        client = anthropic.Anthropic(api_key=api_key)
        persona = build_persona_preamble(passive=False)
        prompt = (
            f"{persona}\n\n"
            "As a security engineer who thinks like an attacker, provide a concise, "
            "actionable remediation for this vulnerability. Explain how an attacker would "
            "exploit it, then give the developer-facing fix.\n\n"
            f"Vulnerability: {finding.vuln_type}\n"
            f"URL: {finding.url}\n"
            f"Payload used: {finding.payload}\n"
            "Tech stack context: (inferred from target)\n\n"
            "Provide: 1 paragraph remediation + 1 code example in the most likely "
            "language/framework. Be specific. No preamble."
        )
        msg = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}],
        )
        return msg.content[0].text.strip()
    except Exception:
        # Degrade gracefully — a failed LLM call must not crash the pipeline.
        return template or "Apply defense-in-depth: validate input, encode output, enforce least-privilege."
