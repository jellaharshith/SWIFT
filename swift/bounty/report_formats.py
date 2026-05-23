"""Bug-bounty report formatters — Rosén narrative style.

Four platform flavours with shared Rosén narrative arc:
Discovery → Hypothesis → Escalation → Impact → Reproduction → Fix

Input dict keys (all optional, sensible fallbacks provided):
  title, target_url, bug_class, severity, cwe, cvss
  summary          -- legacy fallback for discovery/hypothesis
  discovery        -- how the entry point was found (Rosén: show reasoning)
  hypothesis       -- what you believed possible before proof
  escalation_chain -- chain from "interesting" to "exploitable"
  steps            -- exact reproduction steps
  request_evidence -- raw HTTP request/response
  impact_summary   -- business impact first, technical second
  remediation      -- concrete minimal fix
  timeline         -- discovered/reported/patched dates
  vrt              -- Bugcrowd Vulnerability Rating Taxonomy
  severity_rationale -- Intigriti severity justification
  smart_contract_address -- Immunefi contract address
  phase_artifacts  -- dict of PTES phase artifact paths (optional, appended as appendix)
"""
from __future__ import annotations

from typing import Any, Literal

Platform = Literal["h1", "bugcrowd", "intigriti", "immunefi"]


def _hdr(d: dict[str, Any]) -> list[str]:
    return [
        f"# {d.get('title', '(untitled)')}",
        "",
        f"- **Target:** `{d.get('target_url') or d.get('target', '?')}`",
        f"- **Bug class:** {d.get('bug_class', '?')}",
        f"- **Severity:** **{d.get('severity', '?').upper()}**",
        f"- **CWE:** {d.get('cwe', 'N/A')}",
        f"- **CVSS:** {d.get('cvss', 'N/A')}",
        "",
    ]


def _rosen_narrative_body(d: dict[str, Any]) -> list[str]:
    """Rosén-style narrative arc: Discovery → Hypothesis → Escalation → Impact → Repro → Fix."""
    discovery = d.get("discovery") or d.get("summary") or "_Describe how the entry point was found — show your reasoning, not just the endpoint._"
    hypothesis = d.get("hypothesis") or "_What did you believe was possible before you proved it?_"
    escalation = d.get("escalation_chain") or d.get("steps") or "_Describe the chain of reasoning from 'interesting' to 'exploitable'._"
    impact = d.get("impact_summary") or "_Business impact first: who is affected and what can they do? Technical impact second._"
    steps = d.get("steps") or "1. ...\n2. ...\n3. ..."
    request_evidence = d.get("request_evidence") or "(missing — attach HTTP request/response)"
    remediation = d.get("remediation") or "_Concrete minimal fix — specific code change or config, not generic advice._"

    lines = [
        "## Discovery",
        "",
        discovery,
        "",
        "## Hypothesis",
        "",
        hypothesis,
        "",
        "## Escalation Chain",
        "",
        escalation,
        "",
        "## Impact",
        "",
        impact,
        "",
        "## Reproduction Steps",
        "",
        steps,
        "",
        "## Proof of Concept",
        "",
        "```http",
        request_evidence,
        "```",
        "",
        "## Fix",
        "",
        remediation,
        "",
    ]

    # Append PTES phase artifacts as appendix if present
    phase_artifacts = d.get("phase_artifacts")
    if phase_artifacts:
        lines += ["## PTES Phase Artifacts", ""]
        for phase_name, artifact_path in phase_artifacts.items():
            lines.append(f"- [{phase_name}]({artifact_path})")
        lines.append("")

    return lines


# Backward compat aliases
_narrative_body = _rosen_narrative_body
_common_body = _rosen_narrative_body  # old callers get Rosén narrative


def format_h1(d: dict[str, Any]) -> str:
    return "\n".join(_hdr(d) + _rosen_narrative_body(d) + [
        "## Timeline",
        "",
        d.get("timeline", "- **Discovered:** ?\n- **Reported:** ?"),
    ])


def format_bugcrowd(d: dict[str, Any]) -> str:
    return "\n".join(_hdr(d) + _rosen_narrative_body(d) + [
        "## Bugcrowd VRT",
        "",
        d.get("vrt", "_e.g. Server-Side Injection > SQL Injection > Error-Based_"),
    ])


def format_intigriti(d: dict[str, Any]) -> str:
    return "\n".join(_hdr(d) + _rosen_narrative_body(d) + [
        "## Intigriti Severity Rationale",
        "",
        d.get("severity_rationale", "_Justify chosen severity per Intigriti's rubric._"),
    ])


def format_immunefi(d: dict[str, Any]) -> str:
    return "\n".join(_hdr(d) + [
        "## Vulnerability",
        "",
        d.get("summary", ""),
        "",
    ] + _rosen_narrative_body(d) + [
        "## Smart Contract",
        "",
        f"- Address: `{d.get('smart_contract_address', 'N/A')}`",
        f"- Network: {d.get('network', 'N/A')}",
        f"- Audited commit: {d.get('commit', 'N/A')}",
    ])


_FORMATTERS = {
    "h1":        format_h1,
    "bugcrowd":  format_bugcrowd,
    "intigriti": format_intigriti,
    "immunefi":  format_immunefi,
}


def format_report(platform: Platform, d: dict[str, Any]) -> str:
    if platform not in _FORMATTERS:
        raise ValueError(f"unknown platform: {platform}; valid: {list(_FORMATTERS)}")
    return _FORMATTERS[platform](d)
