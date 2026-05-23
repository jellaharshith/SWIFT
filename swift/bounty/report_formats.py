"""Bug-bounty report formatters.

Four flavours, one shared input shape. The input is a free dict (use
:class:`bounty.validator.Finding` fields plus ``impact_summary``,
``remediation``, ``cwe``, ``cvss``, ``timeline``).

* :func:`format_h1`        -- HackerOne markdown
* :func:`format_bugcrowd`  -- Bugcrowd markdown
* :func:`format_intigriti` -- Intigriti markdown
* :func:`format_immunefi`  -- Immunefi (web3) markdown

Pick by name with :func:`format_report`.
"""
from __future__ import annotations

from typing import Any, Literal

Platform = Literal["h1", "bugcrowd", "intigriti", "immunefi"]


def _hdr(d: dict[str, Any]) -> list[str]:
    return [
        f"# {d.get('title', '(untitled)')}",
        "",
        f"- Target: `{d.get('target_url') or d.get('target', '?')}`",
        f"- Bug class: {d.get('bug_class', '?')}",
        f"- Severity: **{d.get('severity', '?').upper()}**",
        f"- CWE: {d.get('cwe', 'N/A')}",
        f"- CVSS: {d.get('cvss', 'N/A')}",
        "",
    ]


def _common_body(d: dict[str, Any]) -> list[str]:
    return [
        "## Summary",
        d.get("summary", "_describe the issue in 2-3 sentences_"),
        "",
        "## Steps to reproduce",
        d.get("steps", "1. ...\n2. ...\n3. ..."),
        "",
        "## Proof of concept",
        "```http",
        d.get("request_evidence", "(missing)"),
        "```",
        "",
        "## Impact",
        d.get("impact_summary", "_quantify business impact, not just the technical class_"),
        "",
        "## Suggested remediation",
        d.get("remediation", "_specific code-level or config-level fix_"),
        "",
    ]


def format_h1(d: dict[str, Any]) -> str:
    return "\n".join(_hdr(d) + _common_body(d) + [
        "## Timeline",
        d.get("timeline", "- discovered: ?\n- reported: ?"),
    ])


def format_bugcrowd(d: dict[str, Any]) -> str:
    return "\n".join(_hdr(d) + _common_body(d) + [
        "## Bugcrowd VRT",
        d.get("vrt", "_e.g. Server-Side Injection > SQL Injection > Error-Based_"),
    ])


def format_intigriti(d: dict[str, Any]) -> str:
    return "\n".join(_hdr(d) + _common_body(d) + [
        "## Intigriti severity rationale",
        d.get("severity_rationale", "_justify chosen severity per Intigriti's rubric_"),
    ])


def format_immunefi(d: dict[str, Any]) -> str:
    return "\n".join(_hdr(d) + [
        "## Vulnerability",
        d.get("summary", ""),
        "",
        "## Contracts & functions in scope",
        "```",
        d.get("contract_refs", "0x...:fnName()"),
        "```",
        "",
        "## Impact",
        d.get("impact_summary", ""),
        "",
        "## Proof of concept",
        "```solidity",
        d.get("poc", "// foundry / hardhat repro"),
        "```",
        "",
        "## Recommendation",
        d.get("remediation", ""),
    ])


_FORMATTERS = {
    "h1":        format_h1,
    "bugcrowd":  format_bugcrowd,
    "intigriti": format_intigriti,
    "immunefi":  format_immunefi,
}


def format_report(platform: Platform, finding: dict[str, Any]) -> str:
    if platform not in _FORMATTERS:
        raise ValueError(f"unknown platform: {platform}; choose {list(_FORMATTERS)}")
    return _FORMATTERS[platform](finding)
