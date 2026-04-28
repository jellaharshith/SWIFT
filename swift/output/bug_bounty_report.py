from __future__ import annotations
import os
from agent.models import UnifiedScanResult, MergedFinding, EscalationPath


def _severity_badge(severity: str) -> str:
    return f"[{severity.upper()}]"


def _finding_section(mf: MergedFinding, escalation_paths: list[EscalationPath]) -> str:
    cf = mf.code_finding
    cve_ids = [cm.cve.cve_id for cm in mf.cve_matches] if mf.cve_matches else []
    cvss = mf.cve_matches[0].cve.cvss_score if mf.cve_matches else "N/A"
    cwe = cf.cwe_id if cf else "N/A"
    location = f"`{cf.file_path}:{cf.line_number}`" if cf else (mf.kali_finding or {}).get("target", "unknown")
    mitre = ", ".join(f"{t['technique_id']} {t['technique']}" for t in (mf.mitre_techniques or []))
    cve_str = ", ".join(cve_ids) if cve_ids else "None"
    confidence_pct = int((cf.confidence if cf else 0.0) * 100)

    exploit_desc = (cf.exploit_description if cf else None) or "See finding details."
    exploit_impact = (cf.exploit_impact if cf else None) or "Impact unknown."
    remediation = (cf.remediation if cf else None) or "Review and remediate."

    escalation = next(
        (p for p in escalation_paths if mf.id in p.finding_ids),
        None,
    )

    lines = [
        f"## {_severity_badge(mf.severity)} {mf.vuln_type.replace('_', ' ').title()} — {location}",
        "",
        f"**CVE:** {cve_str}  |  **CVSS:** {cvss}  |  **CWE:** {cwe}",
        f"**MITRE:** {mitre or 'N/A'}",
        f"**Sources:** {', '.join(mf.sources)}",
    ]
    if mf.actively_exploited:
        lines.append("\n> ⚠️ **ACTIVELY EXPLOITED** — listed in CISA Known Exploited Vulnerabilities")

    lines += [
        "",
        "### Steps to Reproduce",
        "",
        "1. " + exploit_desc,
        "",
        "### Impact",
        "",
        exploit_impact,
        "",
        "### Suggested Fix",
        "",
        f"{remediation} — Patch confidence: {confidence_pct}%",
    ]

    if escalation:
        lines += [
            "",
            "### Privilege Escalation Path",
            "",
            "```",
            escalation.ascii_chain,
            "```",
        ]

    return "\n".join(lines)


class BugBountyFormatter:
    def format_markdown(
        self,
        result: UnifiedScanResult,
        escalation_paths: list[EscalationPath],
    ) -> str:
        header = [
            "# Bug Bounty Report — SWIFT Security Scanner",
            "",
            f"**Scan ID:** `{result.scan_id}`",
            f"**Date:** {result.started_at}",
            f"**Duration:** {result.duration:.1f}s",
            f"**Target:** repo={result.repo_path or 'N/A'}  kali={result.kali_target or 'N/A'}",
            "",
            "---",
            "",
        ]
        sections = [_finding_section(mf, escalation_paths) for mf in result.merged_findings]
        if not sections:
            sections = ["> No findings to report."]
        return "\n".join(header) + "\n\n".join(sections)

    def save(
        self,
        result: UnifiedScanResult,
        escalation_paths: list[EscalationPath],
        artifacts_dir: str,
    ) -> str:
        content = self.format_markdown(result, escalation_paths)
        path = os.path.join(artifacts_dir, f"report-bounty-{result.scan_id}.md")
        with open(path, "w") as f:
            f.write(content)
        return path
