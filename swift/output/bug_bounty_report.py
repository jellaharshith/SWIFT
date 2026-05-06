from __future__ import annotations

import os
from typing import TYPE_CHECKING

from agent.models import UnifiedScanResult, MergedFinding, EscalationPath, Vulnerability

if TYPE_CHECKING:
    from agent.bounty_models import BountyResult
    from pathlib import Path


def _vuln_to_merged(v: Vulnerability) -> MergedFinding:
    """Wrap a code-only Vulnerability in a minimal MergedFinding for rendering."""
    mf = MergedFinding(
        id=v.id,
        vuln_type=v.vuln_type,
        severity=v.severity.upper(),
        sources=["code"],
        code_finding=v,
    )
    return mf


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
        """Format a HackerOne/Bugcrowd-style bug bounty report.

        Args:
            result: Unified scan result containing all findings.
            escalation_paths: Privilege escalation paths from PrivilegeEscalationAnalyzer.

        Returns:
            Markdown string with per-finding sections including PoC steps and impact.
        """
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
        findings_to_render = list(result.merged_findings) + [
            _vuln_to_merged(v) for v in getattr(result, "code_only_findings", [])
        ]
        sections = [_finding_section(mf, escalation_paths) for mf in findings_to_render]
        if not sections:
            sections = ["> No findings to report."]
        return "\n".join(header) + "\n\n".join(sections)

    def save(
        self,
        result: UnifiedScanResult,
        escalation_paths: list[EscalationPath],
        artifacts_dir: str,
    ) -> str:
        """Save bug bounty report to artifacts directory.

        Args:
            result: Unified scan result.
            escalation_paths: Privilege escalation paths.
            artifacts_dir: Directory to write report file.

        Returns:
            Absolute path to the saved report file.
        """
        content = self.format_markdown(result, escalation_paths)
        path = os.path.join(artifacts_dir, f"report-bounty-{result.scan_id}.md")
        with open(path, "w") as f:
            f.write(content)
        return path


class BountyReportFormatter:
    """HackerOne/Bugcrowd-style bug bounty report generator for WebFinding results."""

    def format_markdown(self, result: "BountyResult") -> str:
        """Generate a full HackerOne/Bugcrowd-style markdown report.

        Args:
            result: BountyResult containing WebFinding and PostExploitResult objects.

        Returns:
            Markdown string with per-finding sections, evidence, and post-exploit sim results.
        """
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        sev_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in result.findings:
            sev_counts[f.severity.upper()] = sev_counts.get(f.severity.upper(), 0) + 1

        # Executive summary — CISSP voice
        niche_profile = getattr(result, "niche_profile", None)
        attack_profile_line = ""
        if niche_profile is not None:
            niches_str = ", ".join(niche_profile.primary_niches)
            attack_profile_line = (
                f"**Target Attack Profile:** {niches_str} | "
                f"**Bounty Tier:** {niche_profile.bounty_tier.upper()}"
            )

        lines = [
            "# SWIFT Bug Bounty Report",
            "",
            f"**Target:** `{result.target}`",
            f"**Engagement:** `{result.engagement_id}`",
            f"**Date:** {now}",
            f"**VPN Egress:** {result.vpn_egress_ip or 'direct (no VPN)'}",
            f"**Mode:** {'Autonomous' if result.autonomous else 'Interactive'}",
        ]

        if attack_profile_line:
            lines.append(attack_profile_line)

        lines += [
            "",
            "## Executive Summary",
            "",
        ]

        # CISSP-voice exec summary paragraph
        total = len(result.findings)
        critical_count = sev_counts.get("CRITICAL", 0)
        high_count = sev_counts.get("HIGH", 0)
        if niche_profile is not None:
            lines += [
                f"This authorized red-team assessment of `{result.target}` identified **{total} confirmed "
                f"vulnerabilities** ({critical_count} Critical, {high_count} High) following a "
                f"systematic OSINT-to-active-probe methodology aligned with MITRE ATT&CK and OWASP Top 10. "
                f"Primary attack surfaces analyzed: {', '.join(niche_profile.primary_niches)}. "
                f"Target presents a **{niche_profile.bounty_tier.upper()} bounty tier** risk profile. "
                f"Immediate remediation is recommended for all Critical and High findings prior to next "
                f"production deployment.",
                "",
            ]
            if niche_profile.reasoning and niche_profile.reasoning != "default":
                lines += [
                    f"*Niche Rationale: {niche_profile.reasoning}*",
                    "",
                ]
        else:
            lines += [
                f"This authorized red-team assessment identified **{total} confirmed vulnerabilities** "
                f"({critical_count} Critical, {high_count} High). Immediate remediation is recommended "
                f"for all Critical and High findings.",
                "",
            ]

        lines += [
            "## Findings Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
            f"| 🔴 Critical | {sev_counts.get('CRITICAL', 0)} |",
            f"| 🟠 High     | {sev_counts.get('HIGH', 0)} |",
            f"| 🟡 Medium   | {sev_counts.get('MEDIUM', 0)} |",
            f"| 🟢 Low      | {sev_counts.get('LOW', 0)} |",
            f"| **Total**   | **{len(result.findings)}** |",
            "",
            "---",
            "",
        ]

        for i, finding in enumerate(result.findings, 1):
            cvss = f"{finding.cvss_score:.1f}" if finding.cvss_score else "N/A"
            novel_tag = " 🔬 *Novel method*" if finding.is_novel else ""
            lines += [
                f"## Finding {i}: {finding.vuln_type.replace('_', ' ').title()} — {finding.severity}{novel_tag}",
                "",
                f"**CVSS Score:** {cvss} | **CWE:** {finding.cwe_id or 'N/A'} | **OWASP:** {finding.owasp or 'N/A'}",
                f"**URL:** `{finding.url}`",
                f"**Confidence:** {int(finding.confidence * 100)}%",
                "",
                "### Steps to Reproduce",
                "",
                f"1. Set up Burp Suite or curl with the target URL: `{finding.url}`",
                f"2. Send a `{finding.method}` request with payload: `{finding.payload}`",
                f"3. Observe the response confirming the vulnerability.",
                "",
                "### Evidence",
                "",
                "**Request:**",
                "```http",
                finding.request_raw or f"{finding.method} {finding.url} HTTP/1.1",
                "```",
                "",
                "**Response (excerpt):**",
                "```",
                finding.response_excerpt or "(see evidence file)",
                "```",
            ]
            if finding.evidence_path:
                lines += ["", f"**Screenshot:** `{finding.evidence_path}`"]
            lines += [
                "",
                "### Impact",
                "",
                finding.impact or f"This {finding.vuln_type.replace('_', ' ')} vulnerability allows an attacker to compromise the confidentiality, integrity, or availability of the target system.",
                "",
                "### Remediation",
                "",
                finding.remediation or "Apply OWASP remediation guidelines for this vulnerability class.",
                "",
            ]
            if finding.cvss_vector:
                lines += [f"**CVSS Vector:** `{finding.cvss_vector}`", ""]
            lines += ["---", ""]

        # Post-exploit section
        if result.post_exploit:
            lines += ["## Post-Exploitation Simulation Results", ""]
            for pe in result.post_exploit:
                lines += [
                    f"### {pe.sim_type.title()} — Finding {pe.finding_id}",
                    f"**Feasibility:** {pe.feasibility}",
                    "",
                    pe.attack_tree,
                    "",
                    "**Mitigations:**",
                    *[f"- {m}" for m in pe.mitigations],
                    "",
                    "> ⚠️ *Simulation only — no real C2/exfil/persistence was performed.*",
                    "",
                ]

        lines += [
            "---",
            "",
            "*This report was generated by SWIFT. All testing was performed on authorized targets only.*",
            "*Unauthorized use of these techniques against systems you do not own or have explicit permission to test is illegal.*",
        ]
        return "\n".join(lines)

    def format_json(self, result: "BountyResult") -> str:
        """Serialize BountyResult to JSON string.

        Args:
            result: BountyResult to serialize.

        Returns:
            JSON string representation.
        """
        import json
        return json.dumps(result.to_dict(), indent=2, sort_keys=True)

    def save(self, result: "BountyResult", out_dir: "str | Path") -> str:
        """Save markdown and JSON reports to out_dir.

        Args:
            result: BountyResult to format and save.
            out_dir: Directory to write report files into (created if missing).

        Returns:
            Absolute path to the saved markdown report file.
        """
        import json
        from pathlib import Path
        d = Path(out_dir)
        d.mkdir(parents=True, exist_ok=True)
        md_path = d / f"bounty-report-{result.engagement_id}.md"
        json_path = d / f"bounty-report-{result.engagement_id}.json"
        md_path.write_text(self.format_markdown(result), encoding="utf-8")
        json_path.write_text(self.format_json(result), encoding="utf-8")
        return str(md_path.resolve())
