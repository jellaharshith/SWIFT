"""Output formatters for SWIFT scan results — pure data transformation, no API calls."""
from __future__ import annotations

import json
from typing import Dict

from agent.models import ScanResult


class JSONFormatter:
    """Serialises a ScanResult to a structured JSON string.

    The schema mirrors what downstream consumers (APIs, dashboards) expect:
    a top-level 'scan' block for metadata, a 'summary' block for quick stats,
    and flat arrays for vulnerabilities and patches.
    """

    def format(self, result: ScanResult) -> str:
        """Convert a ScanResult to a JSON string.

        Args:
            result: Completed scan result containing all findings and patches.

        Returns:
            Indented JSON string ready for file output or HTTP response.
        """
        by_severity: Dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
        # Count per severity using lowercase keys so callers don't have to normalise.
        for vuln in result.vulnerabilities:
            key = vuln.severity.lower()
            if key in by_severity:
                by_severity[key] += 1
            else:
                # Preserve unexpected severity values rather than silently dropping.
                by_severity[key] = by_severity.get(key, 0) + 1

        payload = {
            "scan": {
                "id": result.scan_id,
                "repo_path": result.repo_path,
                "duration_seconds": result.duration_seconds,
                "total_cost_usd": result.total_cost_usd,
                "timestamp": result.timestamp,
            },
            "summary": {
                "files_scanned": result.files_scanned,
                "vulnerabilities_found": len(result.vulnerabilities),
                "by_severity": by_severity,
                "patches_generated": len(result.patches),
            },
            "vulnerabilities": [
                {
                    "id": v.id,
                    "file_path": v.file_path,
                    "line_number": v.line_number,
                    "vuln_type": v.vuln_type,
                    "description": v.description,
                    "confidence": v.confidence,
                    "status": v.status,
                    "severity": v.severity,
                    "code_snippet": v.code_snippet,
                    # Evidence bundle fields (all 11)
                    "cwe_id": v.cwe_id,
                    "cwe_url": v.cwe_url,
                    "owasp_category": v.owasp_category,
                    "exploit_description": v.exploit_description,
                    "exploit_impact": v.exploit_impact,
                    "remediation": v.remediation,
                    "remediation_code": v.remediation_code,
                    "remediation_effort": v.remediation_effort,
                    "remediation_time_minutes": v.remediation_time_minutes,
                    "affected_code": v.affected_code,
                    "references": v.references,
                    # Phase 3 risk scoring fields
                    "risk_score": v.risk_score,
                    "exploitability": v.exploitability,
                    "business_impact_category": v.business_impact_category,
                }
                for v in result.vulnerabilities
            ],
            "patches": [
                {
                    "id": p.id,
                    "vuln_id": p.vuln_id,
                    "file_path": p.file_path,
                    "original_code": p.original_code,
                    "patched_code": p.patched_code,
                    "diff": p.diff,
                    "confidence": p.confidence,
                }
                for p in result.patches
            ],
            "exploit_chains": [
                {
                    "chain_id": c.chain_id,
                    "name": c.name,
                    "vulnerability_ids": c.vulnerability_ids,
                    "attack_path": c.attack_path,
                    "entry_point": c.entry_point,
                    "impact": c.impact,
                    "severity": c.severity,
                    "confidence": c.confidence,
                }
                for c in result.exploit_chains
            ],
            "ranked_findings": [
                {
                    "id": v.id,
                    "file_path": v.file_path,
                    "line_number": v.line_number,
                    "vuln_type": v.vuln_type,
                    "severity": v.severity,
                    "confidence": v.confidence,
                    "risk_score": v.risk_score,
                }
                for v in result.ranked_findings
            ],
            "artifacts": {
                "findings.json": [
                    {
                        "id": v.id,
                        "file_path": v.file_path,
                        "line_number": v.line_number,
                        "vuln_type": v.vuln_type,
                        "description": v.description,
                        "severity": v.severity,
                        "confidence": v.confidence,
                        "risk_score": v.risk_score,
                    }
                    for v in result.vulnerabilities
                ],
                "exploit_chains.json": [
                    {
                        "chain_id": c.chain_id,
                        "name": c.name,
                        "vulnerability_ids": c.vulnerability_ids,
                        "entry_point": c.entry_point,
                        "impact": c.impact,
                        "severity": c.severity,
                        "confidence": c.confidence,
                    }
                    for c in result.exploit_chains
                ],
                "ranked_findings.json": [
                    {
                        "id": v.id,
                        "file_path": v.file_path,
                        "line_number": v.line_number,
                        "vuln_type": v.vuln_type,
                        "severity": v.severity,
                        "confidence": v.confidence,
                        "risk_score": v.risk_score,
                    }
                    for v in result.ranked_findings
                ],
            },
        }

        return json.dumps(payload, indent=2)


class MarkdownFormatter:
    """Renders a ScanResult as a human-readable Markdown report.

    Conditional sections (Vulnerabilities, Patches) are only emitted when
    relevant data exists — an empty report should still be meaningful.
    """

    def format(self, result: ScanResult) -> str:
        """Convert a ScanResult to a Markdown string.

        Args:
            result: Completed scan result containing all findings and patches.

        Returns:
            Markdown string suitable for saving as a .md file or displaying
            in a terminal / web UI.
        """
        lines: list[str] = []

        # --- Header and scan metadata ---
        lines.append("# SWIFT Vulnerability Report")
        lines.append("")
        lines.append(f"- **Repository:** {result.repo_path}")
        lines.append(f"- **Timestamp:** {result.timestamp}")
        lines.append(f"- **Duration:** {result.duration_seconds:.1f}s")
        lines.append(f"- **Cost:** ${result.total_cost_usd:.4f}")
        lines.append("")

        # --- Summary section ---
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Files scanned:** {result.files_scanned}")
        lines.append(f"- **Vulnerabilities found:** {len(result.vulnerabilities)}")
        lines.append(f"- **Patches generated:** {len(result.patches)}")
        lines.append("")

        # --- Vulnerabilities ---
        if result.vulnerabilities:
            lines.append("## Vulnerabilities")
            lines.append("")
            for vuln in result.vulnerabilities:
                # Heading makes each finding easily linkable in rendered Markdown.
                lines.append(
                    f"### {vuln.vuln_type} — {vuln.id} [{vuln.severity}]"
                )
                lines.append("")
                lines.append(f"- **File:** `{vuln.file_path}:{vuln.line_number}`")
                # Display confidence as a percentage — more intuitive for humans.
                confidence_pct = int(round(vuln.confidence * 100))
                lines.append(f"- **Confidence:** {confidence_pct}%")
                lines.append(f"- **Status:** {vuln.status}")
                lines.append(f"- **Description:** {vuln.description}")
                lines.append("")
                lines.append("```python")
                lines.append(vuln.code_snippet)
                lines.append("```")
                lines.append("")

                # --- Phase 3 risk scoring fields ---
                # Only show section if at least one Phase 3 field is present
                if vuln.risk_score is not None or vuln.exploitability is not None or vuln.business_impact_category is not None:
                    lines.append("**Phase 3 Risk Assessment:**")
                    lines.append("")
                    if vuln.risk_score is not None:
                        risk_score_int = int(round(vuln.risk_score))
                        lines.append(f"- **Risk Score:** {risk_score_int}/100")
                    else:
                        lines.append("- **Risk Score:** -")

                    if vuln.exploitability is not None:
                        # Map exploitability float (0.0-1.0) to readable string
                        # trivial ≈ 0.9+, moderate ≈ 0.5-0.9, complex ≈ 0.2-0.5, specific ≈ <0.2
                        if vuln.exploitability >= 0.85:
                            exploit_label = "trivial"
                        elif vuln.exploitability >= 0.55:
                            exploit_label = "moderate"
                        elif vuln.exploitability >= 0.25:
                            exploit_label = "complex"
                        else:
                            exploit_label = "specific"
                        lines.append(f"- **Exploitability:** {exploit_label}")
                    else:
                        lines.append("- **Exploitability:** -")

                    if vuln.business_impact_category is not None:
                        lines.append(f"- **Business Impact:** {vuln.business_impact_category}")
                    else:
                        lines.append("- **Business Impact:** -")

                    lines.append("")

        else:
            lines.append("*No vulnerabilities found.*")
            lines.append("")

        # --- Exploit Chains ---
        if result.exploit_chains:
            lines.append("## Exploit Chains")
            lines.append("")
            for chain in result.exploit_chains:
                lines.append(f"### {chain.name} [{chain.severity}]")
                lines.append("")
                lines.append(f"- **Chain ID:** {chain.chain_id}")
                lines.append(f"- **Entry Point:** {chain.entry_point}")
                lines.append(f"- **Impact:** {chain.impact}")
                confidence_pct = int(round(chain.confidence * 100))
                lines.append(f"- **Confidence:** {confidence_pct}%")
                lines.append(f"- **Vulnerabilities involved:** {', '.join(chain.vulnerability_ids)}")
                lines.append("")
                lines.append("**Attack Path:**")
                lines.append("")
                for line in chain.attack_path.split("\n"):
                    if line.strip():
                        lines.append(f"  {line}")
                lines.append("")

        # --- Patches (omitted when empty) ---
        if result.patches:
            lines.append("## Patches")
            lines.append("")
            for patch in result.patches:
                lines.append(f"### {patch.id} → {patch.vuln_id}")
                lines.append("")
                lines.append("```diff")
                lines.append(patch.diff)
                lines.append("```")
                lines.append("")

        return "\n".join(lines)


def format_output(result: ScanResult, format_type: str) -> str:
    """Dispatch to the appropriate formatter based on format_type.

    Args:
        result: Completed scan result to format.
        format_type: One of 'json' or 'markdown'.

    Returns:
        Formatted string ready for output.

    Raises:
        ValueError: If format_type is not 'json' or 'markdown'.
    """
    _SUPPORTED = ["json", "markdown"]

    if format_type == "json":
        return JSONFormatter().format(result)
    elif format_type == "markdown":
        return MarkdownFormatter().format(result)
    else:
        raise ValueError(
            f"Unknown format '{format_type}'. Choose: {_SUPPORTED}"
        )
