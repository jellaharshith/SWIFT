"""Unified report formatter for SWIFT — Markdown + TXT output."""
from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent.models import UnifiedScanResult


class UnifiedReportFormatter:
    """Formats a UnifiedScanResult into Markdown and plain-text reports."""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def format_markdown(self, result: "UnifiedScanResult") -> str:
        sections: list[str] = []
        sections.append(self._md_header(result))
        sections.append(self._md_executive_summary(result))
        sections.append(self._md_merged_findings(result))
        sections.append(self._md_code_only_findings(result))
        sections.append(self._md_kali_only_findings(result))
        sections.append(self._md_cve_matches(result))
        sections.append(self._md_exploit_chains(result))
        sections.append(self._md_patches(result))
        return "\n\n".join(s for s in sections if s)

    def format_txt(self, result: "UnifiedScanResult") -> str:
        md = self.format_markdown(result)
        return self._md_to_txt(md)

    def save(self, result: "UnifiedScanResult", artifacts_dir: str) -> tuple[str, str]:
        out = Path(artifacts_dir)
        out.mkdir(parents=True, exist_ok=True)

        md_content = self.format_markdown(result)
        txt_content = self._md_to_txt(md_content)

        md_path = out / f"report-{result.scan_id}.md"
        txt_path = out / f"report-{result.scan_id}.txt"

        md_path.write_text(md_content, encoding="utf-8")
        txt_path.write_text(txt_content, encoding="utf-8")

        return str(md_path), str(txt_path)

    # ------------------------------------------------------------------
    # Markdown section builders
    # ------------------------------------------------------------------

    def _md_header(self, result: "UnifiedScanResult") -> str:
        return f"# SWIFT Security Report — {result.started_at}"

    def _md_executive_summary(self, result: "UnifiedScanResult") -> str:
        lines = ["## Executive Summary", ""]

        # Severity counts across ALL findings
        counts = self._count_severities(result)
        total = (
            len(result.merged_findings)
            + len(result.code_only_findings)
            + len(result.kali_only_findings)
        )

        # Source flags
        has_code = bool(result.code_only_findings or any(
            "code" in (f.sources or []) for f in result.merged_findings
        ))
        has_kali = bool(result.kali_only_findings or any(
            "kali" in (f.sources or []) for f in result.merged_findings
        ))
        has_cve = bool(result.all_cve_matches)

        code_flag = "✓" if has_code else "✗"
        kali_flag = "✓" if has_kali else "✗"
        cve_flag = "✓" if has_cve else "✗"

        duration = f"{result.duration:.1f}s"

        actively_exploited = sum(
            1 for f in result.merged_findings if f.actively_exploited
        )

        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Total findings | {total} |")
        lines.append(f"| Critical | {counts['CRITICAL']} |")
        lines.append(f"| High | {counts['HIGH']} |")
        lines.append(f"| Medium | {counts['MEDIUM']} |")
        lines.append(f"| Low | {counts['LOW']} |")
        lines.append(f"| Code Scanner | {code_flag} |")
        lines.append(f"| Kali Linux | {kali_flag} |")
        lines.append(f"| CVE Feed | {cve_flag} |")
        lines.append(f"| Duration | {duration} |")
        lines.append(f"| Actively exploited | {actively_exploited} |")

        return "\n".join(lines)

    def _md_merged_findings(self, result: "UnifiedScanResult") -> str:
        if not result.merged_findings:
            return ""
        lines = ["## Merged Findings", ""]
        lines.append("*Findings confirmed by 2 or more sources.*")
        for mf in result.merged_findings:
            lines.append("")
            lines.append(f"### [{mf.severity}] {mf.vuln_type} — {mf.id}")
            # Sources
            source_labels = []
            for s in mf.sources:
                if s == "code":
                    source_labels.append("Code Scanner")
                elif s == "kali":
                    tool = ""
                    if mf.kali_finding and isinstance(mf.kali_finding, dict):
                        tool = mf.kali_finding.get("tool", "")
                    if tool:
                        source_labels.append(f"Kali ({tool})")
                    else:
                        source_labels.append("Kali")
                else:
                    source_labels.append(s.title())
            lines.append(f"**Found by:** {', '.join(source_labels)}")

            # Code location
            if mf.code_finding:
                cf = mf.code_finding
                lines.append(f"**Location:** `{cf.file_path}:{cf.line_number}`")

            # MITRE techniques
            if mf.mitre_techniques:
                techniques = ", ".join(
                    f"{t.get('id', '')} ({t.get('technique', '')})"
                    for t in mf.mitre_techniques
                    if t.get("id")
                )
                if techniques:
                    lines.append(f"**MITRE ATT&CK:** {techniques}")

            # CVE IDs
            if mf.cve_matches:
                cve_parts = []
                for cm in mf.cve_matches:
                    cve_id = cm.cve.cve_id
                    cvss = cm.cve.cvss_score
                    if cve_id:
                        cve_parts.append(f"{cve_id} (CVSS: {cvss})")
                if cve_parts:
                    lines.append(f"**CVEs:** {', '.join(cve_parts)}")

            # Actively exploited badge
            if mf.actively_exploited:
                lines.append("**ACTIVELY EXPLOITED IN THE WILD**")

        return "\n".join(lines)

    def _md_code_only_findings(self, result: "UnifiedScanResult") -> str:
        if not result.code_only_findings:
            return ""
        lines = ["## Code-Only Findings", ""]
        lines.append("| File | Line | Severity | Type | Confidence |")
        lines.append("|------|------|----------|------|------------|")
        for v in result.code_only_findings:
            conf = f"{v.confidence:.0%}"
            lines.append(
                f"| `{v.file_path}` | {v.line_number} | {v.severity} | {v.vuln_type} | {conf} |"
            )
        return "\n".join(lines)

    def _md_kali_only_findings(self, result: "UnifiedScanResult") -> str:
        if not result.kali_only_findings:
            return ""
        lines = ["## Kali-Only Findings", ""]
        lines.append("| Tool | Target | Technique | Tactic |")
        lines.append("|------|--------|-----------|--------|")
        for kf in result.kali_only_findings:
            tool = kf.get("tool", "")
            target = kf.get("target", "")
            technique = kf.get("technique", "")
            tactic = kf.get("tactic", "")
            lines.append(f"| {tool} | {target} | {technique} | {tactic} |")
        return "\n".join(lines)

    def _md_cve_matches(self, result: "UnifiedScanResult") -> str:
        if not result.all_cve_matches:
            return ""
        lines = ["## CVE Matches", ""]
        lines.append("| CVE ID | CVSS | Severity | CISA KEV | Finding ID | Match Reason |")
        lines.append("|--------|------|----------|----------|------------|--------------|")
        for cm in result.all_cve_matches:
            cve_id = cm.cve.cve_id
            cvss = cm.cve.cvss_score
            severity = cm.cve.severity
            kev = "Yes" if cm.cve.cisa_known_exploited else "No"
            finding_id = self._safe_cell(cm.matched_finding_id)
            reason = self._safe_cell(cm.match_reason)
            lines.append(
                f"| {cve_id} | {cvss} | {severity} | {kev} | {finding_id} | {reason} |"
            )
        return "\n".join(lines)

    def _md_exploit_chains(self, result: "UnifiedScanResult") -> str:
        if not result.exploit_chains:
            return ""
        lines = ["## Exploit Chains", ""]
        for ec in result.exploit_chains:
            lines.append(f"### {ec.name}")
            lines.append(f"**Severity:** {ec.severity}")
            lines.append(f"**Chain ID:** `{ec.chain_id}`")
            lines.append(f"**Attack Path:** {ec.attack_path}")
            lines.append(f"**Impact:** {ec.impact}")
            lines.append("")
        return "\n".join(lines)

    def _md_patches(self, result: "UnifiedScanResult") -> str:
        if not result.patches:
            return ""
        lines = ["## Patches", ""]
        for p in result.patches:
            lines.append(f"### Patch {p.id}")
            lines.append(f"**File:** `{p.file_path}`")
            lines.append(f"**Vuln ID:** {p.vuln_id}")
            # First 20 lines of diff
            all_diff_lines = p.diff.splitlines()
            diff_lines = all_diff_lines[:20]
            truncated = len(all_diff_lines) > 20
            lines.append("```diff")
            lines.extend(diff_lines)
            if truncated:
                lines.append("... (truncated)")
            lines.append("```")
            lines.append("")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Severity counting
    # ------------------------------------------------------------------

    def _count_severities(self, result: "UnifiedScanResult") -> dict[str, int]:
        counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for mf in result.merged_findings:
            key = mf.severity.upper() if mf.severity else "MEDIUM"
            if key in counts:
                counts[key] += 1
            else:
                counts["LOW"] += 1

        for v in result.code_only_findings:
            key = v.severity.upper() if v.severity else "MEDIUM"
            if key in counts:
                counts[key] += 1
            else:
                counts["LOW"] += 1

        for kf in result.kali_only_findings:
            sev = kf.get("severity", "MEDIUM").upper()
            if sev not in counts:
                sev = "MEDIUM"
            counts[sev] += 1

        return counts

    # ------------------------------------------------------------------
    # Markdown -> plain text conversion
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_cell(val: str) -> str:
        return str(val).replace("|", "\\|").replace("\n", " ")

    @staticmethod
    def _md_to_txt(md: str) -> str:
        lines = md.splitlines()
        result_lines: list[str] = []

        for line in lines:
            # Strip table separator rows (|---|---|)
            if re.match(r"^\|[-| ]+\|$", line.strip()):
                continue

            # H1: # Title -> TITLE\n======
            h1 = re.match(r"^# (.+)$", line)
            if h1:
                title = UnifiedReportFormatter._strip_inline_md(h1.group(1))
                result_lines.append(title)
                result_lines.append("=" * len(title))
                continue

            # H2: ## Section -> SECTION\n-------
            h2 = re.match(r"^## (.+)$", line)
            if h2:
                title = UnifiedReportFormatter._strip_inline_md(h2.group(1))
                result_lines.append(title)
                result_lines.append("-" * len(title))
                continue

            # H3: ### Sub -> Sub (no special underline, just plain)
            h3 = re.match(r"^### (.+)$", line)
            if h3:
                title = UnifiedReportFormatter._strip_inline_md(h3.group(1))
                result_lines.append(title)
                continue

            # Strip inline markdown from remaining lines
            converted = UnifiedReportFormatter._strip_inline_md(line)
            result_lines.append(converted)

        txt = "\n".join(result_lines)

        # Remove emoji characters (keep ASCII range + common Latin)
        txt = re.sub(
            r"[\U00010000-\U0010FFFF"    # Supplementary planes (emoji, etc.)
            r"\u2600-\u27BF"            # Misc symbols, dingbats
            r"\u2300-\u23FF"            # Misc technical
            r"\u2700-\u27FF"            # Dingbats
            r"\uFE00-\uFE0F"            # Variation selectors
            r"\u200D"                    # Zero-width joiner
            r"\u20E3"                    # Combining enclosing keycap
            r"]",
            "",
            txt,
        )

        return txt

    @staticmethod
    def _strip_inline_md(text: str) -> str:
        """Remove inline markdown: bold, italic, inline code."""
        # **bold** or __bold__ -> BOLD (uppercase)
        text = re.sub(r"\*\*(.+?)\*\*", lambda m: m.group(1).upper(), text)
        text = re.sub(r"__(.+?)__", lambda m: m.group(1).upper(), text)
        # *italic* or _italic_ -> italic (no change in case)
        text = re.sub(r"\*(.+?)\*", r"\1", text)
        text = re.sub(r"_(.+?)_", r"\1", text)
        # `code` -> code (strip backticks)
        text = re.sub(r"`(.+?)`", r"\1", text)
        # ```lang\n...\n``` already handled line-by-line — strip fence markers
        text = re.sub(r"^```.*$", "", text)
        return text
