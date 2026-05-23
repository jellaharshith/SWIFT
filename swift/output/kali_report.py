"""Bug-bounty-style terminal report formatter for raw KaliRunner.run_scan() results.

Pure stdlib — no external template engines or third-party deps.
"""
from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

_TOOL_CWE: dict[str, str] = {
    "sqlmap": "CWE-89",
    "nikto": "CWE-200",
    "gobuster": "CWE-548",
    "nuclei": "CWE-1035",
    "searchsploit": "CWE-1035",
}

_TOOL_RECOMMENDATION: dict[str, str] = {
    "sqlmap": (
        "Use parameterized queries. Never interpolate user input into SQL strings."
    ),
    "nikto": (
        "Review each reported item. Disable unnecessary server features, "
        "remove default files, and harden HTTP response headers."
    ),
    "gobuster": (
        "Restrict access to discovered paths. Ensure sensitive directories "
        "are not publicly reachable and apply proper authentication controls."
    ),
    "nuclei": (
        "Investigate each template match in context. Apply vendor patches "
        "or configuration hardening as directed by the matched template."
    ),
    "searchsploit": (
        "Patch or upgrade the identified software to a version that is not "
        "affected by the listed exploit(s). Verify with CVE advisories."
    ),
    "nmap": (
        "Close unnecessary ports. Ensure exposed services are patched and "
        "correctly configured."
    ),
    "masscan": (
        "Audit all open ports. Close services that are not required and "
        "apply network-level firewall rules."
    ),
}

_DEFAULT_RECOMMENDATION = "Investigate manually and assess risk."

# Nuclei severity strings as reported in output lines
_NUCLEI_SEVERITY_MAP: dict[str, str] = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "informational": "INFO",
}


# ---------------------------------------------------------------------------
# Internal data container
# ---------------------------------------------------------------------------

class _Finding:
    """Represents a single normalised finding extracted from a tool result."""

    __slots__ = (
        "severity",
        "title",
        "tool",
        "technique_id",
        "technique",
        "tactic",
        "cwe",
        "evidence_lines",
        "recommendation",
    )

    def __init__(
        self,
        severity: str,
        title: str,
        tool: str,
        technique_id: str,
        technique: str,
        tactic: str,
        evidence_lines: list[str],
        recommendation: str,
    ) -> None:
        self.severity = severity
        self.title = title
        self.tool = tool
        self.technique_id = technique_id
        self.technique = technique
        self.tactic = tactic
        self.cwe = _TOOL_CWE.get(tool, "")
        self.evidence_lines = evidence_lines
        self.recommendation = recommendation


# ---------------------------------------------------------------------------
# Helper functions (all private)
# ---------------------------------------------------------------------------

def _safe_get(d: dict, key: str, default: Any = "") -> Any:
    """Return d[key] or default — never raises KeyError."""
    try:
        return d[key]
    except (KeyError, TypeError):
        return default


def _trim_output(raw: str, max_lines: int = 20, max_width: int = 100) -> list[str]:
    """Trim raw tool output to at most max_lines lines of max_width characters."""
    lines = raw.splitlines()[:max_lines]
    result: list[str] = []
    for line in lines:
        if len(line) > max_width:
            result.append(line[:max_width] + "… (truncated)")
        else:
            result.append(line)
    return result


def _parse_nmap_ports(output: str) -> list[dict]:
    """Extract open port rows from nmap stdout.

    Returns a list of dicts with keys: port, state, service, version.
    """
    ports: list[dict] = []
    for line in output.splitlines():
        if "/tcp" in line and "open" in line:
            # Typical nmap line: "80/tcp   open  http    nginx 1.18.0"
            parts = line.split()
            port_proto = parts[0] if parts else ""
            port = port_proto.split("/")[0] if "/" in port_proto else port_proto
            state = parts[1] if len(parts) > 1 else "open"
            service = parts[2] if len(parts) > 2 else ""
            version = " ".join(parts[3:]) if len(parts) > 3 else ""
            ports.append(
                {"port": port, "state": state, "service": service, "version": version}
            )
    return ports


def _extract_tool_findings(result: dict) -> list[_Finding]:
    """Derive zero or more _Finding objects from a single tool result dict.

    Gracefully skips any field that is missing or malformed.
    """
    findings: list[_Finding] = []
    try:
        tool = str(_safe_get(result, "tool"))
        exit_code = int(_safe_get(result, "exit_code", 0))
        output = str(_safe_get(result, "output", ""))
        technique_id = str(_safe_get(result, "technique_id", ""))
        technique = str(_safe_get(result, "technique", ""))
        tactic = str(_safe_get(result, "tactic", ""))
        rec = _TOOL_RECOMMENDATION.get(tool, _DEFAULT_RECOMMENDATION)

        # Tools with non-zero exit codes are errors, not findings
        if exit_code != 0:
            return findings

        if tool == "sqlmap":
            findings.extend(
                _parse_sqlmap(output, technique_id, technique, tactic, rec)
            )
        elif tool == "nikto":
            findings.extend(
                _parse_nikto(output, technique_id, technique, tactic, rec)
            )
        elif tool == "nuclei":
            findings.extend(
                _parse_nuclei(output, technique_id, technique, tactic, rec)
            )
        elif tool == "gobuster":
            findings.extend(
                _parse_gobuster(output, technique_id, technique, tactic, rec)
            )
        elif tool == "searchsploit":
            exploits: list[dict] = _safe_get(result, "exploits_found", [])  # type: ignore[assignment]
            findings.extend(
                _parse_searchsploit(exploits, output, technique_id, technique, tactic, rec)
            )
        elif tool in ("nmap", "masscan"):
            findings.extend(
                _parse_port_scanner(tool, output, technique_id, technique, tactic, rec)
            )
    except Exception:  # noqa: BLE001 — swallow any unexpected error per spec
        pass
    return findings


def _parse_sqlmap(
    output: str,
    technique_id: str,
    technique: str,
    tactic: str,
    rec: str,
) -> list[_Finding]:
    """CRITICAL if injectable; no finding if not injectable."""
    injectable_patterns = ["is vulnerable", "parameter is injectable"]
    not_injectable_pattern = "do not appear to be injectable"

    if any(pat in output.lower() for pat in injectable_patterns):
        evidence = _trim_output(output)
        return [
            _Finding(
                severity="CRITICAL",
                title="SQL Injection",
                tool="sqlmap",
                technique_id=technique_id,
                technique=technique,
                tactic=tactic,
                evidence_lines=evidence,
                recommendation=rec,
            )
        ]
    if not_injectable_pattern in output.lower():
        return []
    # Ambiguous — no confirmed finding
    return []


def _parse_nikto(
    output: str,
    technique_id: str,
    technique: str,
    tactic: str,
    rec: str,
) -> list[_Finding]:
    """One MEDIUM finding per nikto '+ ' line (excluding banners)."""
    findings: list[_Finding] = []
    # Lines that are just banners/headers start with '+' but have known patterns
    banner_re = re.compile(
        r"^\+\s+(Target (FQDN|IP|Port|Start|End)|Server:|Retrieved|Nikto|Start Time)",
        re.IGNORECASE,
    )
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped.startswith("+ "):
            continue
        if banner_re.match(stripped):
            continue
        evidence = _trim_output(stripped)
        findings.append(
            _Finding(
                severity="MEDIUM",
                title=stripped[:80],
                tool="nikto",
                technique_id=technique_id,
                technique=technique,
                tactic=tactic,
                evidence_lines=evidence,
                recommendation=rec,
            )
        )
    return findings


def _parse_nuclei(
    output: str,
    technique_id: str,
    technique: str,
    tactic: str,
    rec: str,
) -> list[_Finding]:
    """Extract severity from [severity] tag in each result line."""
    findings: list[_Finding] = []
    # Nuclei -json mode or plain text: look for [severity] bracket
    sev_re = re.compile(r"\[(critical|high|medium|low|info(?:ormational)?)\]", re.IGNORECASE)
    for line in output.splitlines():
        m = sev_re.search(line)
        if not m:
            continue
        raw_sev = m.group(1).lower()
        severity = _NUCLEI_SEVERITY_MAP.get(raw_sev, "INFO")
        evidence = _trim_output(line)
        findings.append(
            _Finding(
                severity=severity,
                title=line[:80].strip(),
                tool="nuclei",
                technique_id=technique_id,
                technique=technique,
                tactic=tactic,
                evidence_lines=evidence,
                recommendation=rec,
            )
        )
    return findings


def _parse_gobuster(
    output: str,
    technique_id: str,
    technique: str,
    tactic: str,
    rec: str,
) -> list[_Finding]:
    """One LOW finding per discovered path line."""
    findings: list[_Finding] = []
    for line in output.splitlines():
        stripped = line.strip()
        # Gobuster -q mode prints lines like: /admin (Status: 200) [Size: 1234]
        if stripped.startswith("/") or re.match(r"^https?://", stripped):
            evidence = _trim_output(stripped)
            findings.append(
                _Finding(
                    severity="LOW",
                    title=f"Discovered path: {stripped[:60]}",
                    tool="gobuster",
                    technique_id=technique_id,
                    technique=technique,
                    tactic=tactic,
                    evidence_lines=evidence,
                    recommendation=rec,
                )
            )
    return findings


def _parse_searchsploit(
    exploits: list[dict],
    output: str,
    technique_id: str,
    technique: str,
    tactic: str,
    rec: str,
) -> list[_Finding]:
    """One HIGH finding per entry in exploits_found."""
    findings: list[_Finding] = []
    for exp in exploits:
        title = str(_safe_get(exp, "title", "Unknown exploit"))
        edb_id = str(_safe_get(exp, "edb_id", ""))
        service = str(_safe_get(exp, "service", ""))
        display = f"{title} (EDB-ID: {edb_id}, service: {service})" if edb_id else title
        evidence = _trim_output(display)
        findings.append(
            _Finding(
                severity="HIGH",
                title=display[:80],
                tool="searchsploit",
                technique_id=technique_id,
                technique=technique,
                tactic=tactic,
                evidence_lines=evidence,
                recommendation=rec,
            )
        )
    return findings


def _parse_port_scanner(
    tool: str,
    output: str,
    technique_id: str,
    technique: str,
    tactic: str,
    rec: str,
) -> list[_Finding]:
    """One INFO finding if any open port is found."""
    findings: list[_Finding] = []
    has_open = any(
        "/tcp" in line and "open" in line for line in output.splitlines()
    )
    if has_open:
        evidence = _trim_output(output)
        findings.append(
            _Finding(
                severity="INFO",
                title="Open port(s) detected",
                tool=tool,
                technique_id=technique_id,
                technique=technique,
                tactic=tactic,
                evidence_lines=evidence,
                recommendation=rec,
            )
        )
    return findings


def _count_severities(findings: list[_Finding]) -> dict[str, int]:
    """Return a dict of severity -> count, ordered by _SEVERITY_ORDER."""
    counts: dict[str, int] = {s: 0 for s in _SEVERITY_ORDER}
    for f in findings:
        sev = f.severity.upper()
        if sev in counts:
            counts[sev] += 1
        else:
            counts[sev] = counts.get(sev, 0) + 1
    return counts


def _tool_counts(results: list[dict]) -> tuple[int, int]:
    """Return (success_count, fail_count) from results list."""
    ok = sum(1 for r in results if int(_safe_get(r, "exit_code", 0)) == 0)
    fail = len(results) - ok
    return ok, fail


def _sanitize_artifact_name(target: str) -> str:
    """Convert a URL-like target to a filename-safe string."""
    # Replace scheme separators and slashes with underscores/colons
    name = re.sub(r"[^a-zA-Z0-9._-]", "_", target)
    return name


def _render_md_table(headers: list[str], rows: list[list[str]]) -> list[str]:
    """Render a markdown table, returning a list of lines."""
    lines: list[str] = []
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join("-" * max(len(h), 3) for h in headers) + " |")
    for row in rows:
        lines.append("| " + " | ".join(str(c) for c in row) + " |")
    return lines


# ---------------------------------------------------------------------------
# Public class
# ---------------------------------------------------------------------------

class KaliBugBountyReport:
    """Render a human-readable bug-bounty report from a raw KaliRunner.run_scan() result.

    Usage::

        report = KaliBugBountyReport()
        markdown = report.render(scan_result, artifact_path="scan.json")
        print(markdown)
    """

    def render(self, report: dict, artifact_path: str = "") -> str:
        """Render a human-readable bug-bounty report from a raw KaliRunner.run_scan() result.

        Args:
            report: Dict returned by ``KaliRunner.run_scan()``.
            artifact_path: Optional path to the saved JSON artifact file.

        Returns:
            Markdown string ready for terminal stdout.
        """
        target = str(_safe_get(report, "target", "unknown"))
        scan_time = str(_safe_get(report, "scan_time", ""))
        tools_run: list[str] = list(_safe_get(report, "tools_run", []))
        results: list[dict] = list(_safe_get(report, "results", []))

        # Collect all findings
        all_findings: list[_Finding] = []
        for result in results:
            try:
                all_findings.extend(_extract_tool_findings(result))
            except Exception:  # noqa: BLE001
                pass

        # Sort findings: Critical → High → Medium → Low → Info
        severity_rank = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
        all_findings.sort(key=lambda f: severity_rank.get(f.severity.upper(), 99))

        counts = _count_severities(all_findings)
        total_findings = sum(counts.values())
        ok_count, fail_count = _tool_counts(results)

        lines: list[str] = []

        # ------------------------------------------------------------------
        # Section 1: Header
        # ------------------------------------------------------------------
        lines.append("# SWIFT Bug Bounty Report")
        lines.append("")
        lines.append(f"Target   : {target}")
        lines.append(f"Scan time: {scan_time}")
        lines.append(
            f"Tools    : {len(tools_run)} run ({ok_count} ✓  {fail_count} ✗)"
        )
        lines.append("")

        # ------------------------------------------------------------------
        # Section 2: Executive Summary
        # ------------------------------------------------------------------
        lines.append("## Executive Summary")
        lines.append("")
        if total_findings == 0:
            lines.append("No actionable findings.")
            lines.append("")
        else:
            rows = [[sev, f"  {counts.get(sev, 0)}  "] for sev in _SEVERITY_ORDER]
            lines.extend(_render_md_table(["Severity", "Count"], rows))
            lines.append("")

        # If zero findings, skip the remaining content sections (but still
        # show tool errors and the trailing artifact line).
        if total_findings > 0:
            # --------------------------------------------------------------
            # Section 3: Findings
            # --------------------------------------------------------------
            lines.append("## Findings")
            lines.append("")
            for finding in all_findings:
                sev = finding.severity.upper()
                lines.append(f"## [{sev}] {finding.title} — {finding.tool}")
                lines.append("")
                mitre_str = (
                    f"{finding.technique_id} {finding.technique} ({finding.tactic})"
                )
                lines.append(f"MITRE : {mitre_str}")
                if finding.cwe:
                    lines.append(f"CWE   : {finding.cwe}")
                lines.append("")
                lines.append("### Evidence")
                lines.append("")
                lines.append("```")
                for ev_line in finding.evidence_lines:
                    lines.append(ev_line)
                lines.append("```")
                lines.append("")
                lines.append("### Recommendation")
                lines.append(finding.recommendation)
                lines.append("")

        # ------------------------------------------------------------------
        # Section 4: Open Ports & Services (only if nmap found open ports)
        # ------------------------------------------------------------------
        nmap_result = next(
            (r for r in results if _safe_get(r, "tool") == "nmap"), None
        )
        if nmap_result is not None:
            nmap_output = str(_safe_get(nmap_result, "output", ""))
            open_ports = _parse_nmap_ports(nmap_output)
            if open_ports:
                lines.append("## Open Ports & Services")
                lines.append("")
                port_rows = [
                    [p["port"], p["state"], p["service"], p["version"]]
                    for p in open_ports
                ]
                lines.extend(
                    _render_md_table(["Port", "State", "Service", "Version"], port_rows)
                )
                lines.append("")

        # ------------------------------------------------------------------
        # Section 5: Tool Errors
        # ------------------------------------------------------------------
        error_results = [
            r for r in results if int(_safe_get(r, "exit_code", 0)) != 0
        ]
        if error_results:
            lines.append("## Tool Errors")
            lines.append("")
            for r in error_results:
                tool_name = str(_safe_get(r, "tool", "unknown"))
                exit_code = int(_safe_get(r, "exit_code", 1))
                raw_out = str(_safe_get(r, "output", ""))
                first_line = raw_out.splitlines()[0] if raw_out.strip() else ""
                trimmed = first_line[:100] if len(first_line) > 100 else first_line
                error_detail = f"container exited with code {exit_code}"
                if trimmed:
                    error_detail += f" ({trimmed})"
                lines.append(f"- {tool_name}: {error_detail}")
            lines.append("")

        # ------------------------------------------------------------------
        # Section 6: Next Steps
        # ------------------------------------------------------------------
        next_steps: list[str] = []

        # SQLi bullet
        sqlmap_result = next(
            (r for r in results if _safe_get(r, "tool") == "sqlmap"), None
        )
        if sqlmap_result is not None:
            sq_output = str(_safe_get(sqlmap_result, "output", "")).lower()
            if any(p in sq_output for p in ["is vulnerable", "parameter is injectable"]):
                next_steps.append(
                    "Manually confirm SQLi findings before reporting "
                    "— sqlmap on root URL may be a false positive."
                )

        # Nuclei re-run bullet (if nuclei errored)
        nuclei_errored = any(
            _safe_get(r, "tool") == "nuclei" and int(_safe_get(r, "exit_code", 0)) != 0
            for r in results
        )
        if nuclei_errored:
            next_steps.append(
                "Re-run with `--tools nuclei` after pulling templates: "
                "`docker pull projectdiscovery/nuclei`."
            )

        # Open ports bullet
        if nmap_result is not None:
            nmap_output2 = str(_safe_get(nmap_result, "output", ""))
            if _parse_nmap_ports(nmap_output2):
                next_steps.append("Review open ports for unexpected services.")

        # Fallback if nothing specific
        if not next_steps:
            next_steps.append(
                "No high-confidence findings detected. Consider expanding scope "
                "or running with additional tools."
            )

        if next_steps:
            lines.append("## Next Steps")
            lines.append("")
            for step in next_steps:
                lines.append(f"- {step}")
            lines.append("")

        # ------------------------------------------------------------------
        # Trailing artifact line (always shown)
        # ------------------------------------------------------------------
        lines.append("---")
        if artifact_path:
            artifact_label = artifact_path
        else:
            safe_name = _sanitize_artifact_name(target)
            artifact_label = f"kali-scan-{safe_name}.json"
        lines.append(f"_Artifact: {artifact_label}_")

        return "\n".join(lines)
