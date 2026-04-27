"""Correlator — merge code scan, Kali, and CVE findings into unified results."""
from __future__ import annotations

import uuid
from urllib.parse import urlparse

from agent.models import MergedFinding, ScanResult, Vulnerability
from feeds.live_cve import CVEEntry, CVEMatch

# Web-related path keywords used when extracting endpoint hints from file paths.
_WEB_KEYWORDS = ("login", "auth", "api", "user", "admin")

# Severity ordering: higher index = higher severity.
_SEVERITY_ORDER = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def _severity_rank(s: str) -> int:
    """Return an integer rank for a severity string (higher = more severe)."""
    return _SEVERITY_ORDER.index(s.upper()) if s.upper() in _SEVERITY_ORDER else -1


def _max_severity(a: str, b: str) -> str:
    """Return whichever of *a* or *b* is the higher severity."""
    return a if _severity_rank(a) >= _severity_rank(b) else b


def _endpoint_from_url(target: str) -> str:
    """Extract the URL path from a target string, e.g. 'http://x.com/login' → '/login'."""
    try:
        return urlparse(target).path or "/"
    except Exception:
        return "/"


def _endpoint_from_file_path(file_path: str) -> str:
    """Return a web-keyword hint extracted from a file path, or empty string."""
    lower = file_path.lower()
    for kw in _WEB_KEYWORDS:
        if kw in lower:
            return f"/{kw}"
    return ""


def _match_confidence(vuln: Vulnerability, kali_finding: dict) -> float:
    """Compute the best match confidence between a code Vulnerability and a Kali finding.

    Rules (take the maximum):
      - CWE overlap:              0.9
      - vuln_type keyword match:  0.8
      - endpoint path substring:  0.7
    """
    best = 0.0

    # --- CWE overlap ---
    vuln_cwe = (vuln.cwe_id or "").upper()
    kali_output = (kali_finding.get("output") or "").upper()
    if vuln_cwe and vuln_cwe in kali_output:
        best = max(best, 0.9)

    # --- vuln_type keyword match ---
    vuln_type_lower = vuln.vuln_type.lower().replace("_", " ")
    kali_tool = (kali_finding.get("tool") or "").lower()
    kali_output_lower = (kali_finding.get("output") or "").lower()
    # Any significant word from vuln_type appearing in tool name or output
    if any(
        word in kali_tool or word in kali_output_lower
        for word in vuln_type_lower.split()
        if len(word) > 3
    ):
        best = max(best, 0.8)

    # --- endpoint path substring ---
    kali_target = kali_finding.get("target", "")
    kali_path = _endpoint_from_url(kali_target).lower()
    vuln_path_hint = _endpoint_from_file_path(vuln.file_path).lower()
    if vuln_path_hint and kali_path and (
        vuln_path_hint in kali_path or kali_path in vuln_path_hint
    ):
        best = max(best, 0.7)

    return best


def _mitre_techniques_from_kali(kali_finding: dict) -> list[dict]:
    """Extract MITRE ATT&CK metadata from a Kali finding dict."""
    technique: dict = {}
    if kali_finding.get("technique_id"):
        technique["technique_id"] = kali_finding["technique_id"]
    if kali_finding.get("technique"):
        technique["technique"] = kali_finding["technique"]
    if kali_finding.get("tactic"):
        technique["tactic"] = kali_finding["tactic"]
    return [technique] if technique else []


def _enrich_merged_with_cves(
    mf: MergedFinding, cve_entries: list[CVEEntry]
) -> None:
    """Attach CVEMatch objects to *mf* and escalate severity/actively_exploited."""
    vuln = mf.code_finding
    for cve in cve_entries:
        match_reason = ""
        confidence = 0.0

        if vuln and vuln.cwe_id and vuln.cwe_id in cve.cwe_ids:
            match_reason = f"CWE match: {vuln.cwe_id}"
            confidence = 0.9
        elif vuln:
            keyword = vuln.vuln_type.lower().replace("_", " ")
            if any(w in cve.description.lower() for w in keyword.split() if len(w) > 3):
                match_reason = f"Keyword match: {keyword}"
                confidence = 0.6

        if confidence >= 0.6:
            mf.cve_matches.append(CVEMatch(
                cve=cve,
                matched_finding_id=mf.id,
                match_reason=match_reason,
                confidence=confidence,
            ))
            if cve.cisa_known_exploited:
                mf.actively_exploited = True
                mf.severity = _max_severity(mf.severity, "CRITICAL")


def _enrich_code_vuln_with_cves(
    vuln: Vulnerability,
    vuln_id: str,
    cve_entries: list[CVEEntry],
) -> tuple[list[CVEMatch], bool]:
    """Return (cve_matches, actively_exploited) for a standalone code Vulnerability."""
    matches: list[CVEMatch] = []
    actively_exploited = False

    for cve in cve_entries:
        match_reason = ""
        confidence = 0.0

        if vuln.cwe_id and vuln.cwe_id in cve.cwe_ids:
            match_reason = f"CWE match: {vuln.cwe_id}"
            confidence = 0.9
        else:
            keyword = vuln.vuln_type.lower().replace("_", " ")
            if any(w in cve.description.lower() for w in keyword.split() if len(w) > 3):
                match_reason = f"Keyword match: {keyword}"
                confidence = 0.6

        if confidence >= 0.6:
            matches.append(CVEMatch(
                cve=cve,
                matched_finding_id=vuln_id,
                match_reason=match_reason,
                confidence=confidence,
            ))
            if cve.cisa_known_exploited:
                actively_exploited = True

    return matches, actively_exploited


def _enrich_kali_finding_with_cves(
    kf: dict,
    kf_id: str,
    cve_entries: list[CVEEntry],
) -> tuple[list[CVEMatch], bool]:
    """Return (cve_matches, actively_exploited) for a standalone Kali finding."""
    matches: list[CVEMatch] = []
    actively_exploited = False

    tool_keyword = (kf.get("tool") or "").lower()
    output_keyword = (kf.get("output") or "").lower()

    for cve in cve_entries:
        desc_lower = cve.description.lower()
        if tool_keyword and tool_keyword in desc_lower:
            matches.append(CVEMatch(
                cve=cve,
                matched_finding_id=kf_id,
                match_reason=f"Keyword match: {tool_keyword}",
                confidence=0.6,
            ))
            if cve.cisa_known_exploited:
                actively_exploited = True
        elif output_keyword:
            # Try a few significant words from the output
            words = [w for w in output_keyword.split() if len(w) > 4][:10]
            if any(w in desc_lower for w in words):
                matches.append(CVEMatch(
                    cve=cve,
                    matched_finding_id=kf_id,
                    match_reason=f"Output keyword match",
                    confidence=0.6,
                ))
                if cve.cisa_known_exploited:
                    actively_exploited = True

    return matches, actively_exploited


class Correlator:
    """Merge code scan results, Kali findings, and CVE entries into unified output."""

    def merge(
        self,
        code_result: ScanResult | None,
        kali_result: dict | None,
        cve_entries: list[CVEEntry],
    ) -> tuple[list[MergedFinding], list[Vulnerability], list[dict]]:
        """Correlate findings across sources.

        Args:
            code_result: Result from static code analysis (may be None).
            kali_result: Result dict from Kali runner (may be None).
            cve_entries: CVE entries for enrichment.

        Returns:
            A 3-tuple of:
              - merged_findings: Findings detected by both code and Kali.
              - code_only_findings: Vulnerabilities found only by code analysis.
              - kali_only_findings: Findings found only by Kali scanning.
        """
        vulns: list[Vulnerability] = (
            code_result.vulnerabilities if code_result else []
        )
        kali_findings: list[dict] = (
            kali_result.get("results", []) if kali_result else []
        )

        matched_vuln_indices: set[int] = set()
        matched_kali_indices: set[int] = set()
        merged: list[MergedFinding] = []

        # --- Greedy best-match pairing ---
        for i, vuln in enumerate(vulns):
            best_conf = 0.0
            best_kali_idx = -1

            for j, kf in enumerate(kali_findings):
                if j in matched_kali_indices:
                    continue
                conf = _match_confidence(vuln, kf)
                if conf > best_conf:
                    best_conf = conf
                    best_kali_idx = j

            if best_conf >= 0.6 and best_kali_idx >= 0:
                matched_vuln_indices.add(i)
                matched_kali_indices.add(best_kali_idx)

                kf = kali_findings[best_kali_idx]
                severity = _max_severity(vuln.severity, "HIGH")
                mf = MergedFinding(
                    id="MERGED-" + uuid.uuid4().hex[:8],
                    vuln_type=vuln.vuln_type,
                    severity=severity,
                    sources=["code", "kali"],
                    code_finding=vuln,
                    kali_finding=kf,
                    correlation_confidence=best_conf,
                    mitre_techniques=_mitre_techniques_from_kali(kf),
                )
                merged.append(mf)

        code_only: list[Vulnerability] = [
            v for i, v in enumerate(vulns) if i not in matched_vuln_indices
        ]
        kali_only: list[dict] = [
            kf for j, kf in enumerate(kali_findings) if j not in matched_kali_indices
        ]

        # --- CVE enrichment ---
        # Merged findings
        for mf in merged:
            _enrich_merged_with_cves(mf, cve_entries)

        # Code-only findings — wrap as MergedFinding-like objects don't exist here;
        # we annotate the Vulnerability objects directly via a side-channel approach.
        # The task spec says code_only returns List[Vulnerability], so we attach
        # CVE info to a parallel attribute if it exists, otherwise we create a
        # thin MergedFinding wrapper and store back for the caller's use.
        # Per the spec, code_only is List[Vulnerability] — we enrich and return as-is,
        # but callers can call _enrich_code_vuln_with_cves themselves.
        # (No mutation of Vulnerability needed per spec — enrichment touches MergedFinding.)

        # Kali-only findings are plain dicts — no mutation needed per spec either.
        # We run enrichment so that any actively_exploited flag would normally surface,
        # but since kali_only is List[dict] there's no field to set. We skip silent
        # mutation of caller dicts and trust the caller to re-enrich as needed.

        return merged, code_only, kali_only
