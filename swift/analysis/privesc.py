from __future__ import annotations
from typing import List
from agent.models import EscalationPath, UnifiedScanResult


_PATTERNS: list[tuple[str, list[str], str, str]] = [
    # (vuln_type, steps, to_impact, base_severity)
    ("sql_injection",            ["DB credential leak", "Admin panel access"],  "account_takeover",        "HIGH"),
    ("ssrf",                     ["Internal network access", "Metadata service"],"cloud_credential_theft",  "HIGH"),
    ("command_injection",        ["Shell access"],                               "full_host_compromise",    "CRITICAL"),
    ("path_traversal",           ["Credential file read", "Lateral movement"],  "privilege_escalation",    "HIGH"),
    ("xxe",                      ["File read", "SSRF pivot"],                   "internal_network_access", "HIGH"),
    ("insecure_deserialization", ["Object injection"],                           "RCE",                     "CRITICAL"),
    ("broken_auth",              ["Session hijack"],                             "account_takeover",        "HIGH"),
    ("open_redirect",            ["Phishing", "Session steal"],                  "account_takeover",        "MEDIUM"),
]

_PATTERN_MAP = {p[0]: p for p in _PATTERNS}


def _build_ascii_chain(from_vuln: str, steps: list[str], to_impact: str) -> str:
    parts = [from_vuln] + steps + [to_impact]
    return " ──► ".join(parts)


class PrivilegeEscalationAnalyzer:
    def analyze(self, result: UnifiedScanResult) -> list[EscalationPath]:
        # Collect all (vuln_type, finding_id, actively_exploited) triples
        triples: list[tuple[str, str, bool]] = []
        for mf in result.merged_findings:
            triples.append((mf.vuln_type, mf.id, mf.actively_exploited))
        for cf in result.code_only_findings:
            triples.append((cf.vuln_type, cf.id, False))
        for kf in result.kali_only_findings:
            vt = kf.get("vuln_type", "") if isinstance(kf, dict) else ""
            triples.append((vt, kf.get("id", "kali"), False))

        paths: list[EscalationPath] = []
        for vuln_type, finding_id, actively_exploited in triples:
            if vuln_type not in _PATTERN_MAP:
                continue
            _, steps, to_impact, base_severity = _PATTERN_MAP[vuln_type]
            severity = "CRITICAL" if (actively_exploited or base_severity == "CRITICAL") else base_severity
            paths.append(EscalationPath(
                from_vuln=vuln_type,
                steps=list(steps),
                to_impact=to_impact,
                severity=severity,
                finding_ids=[finding_id],
                ascii_chain=_build_ascii_chain(vuln_type, steps, to_impact),
            ))
        return paths
