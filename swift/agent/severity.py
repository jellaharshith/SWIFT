"""CVSS v3.1 base score calculator + severity mapper for web findings."""
from __future__ import annotations
import os
from agent.bounty_models import WebFinding

# CVSS v3.1 metric presets for common web vulnerability classes.
# Chosen to reflect realistic attacker position (network, no auth, typical UI).
_VULN_CVSS_PRESETS: dict[str, dict] = {
    "sqli":        {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"},
    "xss":         {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"},
    "idor":        {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
    "ssrf":        {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"},
    "auth_bypass": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
    "misconfig":   {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "L", "A": "L"},
    "jwt":         {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
    "default":     {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"},
}


def _numeric(metric: str, val: str) -> float:
    """Look up the CVSS v3.1 numeric weight for a metric/value pair."""
    tables: dict[str, dict[str, float]] = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
        "AC": {"L": 0.77, "H": 0.44},
        "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
        "UI": {"N": 0.85, "R": 0.62},
        "S":  {"U": 0.0,  "C": 1.0},   # used as a boolean flag
        "C":  {"N": 0.00, "L": 0.22, "H": 0.56},
        "I":  {"N": 0.00, "L": 0.22, "H": 0.56},
        "A":  {"N": 0.00, "L": 0.22, "H": 0.56},
    }
    return tables.get(metric, {}).get(val, 0.0)


def score_cvss(finding: WebFinding) -> float:
    """Compute CVSS v3.1 base score for a WebFinding.

    Args:
        finding: The vulnerability to score.

    Returns:
        Float in the range 0.0–10.0, rounded to one decimal place.
    """
    preset = _VULN_CVSS_PRESETS.get(finding.vuln_type.lower(), _VULN_CVSS_PRESETS["default"])

    av = _numeric("AV", preset["AV"])
    ac = _numeric("AC", preset["AC"])
    pr = _numeric("PR", preset["PR"])
    ui = _numeric("UI", preset["UI"])
    scope_changed = preset["S"] == "C"
    c_ = _numeric("C", preset["C"])
    i_ = _numeric("I", preset["I"])
    a_ = _numeric("A", preset["A"])

    isc_base = 1 - (1 - c_) * (1 - i_) * (1 - a_)

    if scope_changed:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)
    else:
        impact = 6.42 * isc_base

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0

    if scope_changed:
        score = min(10.0, 1.08 * (impact + exploitability))
    else:
        score = min(10.0, impact + exploitability)

    return round(score, 1)


def severity_from_cvss(score: float) -> str:
    """Map a CVSS base score to a qualitative severity label.

    Args:
        score: CVSS v3.1 base score (0.0–10.0).

    Returns:
        One of: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL.
    """
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 0.1:
        return "LOW"
    return "INFORMATIONAL"


def cvss_vector(finding: WebFinding) -> str:
    """Return the CVSS v3.1 vector string for a WebFinding.

    Args:
        finding: The vulnerability whose vector to compute.

    Returns:
        Formatted CVSS:3.1/... vector string.
    """
    preset = _VULN_CVSS_PRESETS.get(finding.vuln_type.lower(), _VULN_CVSS_PRESETS["default"])
    p = preset
    return (
        f"CVSS:3.1/AV:{p['AV']}/AC:{p['AC']}/PR:{p['PR']}/UI:{p['UI']}"
        f"/S:{p['S']}/C:{p['C']}/I:{p['I']}/A:{p['A']}"
    )
