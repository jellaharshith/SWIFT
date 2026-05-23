"""Bug-bounty finding validation.

The 7-question gate from claude-bug-bounty, rendered as code so SWIFT can
run it offline before any report is filed. Each question is a small
predicate over a :class:`Finding`; the first ``False`` short-circuits to
``KILL <Q#>``.

Also exposes a 4-gate post-pass checklist (scope, novelty, impact, PoC
reproducibility) that produces ``PASS`` / ``DOWNGRADE``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    PASS = "PASS"
    KILL = "KILL"
    DOWNGRADE = "DOWNGRADE"
    CHAIN_REQUIRED = "CHAIN_REQUIRED"


@dataclass
class Finding:
    title: str
    target_url: str
    bug_class: str
    severity: str = "medium"          # critical / high / medium / low / info
    # Q1: Reproducible right now via a concrete HTTP request?
    has_request_response: bool = False
    request_evidence: str = ""        # raw HTTP req+resp pair
    # Q2: bug_class on program's accepted list?
    program_accepts_class: bool = True
    program_excludes_reason: str = ""
    # Q3: in scope?
    in_scope: bool = True
    # Q4: works without privileged access an attacker can't realistically obtain?
    needs_admin_only: bool = False
    # Q5: not already documented / disclosed?
    is_documented_behavior: bool = False
    # Q6: impact proved beyond "technically possible"?
    impact_evidence_level: str = "full"   # full | partial | none
    # Q7: not on the never-submit list?
    on_never_submit_list: bool = False
    chain_with: list[str] = field(default_factory=list)
    # Free notes
    notes: str = ""


_NEVER_SUBMIT = {
    "missing_security_headers",
    "missing_spf_dkim_dmarc",
    "graphql_introspection",
    "banner_disclosure",
    "open_redirect_no_impact",
    "self_xss",
    "user_enum_login",
}


@dataclass
class ValidationResult:
    verdict: Verdict
    reason: str = ""
    failed_question: int | None = None
    suggested_severity: str | None = None
    gates: dict[str, bool] = field(default_factory=dict)


def _seven_question_gate(f: Finding) -> ValidationResult:
    # Q1
    if not f.has_request_response or not f.request_evidence.strip():
        return ValidationResult(Verdict.KILL, "Q1: no reproducible HTTP request/response", 1)
    # Q2
    if not f.program_accepts_class:
        return ValidationResult(Verdict.KILL,
                                f"Q2: program excludes class '{f.bug_class}': {f.program_excludes_reason}", 2)
    # Q3
    if not f.in_scope:
        return ValidationResult(Verdict.KILL, "Q3: target not in scope", 3)
    # Q4
    if f.needs_admin_only:
        return ValidationResult(Verdict.KILL, "Q4: requires admin-only access", 4)
    # Q5
    if f.is_documented_behavior:
        return ValidationResult(Verdict.KILL, "Q5: documented behavior, not a flaw", 5)
    # Q6
    if f.impact_evidence_level == "none":
        return ValidationResult(Verdict.KILL, "Q6: impact unproven", 6)
    if f.impact_evidence_level == "partial":
        return ValidationResult(Verdict.DOWNGRADE,
                                "Q6: partial impact -- downgrade severity",
                                6, suggested_severity=_downgrade(f.severity))
    # Q7
    if f.bug_class in _NEVER_SUBMIT or f.on_never_submit_list:
        if f.chain_with:
            return ValidationResult(Verdict.CHAIN_REQUIRED,
                                    f"Q7: never-submit class but chain available with {f.chain_with}",
                                    7)
        return ValidationResult(Verdict.KILL,
                                f"Q7: '{f.bug_class}' on never-submit list and no chain",
                                7)
    return ValidationResult(Verdict.PASS, "all 7 questions passed")


def _downgrade(sev: str) -> str:
    order = ["critical", "high", "medium", "low", "info"]
    if sev not in order:
        return "low"
    i = order.index(sev)
    return order[min(i + 1, len(order) - 1)]


def _four_gate_check(f: Finding) -> dict[str, bool]:
    return {
        "scope":      f.in_scope,
        "novelty":    not f.is_documented_behavior,
        "impact":     f.impact_evidence_level in ("full", "partial"),
        "reproducible": f.has_request_response and bool(f.request_evidence.strip()),
    }


def validate(f: Finding) -> ValidationResult:
    res = _seven_question_gate(f)
    res.gates = _four_gate_check(f)
    return res


def validate_dict(d: dict[str, Any]) -> ValidationResult:
    """Convenience wrapper for CLI use: validate a finding from a dict / JSON."""
    f = Finding(**{k: v for k, v in d.items() if k in Finding.__dataclass_fields__})
    return validate(f)
