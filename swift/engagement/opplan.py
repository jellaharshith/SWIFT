"""OPPLAN -- Operation Plan -- MITRE ATT&CK-mapped phase plan."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


# Minimal MITRE ATT&CK technique catalog used by SWIFT phases.
_ATT_CK = {
    "recon":         ["T1595 Active Scanning", "T1592 Gather Victim Host Info", "T1589 Gather Victim Identity Info"],
    "initial_access": ["T1190 Exploit Public-Facing App", "T1133 External Remote Services"],
    "execution":     ["T1059 Command and Scripting Interpreter"],
    "credential_access": ["T1110 Brute Force", "T1003 OS Credential Dumping"],
    "lateral_movement": ["T1021 Remote Services"],
    "exfiltration":  ["T1041 Exfiltration Over C2"],
}


@dataclass
class OPPLAN:
    engagement_id: str
    targets: list[str]
    phases: list[str] = field(default_factory=lambda: list(_ATT_CK.keys()))
    objectives: list[str] = field(default_factory=list)
    constraints: list[str] = field(default_factory=list)
    contact: str = ""

    def attck_for(self, phase: str) -> list[str]:
        return _ATT_CK.get(phase, [])


def render_opplan(plan: OPPLAN) -> str:
    """Render an :class:`OPPLAN` as Markdown."""
    now = datetime.now(timezone.utc).isoformat()
    lines: list[str] = [
        f"# OPPLAN -- {plan.engagement_id}",
        f"_Generated {now}_",
        "",
        "## Engagement",
        f"- Engagement ID: `{plan.engagement_id}`",
        f"- Contact: {plan.contact or '(unset)'}",
        f"- Targets: {', '.join(plan.targets) or '(none)'}",
        "",
        "## Objectives",
    ]
    if plan.objectives:
        lines.extend(f"- {o}" for o in plan.objectives)
    else:
        lines.append("- (none specified)")

    lines += ["", "## Constraints"]
    if plan.constraints:
        lines.extend(f"- {c}" for c in plan.constraints)
    else:
        lines.append("- ROE simulate_only=True unless explicitly toggled in roe.yaml")

    lines += ["", "## Phases & MITRE ATT&CK"]
    for ph in plan.phases:
        lines.append(f"### {ph}")
        for t in plan.attck_for(ph):
            lines.append(f"- {t}")
        lines.append("")

    return "\n".join(lines)
