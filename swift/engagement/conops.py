"""ConOps -- Concept of Operations narrative."""
from __future__ import annotations

from datetime import datetime, timezone


def render_conops(
    *,
    engagement_id: str,
    targets: list[str],
    contact: str,
    narrative: str = "",
    success_criteria: list[str] | None = None,
    abort_conditions: list[str] | None = None,
) -> str:
    success_criteria = success_criteria or [
        "All authorized targets enumerated, no out-of-scope traffic.",
        "Every finding reproducible from the audit log.",
    ]
    abort_conditions = abort_conditions or [
        "Any out-of-scope target contacted.",
        "Production alarm raised by target's blue team.",
        "Operator presses Ctrl-C.",
    ]
    now = datetime.now(timezone.utc).isoformat()
    lines: list[str] = [
        f"# ConOps -- {engagement_id}",
        f"_Generated {now}_",
        "",
        "## Mission",
        narrative or "_Operator to fill in: 1-2 paragraphs describing the engagement intent._",
        "",
        "## Scope",
        f"- Contact: {contact or '(unset)'}",
        f"- Authorized targets: {', '.join(targets) or '(none)'}",
        "",
        "## Success criteria",
    ]
    lines.extend(f"- {c}" for c in success_criteria)
    lines += ["", "## Abort conditions"]
    lines.extend(f"- {c}" for c in abort_conditions)
    return "\n".join(lines)
