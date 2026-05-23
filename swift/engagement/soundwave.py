"""Soundwave engagement interviewer.

Two paths:

* :func:`engage`        -- LLM-driven; uses the soundwave specialist
                           sub-graph and writes roe.yaml / OPPLAN.md / ConOps.md
                           into the supplied output directory.
* :func:`engage_quick`  -- stamps templates without any LLM call. Useful for
                           offline / CI / first-run bootstrap.
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

import yaml

from engagement.conops import render_conops
from engagement.opplan import OPPLAN, render_opplan
from log.audit import log_step


def _default_window() -> tuple[str, str]:
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    return now.isoformat(), (now + dt.timedelta(hours=4)).isoformat()


def engage_quick(
    *,
    engagement_id: str,
    targets: list[str],
    contact: str,
    outdir: str | Path = ".swift-engagement",
    techniques: list[str] | None = None,
    simulate_only: bool = True,
) -> dict[str, Path]:
    """Write template roe.yaml / OPPLAN.md / ConOps.md. No LLM."""
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    start, end = _default_window()
    techniques = techniques or [
        "osint", "active_scan", "research",
        "vuln_pipeline", "engagement_planning",
    ]

    roe = {
        "engagement_id": engagement_id,
        "authorized_targets": targets,
        "allowed_techniques": techniques,
        "window_start": start,
        "window_end": end,
        "contact": contact,
        "simulate_only": simulate_only,
        "allow_chain_execution": False,
        "rate_limit_rps": 2.0,
        "rate_limit_burst": 1,
        "max_runtime_seconds": 1800,
    }
    roe_path = outdir / "roe.yaml"
    roe_path.write_text(yaml.safe_dump(roe, sort_keys=False), encoding="utf-8")

    opplan = OPPLAN(engagement_id=engagement_id, targets=targets, contact=contact)
    opplan_path = outdir / "OPPLAN.md"
    opplan_path.write_text(render_opplan(opplan), encoding="utf-8")

    conops_path = outdir / "ConOps.md"
    conops_path.write_text(
        render_conops(engagement_id=engagement_id, targets=targets, contact=contact),
        encoding="utf-8",
    )

    log_step("engage.quick", engagement_id=engagement_id, outdir=str(outdir))
    return {"roe": roe_path, "opplan": opplan_path, "conops": conops_path}


def engage(
    *,
    engagement_id: str,
    targets: list[str],
    contact: str,
    outdir: str | Path = ".swift-engagement",
    answers: dict[str, str] | None = None,
) -> dict[str, Path]:
    """LLM-driven engagement interview.

    Boot-straps the template files via :func:`engage_quick`, then runs the
    soundwave specialist with the seed state so the LLM can refine the docs.
    """
    paths = engage_quick(
        engagement_id=engagement_id, targets=targets, contact=contact, outdir=outdir,
    )

    # Optional refinement pass through the LLM.
    try:
        from agent.langgraph_layer import run_subgraph
        state: dict[str, Any] = {
            "engagement": {
                "engagement_id": engagement_id,
                "authorized_targets": targets,
                "contact": contact,
                "allowed_techniques": ["engagement_planning"],
                "simulate_only": True,
            },
            "answers": answers or {},
            "outdir": str(Path(outdir).resolve()),
        }
        run_subgraph("soundwave", state)
        log_step("engage.llm_refined", engagement_id=engagement_id)
    except Exception as exc:  # pragma: no cover -- LLM optional
        log_step("engage.llm_skipped", reason=str(exc))

    return paths
