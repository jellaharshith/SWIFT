"""Route swiftsec hunt --ptes through the PTES 7-phase DAG with bounty ROE profile.

Bug-bounty mode differences vs pentest mode:
- Intel phase is passive-heavy (no active scanning without explicit ROE)
- Exploitation requires verifier gate (no direct exploitation)
- Report uses platform-specific formatter on top of Rosén narrative
"""
from __future__ import annotations

from typing import Any

from agent.langgraph_layer.graphs.ptes import run_ptes
from agent.langgraph_layer.graphs import State


def run_bounty_ptes(
    state: State,
    *,
    program: str,
    platform: str = "h1",
    depth: str = "standard",
    stop_after: str | None = None,
    out_dir: str = ".swift-artifacts/hunt-ptes",
) -> State:
    """Run the PTES 7-phase pipeline in bug-bounty mode.

    Differences from pentest mode:
    - ptes_mode = 'bounty' (read by specialists to adjust aggressiveness)
    - Platform tag injected into state for report formatter
    - Exploit phase uses verifier → exploiter subchain only (no direct kali_run)
    """
    state.setdefault("findings", [])
    state["bounty_program"] = program
    state["bounty_platform"] = platform
    state["ptes_mode"] = "bounty"

    return run_ptes(
        state,
        mode="bounty",
        depth=depth,
        stop_after=stop_after,
        out_dir=out_dir,
    )
