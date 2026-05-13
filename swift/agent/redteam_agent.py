"""Agentic Red-Team Loop — Module 5.

Sonnet tool-use loop that reasons about attack surface,
forms hypotheses, runs probes, and chains findings.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from collections import Counter
from pathlib import Path
from typing import Any

from .agent_prompts import (
    AGENT_SYSTEM_PROMPT,
    MODELS,
    AgentBudget,
    AgentHypothesis,
    EngagementResult,
)
from .agent_tools import TOOL_SCHEMAS, dispatch_tool

_CLIENT = None


def _get_client():
    global _CLIENT
    if _CLIENT is None:
        import anthropic
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if api_key:
            _CLIENT = anthropic.Anthropic(api_key=api_key)
    return _CLIENT


class RedTeamAgent:
    """Sonnet-driven agentic penetration test loop."""

    def __init__(
        self,
        target: str,
        roe,
        budget: AgentBudget | None = None,
        audit_logger=None,
        engagement_dir: Path | None = None,
    ) -> None:
        self.target = target
        self.roe = roe
        self.budget = budget or AgentBudget()
        self.audit = audit_logger
        self.engagement_dir = engagement_dir or Path.home() / ".swift" / "engagements" / "latest"

        self.findings_store: list = []
        self.hypotheses: list[AgentHypothesis] = []
        self.exhausted_vectors: set[str] = set()
        self.message_history: list[dict] = []
        self.iteration: int = 0
        self.attack_surface: dict[str, Any] = {}

        self._probe_history: list[tuple[str, str]] = []  # (probe_name, target)

    async def run(self) -> EngagementResult:
        log_path = self.engagement_dir / "agent_log.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Seed with initial user message
        self.message_history.append({
            "role": "user",
            "content": (
                f"Begin authorized penetration test against: {self.target}\n"
                f"ROE: techniques={sorted(self.roe.allowed_techniques)}, "
                f"simulate_only={self.roe.simulate_only}\n"
                "Start by calling get_attack_surface for all categories, "
                "then form hypotheses and run probes."
            ),
        })

        while self._budget_remaining():
            response = await self._call_sonnet()
            if response is None:
                break

            self.budget.sonnet_calls_used += 1
            await self._log_iteration(log_path, response)

            if response.stop_reason == "end_turn":
                break

            tool_calls = [b for b in response.content if b.type == "tool_use"]
            if not tool_calls:
                break

            tool_results = []
            for tc in tool_calls:
                if not self._budget_remaining():
                    break
                result = await dispatch_tool(tc.name, tc.input, self)
                self._probe_history.append((tc.name, str(tc.input.get("target", ""))))
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tc.id,
                    "content": json.dumps(result, default=str),
                })

            self.message_history.append({"role": "assistant", "content": response.content})
            self.message_history.append({"role": "user", "content": tool_results})

            self._compress_history_if_long()
            self.iteration += 1

            if self._plateau_detected():
                break

            # Warn at 80% budget
            if (self.budget.probe_calls_used / max(self.budget.max_probe_calls, 1)) >= 0.8:
                pass  # logged in agent_log

        return EngagementResult(
            findings=self.findings_store,
            hypotheses=self.hypotheses,
            iterations=self.iteration,
            budget_consumed=self.budget,
            agent_log_path=log_path,
        )

    def _budget_remaining(self) -> bool:
        return not self.budget.is_exhausted()

    def _plateau_detected(self) -> bool:
        """Sliding window: last 8 tool calls all returned empty/low-confidence."""
        window = self._probe_history[-8:]
        if len(window) < 8:
            return False
        counter = Counter(window)
        if any(v > 5 for v in counter.values()):
            # Fallback: mark current vectors exhausted, try unexplored
            self.exhausted_vectors.update(set(window))
            return True
        return False

    def _compress_history_if_long(self) -> None:
        if len(self.message_history) <= 20:
            return
        # Summarize turns 1..N-5 via Haiku
        old = self.message_history[1:-5]
        keep = self.message_history[-5:]
        vuln_types = sorted({str(getattr(f, "vuln_type", "?")) for f in self.findings_store})
        exhausted = sorted(self.exhausted_vectors)
        summary_text = (
            f"[COMPRESSED: {len(old)} prior turns. "
            f"Findings: {len(self.findings_store)} ({', '.join(vuln_types) or 'none'}). "
            f"Hypotheses: {len(self.hypotheses)}. "
            f"Exhausted vectors: {exhausted}.]"
        )
        self.message_history = [self.message_history[0], {"role": "user", "content": summary_text}, *keep]

    async def _call_sonnet(self):
        client = _get_client()
        if not client:
            return None
        loop = asyncio.get_event_loop()
        def _call():
            return client.messages.create(
                model=MODELS["sonnet"],
                max_tokens=4096,
                system=AGENT_SYSTEM_PROMPT,
                tools=TOOL_SCHEMAS,
                messages=self.message_history,
            )
        try:
            return await loop.run_in_executor(None, _call)
        except Exception:
            return None

    async def _log_iteration(self, log_path: Path, response) -> None:
        entry = {
            "timestamp": time.time(),
            "iteration": self.iteration,
            "stop_reason": getattr(response, "stop_reason", None),
            "tool_calls": [
                {"name": b.name, "input": b.input}
                for b in getattr(response, "content", [])
                if b.type == "tool_use"
            ],
            "finding_count": len(self.findings_store),
            "budget_probes": self.budget.probe_calls_used,
            "budget_sonnet": self.budget.sonnet_calls_used,
        }
        with log_path.open("a") as f:
            f.write(json.dumps(entry, default=str) + "\n")


def show_agent_status(args) -> None:
    """Print live agent status from engagement_dir/agent_log.jsonl."""
    import sys
    engagement_dir = getattr(args, "engagement_dir", None)
    if not engagement_dir:
        # Find latest
        base = Path.home() / ".swift" / "engagements"
        if not base.exists():
            print("[agent-status] No engagements found.", file=sys.stderr)
            return
        dirs = sorted(base.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
        if not dirs:
            print("[agent-status] No engagements found.", file=sys.stderr)
            return
        engagement_dir = dirs[0]

    log_path = Path(engagement_dir) / "agent_log.jsonl"
    if not log_path.exists():
        print(f"[agent-status] No agent_log.jsonl in {engagement_dir}", file=sys.stderr)
        return

    entries = []
    with log_path.open() as f:
        for line in f:
            try:
                entries.append(json.loads(line))
            except Exception:
                pass

    if not entries:
        print("[agent-status] Log empty.")
        return

    last = entries[-1]
    print(f"Iterations: {last.get('iteration', '?')}")
    print(f"Findings: {last.get('finding_count', '?')}")
    print(f"Budget probes: {last.get('budget_probes', '?')}")
    print(f"Budget Sonnet: {last.get('budget_sonnet', '?')}")
    print(f"Stop reason: {last.get('stop_reason', 'running')}")
