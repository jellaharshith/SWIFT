"""Claude-driven research loop for `swiftsec research`.

Sonnet drives a tool-use loop over PUBLIC surface (docs, OSS code, CVEs).
No live exploitation. No decompilation. Output: hypothesis ledger +
research playbook in markdown. The user executes any actual PoCs manually.

Pattern mirrors agent/redteam_agent.py but stripped to research-only:
  - No probe budget (only iteration cap)
  - No plateau detection (Claude calls mark_done explicitly)
  - All tools route through agent/research_tools.dispatch_tool

Usage:
    agent = ResearchAgent(target="Burp Suite Pro", focus="project file format",
                          roe=loaded_roe, max_iterations=20)
    result = await agent.run()
    print(result["markdown"])
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .research_tools import TOOL_SCHEMAS, dispatch_tool
from .researcher_persona import build_researcher_system_prompt


_CLIENT = None


def _get_client():
    global _CLIENT
    if _CLIENT is None:
        import anthropic
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            return None
        _CLIENT = anthropic.Anthropic(api_key=api_key)
    return _CLIENT


# Centralized model id — keep in sync with config/settings.py:35
_SONNET_MODEL = "claude-sonnet-4-6"


class ResearchAgent:
    def __init__(
        self,
        target: str,
        focus: str,
        roe,
        max_iterations: int = 20,
        engagement_dir: Path | None = None,
        dry_run: bool = False,
    ) -> None:
        self.target = target
        self.focus = focus
        self.roe = roe
        self.max_iterations = int(max_iterations)
        self.engagement_dir = engagement_dir or (Path.cwd() / "research-out")
        self.dry_run = bool(dry_run)

        self.hypotheses: list[dict] = []
        self.message_history: list[dict] = []
        self.iteration: int = 0
        self.done: bool = False
        self.verdict: str = "incomplete"
        self.summary: str = ""

        self.system_prompt = build_researcher_system_prompt(
            target=target, focus=focus, max_iterations=max_iterations,
        )

    async def run(self) -> dict[str, Any]:
        self.engagement_dir.mkdir(parents=True, exist_ok=True)
        log_path = self.engagement_dir / "research_log.jsonl"
        client = _get_client()
        if client is None and not self.dry_run:
            return {
                "status": "error",
                "error": "ANTHROPIC_API_KEY not set",
                "hypotheses": [],
                "markdown_path": None,
            }

        self.message_history.append({
            "role": "user",
            "content": (
                f"Begin research session.\n"
                f"Target: {self.target}\n"
                f"Focus: {self.focus}\n\n"
                "Start by calling get_focus, then map the documented attack surface "
                "via fetch_url against vendor docs."
            ),
        })

        if self.dry_run:
            return self._dry_run_summary()

        while not self.done and self.iteration < self.max_iterations:
            response = await self._call_sonnet(client)
            if response is None:
                break

            await self._log_iteration(log_path, response)

            if getattr(response, "stop_reason", None) == "end_turn":
                break

            tool_calls = [b for b in response.content if getattr(b, "type", "") == "tool_use"]
            if not tool_calls:
                break

            tool_results = []
            for tc in tool_calls:
                result = dispatch_tool(tc.name, tc.input, self)
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tc.id,
                    "content": json.dumps(result, default=str),
                })

            self.message_history.append({"role": "assistant", "content": response.content})
            self.message_history.append({"role": "user", "content": tool_results})
            self.iteration += 1

        md_path = self._write_markdown()
        return {
            "status": "ok",
            "target": self.target,
            "focus": self.focus,
            "iterations": self.iteration,
            "hypotheses": self.hypotheses,
            "verdict": self.verdict,
            "summary": self.summary,
            "markdown_path": str(md_path),
            "log_path": str(log_path),
        }

    async def _call_sonnet(self, client):
        loop = asyncio.get_event_loop()

        def _call():
            return client.messages.create(
                model=_SONNET_MODEL,
                max_tokens=4096,
                system=self.system_prompt,
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
                if getattr(b, "type", "") == "tool_use"
            ],
            "hypothesis_count": len(self.hypotheses),
        }
        with log_path.open("a") as f:
            f.write(json.dumps(entry, default=str) + "\n")

    def _dry_run_summary(self) -> dict[str, Any]:
        """Return what the agent would do without making any API calls."""
        return {
            "status": "dry-run",
            "target": self.target,
            "focus": self.focus,
            "max_iterations": self.max_iterations,
            "system_prompt_preview": self.system_prompt[:600],
            "available_tools": [t["name"] for t in TOOL_SCHEMAS],
            "note": "ANTHROPIC_API_KEY would be required for live run. No tokens spent.",
        }

    def _write_markdown(self) -> Path:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        md_path = self.engagement_dir / f"research_session_{ts}.md"
        lines: list[str] = []
        lines.append(f"# Research session — {self.target}")
        lines.append("")
        lines.append(f"- **Focus:** {self.focus}")
        lines.append(f"- **Iterations used:** {self.iteration} / {self.max_iterations}")
        lines.append(f"- **Verdict:** {self.verdict}")
        lines.append(f"- **Engagement:** {getattr(self.roe, 'engagement_id', 'n/a')}")
        lines.append("")
        if self.summary:
            lines.append("## Summary")
            lines.append("")
            lines.append(self.summary)
            lines.append("")
        lines.append(f"## Hypotheses ({len(self.hypotheses)})")
        lines.append("")
        if not self.hypotheses:
            lines.append("_No hypotheses produced._")
        else:
            high_conf = [h for h in self.hypotheses if h.get("confidence", 0) >= 0.7]
            low_conf = [h for h in self.hypotheses if h.get("confidence", 0) < 0.7]
            lines.append(f"### Playbook ({len(high_conf)} hypotheses, confidence >= 0.7)")
            lines.append("")
            for i, h in enumerate(high_conf, 1):
                lines.append(f"#### {i}. [{h.get('category', 'uncategorized')}] (conf={h.get('confidence'):.2f})")
                lines.append("")
                lines.append(h.get("text", ""))
                lines.append("")
                lines.append("**Evidence:**")
                for u in h.get("evidence_urls", []):
                    lines.append(f"- {u}")
                lines.append("")
            if low_conf:
                lines.append(f"### Logged (low-confidence, {len(low_conf)} entries)")
                lines.append("")
                for h in low_conf:
                    lines.append(f"- ({h.get('confidence'):.2f}) {h.get('text')}")
                lines.append("")
        md_path.write_text("\n".join(lines), encoding="utf-8")
        return md_path
