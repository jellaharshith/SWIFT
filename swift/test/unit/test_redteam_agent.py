"""Tests for RedTeamAgent agentic loop."""
import asyncio
import datetime
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from agent.redteam_agent import RedTeamAgent
from agent.agent_prompts import AgentBudget, AgentHypothesis, EngagementResult, AGENT_SYSTEM_PROMPT
from security.roe import ROE


def _make_roe(techniques=None):
    return ROE(
        engagement_id="test",
        authorized_targets=["*"],
        allowed_techniques=set(techniques or ["active_scan", "oob_ssrf"]),
        window_start=datetime.datetime(2025, 1, 1),
        window_end=datetime.datetime(2035, 1, 1),
        contact="test",
    )


def test_agent_system_prompt_content():
    assert "OSCP" in AGENT_SYSTEM_PROMPT
    assert "CISSP" in AGENT_SYSTEM_PROMPT
    assert "get_attack_surface" in AGENT_SYSTEM_PROMPT
    assert "update_hypothesis" in AGENT_SYSTEM_PROMPT


def test_agent_budget_defaults():
    b = AgentBudget()
    assert b.max_probe_calls == 50
    assert b.max_sonnet_calls == 20
    assert not b.is_exhausted()


def test_agent_budget_exhausted():
    b = AgentBudget(max_probe_calls=2, max_sonnet_calls=2)
    b.probe_calls_used = 2
    assert b.is_exhausted()


def test_agent_budget_time_exhausted():
    import time
    b = AgentBudget(max_time_seconds=0)
    b.started_at = time.time() - 1
    assert b.is_exhausted()


async def test_agent_exits_on_end_turn(tmp_path):
    """Agent exits cleanly when Sonnet returns stop_reason=end_turn."""
    roe = _make_roe()
    budget = AgentBudget(max_probe_calls=5, max_sonnet_calls=5)
    agent = RedTeamAgent(target="http://target.com", roe=roe, budget=budget,
                         engagement_dir=tmp_path)

    mock_resp = MagicMock()
    mock_resp.stop_reason = "end_turn"
    mock_resp.content = []

    with patch.object(agent, "_call_sonnet", new=AsyncMock(return_value=mock_resp)):
        result = await agent.run()

    assert isinstance(result, EngagementResult)
    assert result.iterations == 0
    assert (tmp_path / "agent_log.jsonl").exists()


async def test_agent_dispatches_tool_calls(tmp_path):
    """Agent dispatches tool calls and appends results to history."""
    roe = _make_roe()
    budget = AgentBudget(max_probe_calls=5, max_sonnet_calls=5)
    agent = RedTeamAgent(target="http://target.com", roe=roe, budget=budget,
                         engagement_dir=tmp_path)

    tool_use_block = MagicMock()
    tool_use_block.type = "tool_use"
    tool_use_block.name = "update_hypothesis"
    tool_use_block.id = "tu_1"
    tool_use_block.input = {"hypothesis": "test", "confidence": 0.8, "evidence": "x"}

    end_resp = MagicMock()
    end_resp.stop_reason = "end_turn"
    end_resp.content = []

    tool_resp = MagicMock()
    tool_resp.stop_reason = "tool_use"
    tool_resp.content = [tool_use_block]

    responses = [tool_resp, end_resp]
    call_count = [0]
    async def mock_call():
        resp = responses[min(call_count[0], len(responses) - 1)]
        call_count[0] += 1
        return resp

    with patch.object(agent, "_call_sonnet", new=mock_call):
        result = await agent.run()

    assert len(agent.hypotheses) == 1
    assert agent.hypotheses[0].text == "test"


def test_plateau_detected_same_probe_repeated(tmp_path):
    """Plateau detected when same probe called >5x in a window of 8."""
    roe = _make_roe()
    agent = RedTeamAgent(target="http://t.com", roe=roe, engagement_dir=tmp_path)
    # 6 of the same probe in an 8-element window triggers plateau (v > 5)
    agent._probe_history = [("sqli", "http://t.com")] * 6 + [("xss", "a"), ("ssrf", "b")]
    assert agent._plateau_detected() is True


def test_plateau_not_detected_varied_probes(tmp_path):
    roe = _make_roe()
    agent = RedTeamAgent(target="http://t.com", roe=roe, engagement_dir=tmp_path)
    agent._probe_history = [
        ("sqli", "a"), ("xss", "b"), ("ssrf", "c"), ("idor", "d"),
        ("oauth", "e"), ("jwt", "f"), ("csrf", "g"), ("lfi", "h"),
    ]
    assert agent._plateau_detected() is False


def test_compress_history_long(tmp_path):
    roe = _make_roe()
    agent = RedTeamAgent(target="http://t.com", roe=roe, engagement_dir=tmp_path)
    # Build 25 turns
    agent.message_history = [{"role": "user", "content": "start"}]
    for i in range(24):
        role = "assistant" if i % 2 == 0 else "user"
        agent.message_history.append({"role": role, "content": f"turn {i}"})
    agent._compress_history_if_long()
    assert len(agent.message_history) <= 8  # compressed
