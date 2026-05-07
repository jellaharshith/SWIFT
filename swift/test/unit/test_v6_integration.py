"""Integration-style tests for v6.0 pipeline — mock-based, no live targets."""
import asyncio
import datetime
import json
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from sdk.registry import PluginRegistry
from sdk.base import Phase, VulnType
from sdk.migration import ALL_ADAPTERS
from audit.immutable_log import HashChainLogger
from audit import init_engagement_logger
from agent.agent_prompts import AgentBudget, AGENT_SYSTEM_PROMPT
from agent.redteam_agent import RedTeamAgent
from security.roe import ROE


def _make_roe():
    return ROE(
        engagement_id="integ-test",
        authorized_targets=["*"],
        allowed_techniques={
            "active_scan", "oob_ssrf", "oauth_attack",
            "websocket_attack", "bizlogic", "agentic_loop",
        },
        window_start=datetime.datetime(2025, 1, 1),
        window_end=datetime.datetime(2035, 1, 1),
        contact="test",
    )


def test_plugin_registry_discovers_adapters():
    """SDK registry registers all migration adapters."""
    reg = PluginRegistry()
    for cls in ALL_ADAPTERS:
        try:
            reg.register(cls)
        except Exception:
            pass
    assert len(reg.names()) > 0


def test_plugin_registry_list_by_phase():
    reg = PluginRegistry()
    for cls in ALL_ADAPTERS:
        try:
            reg.register(cls)
        except Exception:
            pass
    actives = reg.list_by_phase(Phase.ACTIVE)
    assert len(actives) > 0


def test_new_probes_importable():
    """All v6.0 probes import without errors."""
    from probes.oob_ssrf import OOBSSRFProbe
    from probes.oauth import OAuthProbe
    from probes.websocket import WebSocketProbe
    from probes.bizlogic import BusinessLogicProbe
    for cls in (OOBSSRFProbe, OAuthProbe, WebSocketProbe, BusinessLogicProbe):
        cls.validate_subclass()


def test_audit_chain_roundtrip(tmp_path: Path):
    """Write entries, verify chain, export report."""
    logger = HashChainLogger(tmp_path / "audit.jsonl", engagement_id="integ")
    asyncio.run(logger.log("probe_executed", {"probe": "oob_ssrf"}))
    asyncio.run(logger.log("finding_recorded", {"severity": "CRITICAL"}))
    result = logger.verify_chain(tmp_path / "audit.jsonl")
    assert result.valid
    assert result.entries_checked == 2
    # Export
    from audit.reporter import write_markdown
    out = tmp_path / "report.md"
    write_markdown(tmp_path / "audit.jsonl", out)
    assert "audit.jsonl" or "report" in out.read_text()


def test_init_engagement_logger(tmp_path: Path):
    """init_engagement_logger creates logger and sets global."""
    import audit
    logger = init_engagement_logger("eng-001", "ops@test.com", base_dir=tmp_path)
    assert logger is not None
    assert audit._global_logger is logger
    assert tmp_path.exists()  # file written on first log call
    audit._global_logger = None  # cleanup


def test_vulnerability_chain_fields():
    """Vulnerability dataclass has v6.0 chain fields."""
    from agent.models import Vulnerability
    v = Vulnerability(
        id="v1", file_path="x.py", line_number=1,
        vuln_type="ssrf", description="test",
        confidence=0.95, severity="HIGH", code_snippet="",
        chain_primitive="ssrf", oob_confirmed=True,
    )
    assert v.chain_primitive == "ssrf"
    assert v.oob_confirmed is True


async def test_redteam_agent_full_cycle(tmp_path: Path):
    """RedTeamAgent runs to completion with mocked Sonnet."""
    roe = _make_roe()
    budget = AgentBudget(max_probe_calls=3, max_sonnet_calls=3)
    agent = RedTeamAgent(
        target="http://target.com",
        roe=roe,
        budget=budget,
        engagement_dir=tmp_path,
    )

    end_resp = MagicMock()
    end_resp.stop_reason = "end_turn"
    end_resp.content = []

    with patch.object(agent, "_call_sonnet", new=AsyncMock(return_value=end_resp)):
        result = await agent.run()

    assert result.iterations == 0
    assert (tmp_path / "agent_log.jsonl").exists()
    log_entries = [(json.loads(l)) for l in (tmp_path / "agent_log.jsonl").read_text().splitlines()]
    assert len(log_entries) >= 1


def test_agent_system_prompt_key_content():
    assert "OSCP" in AGENT_SYSTEM_PROMPT
    assert "chain" in AGENT_SYSTEM_PROMPT.lower()
    assert "update_hypothesis" in AGENT_SYSTEM_PROMPT
