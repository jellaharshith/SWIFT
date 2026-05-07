import asyncio
from unittest.mock import patch
from agent.agent_pool import AgentPool, CodeAgent, NetworkAgent, WebAgent, CVEAgent
from agent.models import UnifiedScanResult


def test_code_agent_emits_label():
    labels = []
    agent = CodeAgent()
    asyncio.run(agent.run("/tmp/repo", lambda msg: labels.append(msg)))
    assert any("[CodeAgent]" in l for l in labels)


def test_network_agent_emits_label():
    labels = []
    with patch("agent.agent_pool.KaliRunner") as MockRunner:
        MockRunner.return_value.run_scan.return_value = {"tools": []}
        agent = NetworkAgent()
        asyncio.run(agent.run("example.com", lambda msg: labels.append(msg)))
    assert any("[NetworkAgent]" in l for l in labels)


def test_web_agent_emits_label():
    labels = []
    with patch("agent.agent_pool.KaliRunner") as MockRunner:
        MockRunner.return_value.run_scan.return_value = {"tools": []}
        agent = WebAgent()
        asyncio.run(agent.run("http://example.com", lambda msg: labels.append(msg)))
    assert any("[WebAgent]" in l for l in labels)


def test_cve_agent_emits_label():
    labels = []
    with patch("agent.agent_pool.LiveCVEFeed") as MockFeed:
        async def fake_poll(callback):
            pass
        MockFeed.return_value.poll_forever.side_effect = fake_poll
        agent = CVEAgent()
        asyncio.run(agent.run(0.01, lambda msg: labels.append(msg)))
    assert any("[CVEAgent]" in l for l in labels)


def test_agent_pool_returns_unified_scan_result():
    with (
        patch("agent.agent_pool.KaliRunner") as MockRunner,
        patch("agent.agent_pool.Correlator") as MockCorrelator,
    ):
        MockRunner.return_value.run_scan.return_value = {"tools": []}
        # merge returns (merged, code_only, kali_only) tuple
        MockCorrelator.return_value.merge.return_value = ([], [], [])

        pool = AgentPool()
        result = asyncio.run(pool.run_all("/tmp/repo", "example.com", lambda msg: None))
    assert isinstance(result, UnifiedScanResult)
    assert result.repo_path == "/tmp/repo"
    assert result.kali_target == "example.com"
