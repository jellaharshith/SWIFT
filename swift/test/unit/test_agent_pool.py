import asyncio
from unittest.mock import MagicMock, patch
from agent.agent_pool import AgentPool, CodeAgent, NetworkAgent, WebAgent, CVEAgent
from agent.models import UnifiedScanResult, ScanResult


def _make_scan_result():
    r = MagicMock(spec=ScanResult)
    r.vulnerabilities = []
    r.patches = []
    r.exploit_chains = []
    r.ranked_findings = []
    r.files_scanned = 3
    r.duration_seconds = 5.0
    r.scan_id = "TEST-001"
    r.repo_path = "/tmp/repo"
    r.total_cost_usd = 0.01
    r.timestamp = "2026-04-27T00:00:00Z"
    r.status = "complete"
    r.signals_detected = 0
    r.chain_detection_error = None
    return r


def test_code_agent_emits_label():
    labels = []
    with patch("agent.agent_pool.scan_codebase", return_value=_make_scan_result()):
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


def test_agent_pool_returns_unified_scan_result():
    with (
        patch("agent.agent_pool.scan_codebase", return_value=_make_scan_result()),
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
