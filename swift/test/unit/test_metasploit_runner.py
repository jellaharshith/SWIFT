"""Unit tests for MetasploitRunner."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.fixture
def mock_roe():
    roe = MagicMock()
    roe.allowed_techniques = {"exploit"}
    roe.simulate_only = True
    return roe


@pytest.mark.asyncio
async def test_simulate_only_returns_simulated_result(mock_roe):
    from kali.metasploit_runner import MetasploitRunner
    runner = MetasploitRunner(mock_roe, simulate_only=True)
    result = await runner.run_module("exploit/multi/handler", {"LHOST": "127.0.0.1"}, mock_roe)
    assert result.get("simulated") is True
    assert "exploit/multi/handler" in result.get("module", "")
    assert "simulate_only" in result.get("result", "").lower()


@pytest.mark.asyncio
async def test_roe_blocks_when_exploit_not_allowed():
    from kali.metasploit_runner import MetasploitRunner
    roe = MagicMock()
    roe.allowed_techniques = {"osint"}
    roe.simulate_only = False
    runner = MetasploitRunner(roe, simulate_only=False)
    with pytest.raises((SystemExit, Exception)):
        await runner.run_module("exploit/multi/handler", {}, roe)


@pytest.mark.asyncio
async def test_pymetasploit3_not_installed_returns_error(mock_roe):
    from kali.metasploit_runner import MetasploitRunner
    roe = MagicMock()
    roe.allowed_techniques = {"exploit"}
    roe.simulate_only = False
    runner = MetasploitRunner(roe, simulate_only=False)
    import asyncio
    result = await runner._live_run("exploit/multi/handler", {})
    assert "error" in result or "simulated" in str(result)
