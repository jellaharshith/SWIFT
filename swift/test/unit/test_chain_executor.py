"""Unit tests for agent/chain_executor.py."""
from __future__ import annotations

import asyncio
import sys
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from agent.chain_executor import execute_chain, ChainExecutionResult, ALLOWED_TARGETS, _is_target_allowed


# ── Fixtures ──────────────────────────────────────────────────────────────────

@dataclass
class _FakeROE:
    allow_chain_execution: bool = False
    simulate_only: bool = True
    allowed_techniques: set = field(default_factory=lambda: {"osint", "active_scan"})


_SAMPLE_CHAIN = {
    "chain_id": "CHAIN-001",
    "entry_point": "http://localhost:3000/api/Users",
    "attack_steps": [
        {
            "step": 1,
            "description": "Enumerate users",
            "entry_point": "http://localhost:3000/api/Users",
            "method": "GET",
            "payload": None,
        },
        {
            "step": 2,
            "description": "Fetch user by ID",
            "entry_point": "http://localhost:3000/api/Users/1",
            "method": "GET",
            "payload": None,
        },
    ],
}


# ── ROE gate tests ────────────────────────────────────────────────────────────

def test_roe_gate_blocks_when_flag_false(tmp_path):
    """Chain execution must be blocked when allow_chain_execution=False."""
    roe = _FakeROE(allow_chain_execution=False)
    result = asyncio.run(execute_chain(_SAMPLE_CHAIN, roe, out_dir=str(tmp_path)))
    assert result.validated is False
    assert result.steps_attempted == 0
    assert result.error is not None
    assert "allow_chain_execution" in result.error.lower() or "roe" in result.error.lower()


def test_roe_gate_blocks_default_roe():
    """Default ROE object (no allow_chain_execution attr) must deny execution."""
    roe = MagicMock(spec=[])  # no attributes
    result = asyncio.run(execute_chain(_SAMPLE_CHAIN, roe, out_dir="/tmp"))
    assert result.validated is False
    assert result.steps_attempted == 0


# ── Target allowlist tests ────────────────────────────────────────────────────

@pytest.mark.parametrize("target,expected", [
    ("http://localhost:3000", True),
    ("http://127.0.0.1:3000", True),
    ("http://juice-shop.local", True),
    ("http://dvwa.local/login", True),
    ("http://example.com", False),
    ("http://prod.mycompany.com", False),
    ("http://10.0.0.1", False),
])
def test_target_allowlist(target, expected):
    assert _is_target_allowed(target) == expected


def test_target_not_in_allowlist_blocks_execution(tmp_path):
    """Execution must be blocked for targets not in ALLOWED_TARGETS."""
    roe = _FakeROE(allow_chain_execution=True, simulate_only=False)
    chain = {
        "chain_id": "CHAIN-BAD",
        "entry_point": "http://example.com/api",
        "attack_steps": [{"step": 1, "description": "test", "entry_point": "http://example.com/api", "method": "GET"}],
    }
    result = asyncio.run(execute_chain(chain, roe, out_dir=str(tmp_path)))
    assert result.validated is False
    assert result.steps_attempted == 0
    assert result.error is not None


# ── Successful execution test ─────────────────────────────────────────────────

def test_successful_chain_execution(tmp_path):
    """Chain with all-200 responses should return validated=True."""
    roe = _FakeROE(allow_chain_execution=True, simulate_only=False)

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = '{"status":"ok"}'

    with patch("agent.chain_executor._HTTPX_AVAILABLE", True):
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.request = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value = mock_client

            result = asyncio.run(execute_chain(_SAMPLE_CHAIN, roe, out_dir=str(tmp_path)))

    assert result.steps_attempted == 2
    assert result.steps_succeeded == 2
    assert result.validated is True
    assert result.error is None


# ── Failed step test ──────────────────────────────────────────────────────────

def test_failed_step_sets_validated_false(tmp_path):
    """A single step returning 403 must set validated=False."""
    roe = _FakeROE(allow_chain_execution=True, simulate_only=False)

    responses = [
        MagicMock(status_code=200, text='{"ok":true}'),
        MagicMock(status_code=403, text='{"error":"forbidden"}'),
    ]
    call_count = {"n": 0}

    async def _mock_request(*args, **kwargs):
        idx = call_count["n"]
        call_count["n"] += 1
        return responses[idx] if idx < len(responses) else responses[-1]

    with patch("agent.chain_executor._HTTPX_AVAILABLE", True):
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.request = _mock_request
            mock_client_cls.return_value = mock_client

            result = asyncio.run(execute_chain(_SAMPLE_CHAIN, roe, out_dir=str(tmp_path)))

    assert result.steps_attempted == 2
    assert result.steps_succeeded == 1
    assert result.validated is False


# ── httpx unavailable test ────────────────────────────────────────────────────

def test_httpx_unavailable_returns_error(tmp_path):
    """When httpx is not installed, execution should return an error result."""
    roe = _FakeROE(allow_chain_execution=True, simulate_only=False)

    with patch("agent.chain_executor._HTTPX_AVAILABLE", False):
        result = asyncio.run(execute_chain(_SAMPLE_CHAIN, roe, out_dir=str(tmp_path)))

    assert result.validated is False
    assert result.steps_attempted == 0
    assert result.error is not None
    assert "httpx" in result.error.lower()
