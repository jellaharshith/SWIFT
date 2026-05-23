"""Unit tests for MultiModelClient."""
from __future__ import annotations

import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.mark.asyncio
async def test_claude_success():
    from agent.multi_model import MultiModelClient
    client = MultiModelClient()
    with patch.object(client, "_call_claude", new_callable=AsyncMock) as mock_claude:
        mock_claude.return_value = "test response"
        result = await client.complete([{"role": "user", "content": "hello"}])
    assert result == "test response"


@pytest.mark.asyncio
async def test_fallback_to_openai_on_error():
    from agent.multi_model import MultiModelClient
    client = MultiModelClient()
    with patch.object(client, "_call_claude", new_callable=AsyncMock) as mock_claude, \
         patch.object(client, "_call_openai", new_callable=AsyncMock) as mock_openai:
        mock_claude.side_effect = Exception("Rate limit exceeded")
        mock_openai.return_value = "openai fallback"
        result = await client.complete([{"role": "user", "content": "hello"}])
    assert result == "openai fallback"


@pytest.mark.asyncio
async def test_all_providers_fail_raises():
    from agent.multi_model import MultiModelClient
    client = MultiModelClient(primary="claude", fallback_order=[])
    with patch.object(client, "_call_claude", new_callable=AsyncMock) as mock_claude:
        mock_claude.side_effect = RuntimeError("API down")
        with pytest.raises(RuntimeError):
            await client.complete([{"role": "user", "content": "hello"}])


def test_env_override_primary():
    with patch.dict(os.environ, {"SWIFT_AI_MODEL": "openai"}):
        from agent.multi_model import MultiModelClient
        client = MultiModelClient()
    assert client.primary == "openai"
