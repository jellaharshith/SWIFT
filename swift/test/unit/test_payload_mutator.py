"""Unit tests for LLMPayloadMutator."""
from __future__ import annotations

import json
import pytest
from unittest.mock import MagicMock, patch


def test_mutate_bulk_returns_variants():
    from agent.payload_mutator import LLMPayloadMutator
    mutator = LLMPayloadMutator()
    variants = ["' OR 1=1--", "' OR '1'='1", "1 UNION SELECT null--"]
    mock_resp = MagicMock()
    mock_resp.content = [MagicMock(text=json.dumps(variants))]
    with patch.object(mutator, "_get_client") as mock_get:
        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_resp
        mock_get.return_value = mock_client
        import asyncio
        result = asyncio.get_event_loop().run_until_complete(
            mutator.mutate_bulk(["' OR 1=1--"])
        )
    assert isinstance(result, list)
    assert len(result) > 0


def test_mutate_bulk_no_client_returns_original():
    from agent.payload_mutator import LLMPayloadMutator
    mutator = LLMPayloadMutator()
    with patch.object(mutator, "_get_client", return_value=None):
        import asyncio
        original = ["payload1", "payload2"]
        result = asyncio.get_event_loop().run_until_complete(mutator.mutate_bulk(original))
    assert result == original


def test_mutate_waf_bypass_no_client_returns_original():
    from agent.payload_mutator import LLMPayloadMutator
    mutator = LLMPayloadMutator()
    with patch.object(mutator, "_get_client", return_value=None):
        import asyncio
        result = asyncio.get_event_loop().run_until_complete(
            mutator.mutate_waf_bypass("<script>alert(1)</script>", ["nginx", "modsecurity"])
        )
    assert result == ["<script>alert(1)</script>"]
