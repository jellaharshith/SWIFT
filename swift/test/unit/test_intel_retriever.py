"""Unit tests for IntelRetriever."""
from __future__ import annotations

import pytest
from unittest.mock import patch


def test_retriever_returns_empty_without_chromadb():
    from intel.query.retriever import IntelRetriever
    r = IntelRetriever()
    with patch.object(r, "_init", return_value=False):
        result = r.query("SQL injection")
    assert result == []


def test_query_for_target_empty_when_no_results():
    from intel.query.retriever import IntelRetriever
    r = IntelRetriever()
    with patch.object(r, "query", return_value=[]):
        output = r.query_for_target(["django"], ["sqli"], "https://example.com", budget_tokens=200)
    assert output == ""


def test_get_payloads_returns_list():
    from intel.query.retriever import IntelRetriever
    r = IntelRetriever()
    with patch.object(r, "query", return_value=[]):
        payloads = r.get_payloads("sqli", n=10)
    assert isinstance(payloads, list)


def test_query_for_target_respects_budget():
    from intel.query.retriever import IntelRetriever
    r = IntelRetriever()
    long_result = [{"content": "word " * 500, "metadata": {}} for _ in range(5)]
    with patch.object(r, "query", return_value=long_result):
        output = r.query_for_target(["node"], ["xss"], "https://example.com", budget_tokens=100)
    # Should be truncated
    assert len(output) < len("word " * 500 * 5)
