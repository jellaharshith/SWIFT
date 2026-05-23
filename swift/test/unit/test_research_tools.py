"""Tests for agent.research_tools — focus on safety guardrails.

The research agent's value is bounded by its guardrails:
  - fetch_url must reject non-whitelisted hosts (no SSRF surface)
  - run_sandbox_test must reject non-whitelisted scenario_ids (no arbitrary code path)
  - note_hypothesis must require evidence URLs (no "I think" without citation)
"""
from __future__ import annotations

from agent.research_tools import (
    _ALLOWED_FETCH_HOSTS,
    _SANDBOX_SCENARIOS,
    dispatch_tool,
)


class _FakeAgent:
    """Minimal stand-in for ResearchAgent — only attributes the tools touch."""
    def __init__(self) -> None:
        self.target = "Burp Suite Pro"
        self.focus = "project file untrusted mode"
        self.max_iterations = 10
        self.iteration = 0
        self.hypotheses: list[dict] = []
        self.done = False
        self.verdict = "incomplete"
        self.summary = ""


def test_fetch_url_rejects_non_whitelisted_host() -> None:
    agent = _FakeAgent()
    result = dispatch_tool("fetch_url", {"url": "https://evil.example.com/payload"}, agent)
    assert "error" in result
    assert result["error"] == "host not whitelisted"
    assert result["host"] == "evil.example.com"


def test_fetch_url_rejects_http_scheme() -> None:
    agent = _FakeAgent()
    result = dispatch_tool("fetch_url", {"url": "http://portswigger.net/burp"}, agent)
    assert "error" in result
    assert result["error"] == "only https permitted"


def test_run_sandbox_test_rejects_invented_scenario() -> None:
    agent = _FakeAgent()
    result = dispatch_tool("run_sandbox_test",
                           {"scenario_id": "decompile_jar"}, agent)
    assert "error" in result
    assert result["error"] == "scenario not whitelisted"
    assert "decompile_jar" not in result["whitelisted"]


def test_run_sandbox_test_accepts_whitelisted_scenario() -> None:
    agent = _FakeAgent()
    scenario = next(iter(_SANDBOX_SCENARIOS))
    result = dispatch_tool("run_sandbox_test", {"scenario_id": scenario}, agent)
    assert result.get("scenario_id") == scenario
    assert result.get("status") == "stub"


def test_note_hypothesis_requires_evidence() -> None:
    agent = _FakeAgent()
    result = dispatch_tool("note_hypothesis",
                           {"text": "guess", "confidence": 0.5, "evidence_urls": []}, agent)
    assert "error" in result
    assert "evidence_url" in result["error"]


def test_note_hypothesis_records_when_evidenced() -> None:
    agent = _FakeAgent()
    result = dispatch_tool("note_hypothesis", {
        "text": "Project file length-prefix parser may overflow",
        "confidence": 0.8,
        "evidence_urls": ["https://portswigger.net/burp/documentation/desktop/projects"],
        "category": "parser_crash",
    }, agent)
    assert result.get("recorded") is True
    assert len(agent.hypotheses) == 1
    assert agent.hypotheses[0]["category"] == "parser_crash"


def test_mark_done_sets_agent_state() -> None:
    agent = _FakeAgent()
    result = dispatch_tool("mark_done",
                           {"verdict": "worth_pursuing", "summary": "3 leads"}, agent)
    assert result.get("acknowledged") is True
    assert agent.done is True
    assert agent.verdict == "worth_pursuing"
    assert agent.summary == "3 leads"


def test_unknown_tool_rejected() -> None:
    agent = _FakeAgent()
    result = dispatch_tool("rm_rf_slash", {"path": "/"}, agent)
    assert "error" in result
    assert "unknown tool" in result["error"]


def test_fetch_host_whitelist_contains_portswigger_and_nvd() -> None:
    assert "portswigger.net" in _ALLOWED_FETCH_HOSTS
    assert "nvd.nist.gov" in _ALLOWED_FETCH_HOSTS
    assert "github.com" in _ALLOWED_FETCH_HOSTS
    # Sanity: no random hosts crept in
    assert "evil.example.com" not in _ALLOWED_FETCH_HOSTS


def test_sandbox_whitelist_does_not_contain_decompile() -> None:
    for sid in _SANDBOX_SCENARIOS:
        assert "decompile" not in sid.lower()
        assert "exploit" not in sid.lower()
        assert "rce" not in sid.lower()
