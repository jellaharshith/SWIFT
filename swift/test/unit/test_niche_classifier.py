"""Unit tests for agent.niche_classifier."""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from unittest.mock import MagicMock

import pytest

from agent.niche_classifier import NicheProfile, classify_niches, _parse_response, _build_prompt


@dataclass
class _FakeSurface:
    target: str = "example.com"
    tech_stack: list = field(default_factory=lambda: ["Django", "nginx", "PostgreSQL"])
    endpoints: list = field(default_factory=lambda: [
        "https://example.com/api/v1/users",
        "https://example.com/login",
    ])
    open_ports: list = field(default_factory=lambda: [80, 443])
    github_leaks: list = field(default_factory=list)
    subdomains: list = field(default_factory=lambda: ["api.example.com"])


def _make_client_mock(response_json: dict) -> MagicMock:
    client = MagicMock()
    msg = MagicMock()
    msg.content = [MagicMock(text=json.dumps(response_json))]
    client.messages.create.return_value = msg
    return client


def test_parse_valid_response():
    raw = json.dumps({
        "primary_niches": ["sqli", "idor", "api_security"],
        "focus_payloads": ["sqli", "idor"],
        "bounty_tier": "high",
        "reasoning": "Django ORM + API endpoints are classic sqli/idor targets.",
        "confidence": 0.8,
    })
    profile = _parse_response(raw)
    assert profile is not None
    assert "sqli" in profile.primary_niches
    assert profile.bounty_tier == "high"
    assert profile.confidence == 0.8


def test_parse_invalid_json_returns_none():
    profile = _parse_response("not valid json {{{")
    assert profile is None


def test_parse_empty_niches_returns_none():
    raw = json.dumps({
        "primary_niches": [],
        "focus_payloads": [],
        "bounty_tier": "medium",
        "reasoning": "",
        "confidence": 0.5,
    })
    profile = _parse_response(raw)
    assert profile is None


def test_parse_invalid_niche_names_filtered():
    raw = json.dumps({
        "primary_niches": ["sqli", "made_up_niche", "idor"],
        "focus_payloads": ["sqli"],
        "bounty_tier": "medium",
        "reasoning": "test",
        "confidence": 0.6,
    })
    profile = _parse_response(raw)
    assert profile is not None
    assert "made_up_niche" not in profile.primary_niches
    assert "sqli" in profile.primary_niches


def test_parse_invalid_tier_defaults_to_medium():
    raw = json.dumps({
        "primary_niches": ["xss"],
        "focus_payloads": ["xss"],
        "bounty_tier": "ultra_high",
        "reasoning": "",
        "confidence": 0.5,
    })
    profile = _parse_response(raw)
    assert profile is not None
    assert profile.bounty_tier == "medium"


def test_classify_niches_success():
    client = _make_client_mock({
        "primary_niches": ["sqli", "idor", "api_security"],
        "focus_payloads": ["sqli", "idor"],
        "bounty_tier": "high",
        "reasoning": "API-heavy Django app.",
        "confidence": 0.85,
    })
    surface = _FakeSurface()
    profile = asyncio.run(classify_niches("example.com", surface, client))
    assert "sqli" in profile.primary_niches
    assert profile.bounty_tier == "high"
    assert client.messages.create.called


def test_classify_niches_returns_default_on_api_error():
    client = MagicMock()
    client.messages.create.side_effect = RuntimeError("API timeout")
    surface = _FakeSurface()
    profile = asyncio.run(classify_niches("example.com", surface, client))
    assert isinstance(profile, NicheProfile)
    assert profile.confidence == 0.3
    assert "xss" in profile.primary_niches


def test_classify_niches_returns_default_when_no_client():
    surface = _FakeSurface()
    profile = asyncio.run(classify_niches("example.com", surface, None))
    assert isinstance(profile, NicheProfile)
    assert profile.reasoning == "default"


def test_classify_niches_returns_default_on_malformed_response():
    client = MagicMock()
    msg = MagicMock()
    msg.content = [MagicMock(text="garbage response")]
    client.messages.create.return_value = msg
    surface = _FakeSurface()
    profile = asyncio.run(classify_niches("example.com", surface, client))
    assert isinstance(profile, NicheProfile)
    assert profile.reasoning == "default"


def test_build_prompt_includes_persona_preamble():
    surface = _FakeSurface()
    prompt = _build_prompt("example.com", surface)
    assert "example.com" in prompt
    assert "Django" in prompt


def test_persona_preamble_in_system_prompt():
    from agent.niche_classifier import _SYSTEM_PROMPT
    from agent.pentester_persona import build_persona_preamble
    offensive = build_persona_preamble(passive=False)
    # The system prompt must contain the offensive preamble
    assert offensive[:40] in _SYSTEM_PROMPT
