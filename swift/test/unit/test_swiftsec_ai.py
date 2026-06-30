"""Unit tests for the swiftsec_ai subsystem (no network).

Covers: CVE upsert + FTS5 search + KEV ordering + retrieve_context; backend
factory resolution (auto/ollama/anthropic); tool registry execution incl.
unknown-tool + scope_check-without-ROE; and that both backends translate the
same neutral tool schema correctly.
"""
from __future__ import annotations

import pytest

from swiftsec_ai import schedule
from swiftsec_ai.config import Settings, load_settings
from swiftsec_ai.cve import CVEStore, parse_nvd_cve
from swiftsec_ai.llm import (
    AnthropicBackend,
    OllamaBackend,
    build_backend,
    to_anthropic_tools,
    to_ollama_tools,
)
from swiftsec_ai.tools import build_registry

# --------------------------------------------------------------- fixtures

def _nvd_obj(cve_id, desc, score, severity, kev=False, vector="CVSS:3.1/AV:N"):
    obj = {
        "id": cve_id,
        "published": "2024-01-01T00:00:00.000",
        "lastModified": "2024-02-01T00:00:00.000",
        "descriptions": [{"lang": "en", "value": desc}],
        "metrics": {
            "cvssMetricV31": [
                {"cvssData": {"baseScore": score, "baseSeverity": severity, "vectorString": vector}}
            ]
        },
    }
    if kev:
        obj["cisaExploitAdd"] = "2024-03-01"
    return obj


@pytest.fixture
def store(tmp_path):
    s = CVEStore(tmp_path / "cve.db")
    yield s
    s.close()


# --------------------------------------------------------------- CVE parse

def test_parse_nvd_cve_extracts_fields():
    row = parse_nvd_cve(_nvd_obj("CVE-2024-0001", "OpenSSL heap overflow", 9.8, "CRITICAL", kev=True))
    assert row["id"] == "CVE-2024-0001"
    assert row["cvss"] == 9.8
    assert row["severity"] == "CRITICAL"
    assert row["kev"] == 1
    assert "OpenSSL" in row["description"]
    assert row["vector"].startswith("CVSS:3.1")


# --------------------------------------------------------------- CVE store

def test_upsert_and_count(store):
    n = store.upsert_cves([parse_nvd_cve(_nvd_obj("CVE-2024-1000", "nginx path traversal", 7.5, "HIGH"))])
    assert n == 1
    assert store.count() == 1
    # Upsert same id again → replace, not duplicate.
    store.upsert_cves([parse_nvd_cve(_nvd_obj("CVE-2024-1000", "nginx path traversal v2", 7.5, "HIGH"))])
    assert store.count() == 1


def test_fts_search_matches_keyword(store):
    store.upsert_cves([
        parse_nvd_cve(_nvd_obj("CVE-2024-2001", "Apache Struts remote code execution", 9.0, "CRITICAL")),
        parse_nvd_cve(_nvd_obj("CVE-2024-2002", "WordPress stored XSS in comments", 6.1, "MEDIUM")),
    ])
    hits = store.search("Struts")
    assert len(hits) == 1
    assert hits[0]["id"] == "CVE-2024-2001"


def test_kev_ordering_beats_higher_cvss(store):
    # Lower CVSS but KEV-flagged should sort ahead of a higher-CVSS non-KEV CVE.
    store.upsert_cves([
        parse_nvd_cve(_nvd_obj("CVE-2024-3001", "high score no kev", 9.8, "CRITICAL", kev=False)),
        parse_nvd_cve(_nvd_obj("CVE-2024-3002", "mid score but kev", 5.0, "MEDIUM", kev=True)),
    ])
    hits = store.search("score")
    assert [h["id"] for h in hits] == ["CVE-2024-3002", "CVE-2024-3001"]


def test_min_cvss_and_kev_filters(store):
    store.upsert_cves([
        parse_nvd_cve(_nvd_obj("CVE-2024-4001", "low bug", 3.0, "LOW", kev=False)),
        parse_nvd_cve(_nvd_obj("CVE-2024-4002", "high bug", 8.0, "HIGH", kev=True)),
    ])
    assert [h["id"] for h in store.search("bug", min_cvss=5.0)] == ["CVE-2024-4002"]
    assert [h["id"] for h in store.search("bug", kev_only=True)] == ["CVE-2024-4002"]


def test_retrieve_context_block(store):
    store.upsert_cves([parse_nvd_cve(_nvd_obj("CVE-2024-5001", "Log4j JNDI injection", 10.0, "CRITICAL", kev=True))])
    ctx = store.retrieve_context("Log4j")
    assert "CVE-2024-5001" in ctx
    assert "CISA-KEV" in ctx
    # Empty store / no match → empty string.
    assert store.retrieve_context("nonexistent-token-xyz") == ""


# --------------------------------------------------------------- backend factory

def test_backend_auto_resolves_to_ollama_without_key():
    assert build_backend(Settings(llm_backend="auto", anthropic_api_key="")).name == "ollama"


def test_backend_auto_resolves_to_anthropic_with_key():
    b = build_backend(Settings(llm_backend="auto", anthropic_api_key="sk-test"))
    assert b.name == "anthropic"
    assert isinstance(b, AnthropicBackend)


def test_backend_explicit_selection():
    assert isinstance(build_backend(Settings(llm_backend="ollama")), OllamaBackend)
    assert isinstance(build_backend(Settings(llm_backend="anthropic")), AnthropicBackend)


def test_load_settings_resolved_backend(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("SWIFTSEC_LLM_BACKEND", "auto")
    s = load_settings(env_file=None)
    assert s.resolved_backend == "ollama"


# --------------------------------------------------------------- tool registry

def test_registry_has_all_tools(store):
    reg = build_registry(store)
    assert set(reg.names()) == {
        "cve_lookup", "scope_check", "run_recon", "run_scan", "draft_h1_report",
        "ai_asm", "redteam",
    }


def test_unknown_tool_handled(store):
    reg = build_registry(store)
    out = reg.execute("does_not_exist", {})
    assert "unknown tool" in out


def test_scope_check_unverified_without_roe(store):
    reg = build_registry(store, roe=None)
    out = reg.execute("scope_check", {"target": "example.com"})
    assert "UNVERIFIED" in out


def test_scope_check_with_roe_callable(store):
    def roe(target, technique="active_scan"):
        return {"in_scope": target == "example.com", "reason": "test roe"}

    reg = build_registry(store, roe=roe)
    assert "IN SCOPE" in reg.execute("scope_check", {"target": "example.com"})
    assert "OUT OF SCOPE" in reg.execute("scope_check", {"target": "evil.com"})


def test_cve_lookup_tool_uses_store(store):
    store.upsert_cves([parse_nvd_cve(_nvd_obj("CVE-2024-6001", "Citrix ADC memory disclosure", 7.5, "HIGH"))])
    reg = build_registry(store)
    out = reg.execute("cve_lookup", {"query": "Citrix"})
    assert "CVE-2024-6001" in out


def test_tool_handler_never_crashes_on_bad_args(store):
    reg = build_registry(store)
    # Missing required field → graceful error string, not an exception.
    assert reg.execute("cve_lookup", {}).startswith("[error]")
    assert reg.execute("run_scan", {}).startswith("[error]")


def test_run_scan_refuses_without_scope(store):
    # No ROE wired → active scan must refuse, never call the scanner.
    called = {"hit": False}

    def scanner(target):
        called["hit"] = True
        return "should not run"

    reg = build_registry(store, roe=None, scanner=scanner)
    out = reg.execute("run_scan", {"target": "example.com"})
    assert "REFUSED" in out
    assert called["hit"] is False


# --------------------------------------------------------------- schema translation

def test_both_backends_translate_same_neutral_schema(store):
    neutral = build_registry(store).to_neutral_schema()
    names = {t["name"] for t in neutral}

    anth = to_anthropic_tools(neutral)
    olla = to_ollama_tools(neutral)

    assert {t["name"] for t in anth} == names
    assert {t["function"]["name"] for t in olla} == names

    # Same JSON-schema body surfaces under each backend's own key.
    for n, a, o in zip(neutral, anth, olla):
        assert a["input_schema"] == n["parameters"]
        assert o["type"] == "function"
        assert o["function"]["parameters"] == n["parameters"]
        assert o["function"]["description"] == n["description"]


# --------------------------------------------------------------- scheduler

def test_schedule_status_returns_dict():
    st = schedule.status()
    assert "scheduler" in st
    assert st["scheduler"] in {"launchd", "cron"}


def test_schedule_install_rejects_invalid_time():
    # Invalid time must fail fast, before any OS-level write.
    out = schedule.install(hour=99, minute=0)
    assert out["status"] == "error"
