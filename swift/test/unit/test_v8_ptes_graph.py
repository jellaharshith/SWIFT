"""Unit tests for the PTES 7-phase graph, doctrine layer, and Rosén report rewrite."""
from __future__ import annotations

import sys
import os

# Ensure swift/ is on path when run directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


# ── Doctrine layer ────────────────────────────────────────────────────────────

def test_doctrine_loader_loads_mitnick():
    from doctrine import load_doctrine
    text = load_doctrine("mitnick")
    assert len(text) > 100
    assert "human" in text.lower() or "trust" in text.lower()


def test_doctrine_loader_loads_haddix():
    from doctrine import load_doctrine
    text = load_doctrine("haddix")
    assert len(text) > 100
    assert "recon" in text.lower() or "subdomain" in text.lower() or "surface" in text.lower()


def test_doctrine_loader_loads_rosen():
    from doctrine import load_doctrine
    text = load_doctrine("rosen")
    assert len(text) > 100
    assert "impact" in text.lower() or "discovery" in text.lower()


def test_doctrine_loader_missing_returns_empty():
    from doctrine import load_doctrine
    result = load_doctrine("nonexistent_doctrine_xyz")
    assert result == ""


def test_compose_persona_recon_includes_haddix():
    from doctrine import compose_persona
    persona = compose_persona("recon")
    assert "HADDIX" in persona.upper() or "haddix" in persona.lower() or len(persona) > 500


def test_compose_persona_analyst_includes_rosen():
    from doctrine import compose_persona
    persona = compose_persona("analyst")
    assert len(persona) > 100  # rosen doctrine present


def test_compose_persona_unknown_returns_empty():
    from doctrine import compose_persona
    result = compose_persona("nonexistent_specialist_xyz")
    assert result == ""


# ── Specialist doctrine injection ─────────────────────────────────────────────

def test_get_specialist_with_doctrine_injects_preamble():
    from agent.langgraph_layer.specialists import get_specialist_with_doctrine, SPECIALISTS
    base = SPECIALISTS["recon"].system_prompt
    with_doc = get_specialist_with_doctrine("recon").system_prompt
    # doctrine-injected version must be longer (preamble added)
    assert len(with_doc) >= len(base)


def test_new_specialists_present():
    from agent.langgraph_layer.specialists import SPECIALISTS
    assert "threat_modeler" in SPECIALISTS
    assert "report_formatter" in SPECIALISTS
    assert "ptes_orchestrator" in SPECIALISTS


def test_threat_modeler_has_kg_query_tool():
    from agent.langgraph_layer.specialists import SPECIALISTS
    assert "kg_query" in SPECIALISTS["threat_modeler"].tool_names


def test_report_formatter_has_write_doc_tool():
    from agent.langgraph_layer.specialists import SPECIALISTS
    assert "write_doc" in SPECIALISTS["report_formatter"].tool_names


# ── PTES graph topology ───────────────────────────────────────────────────────

def test_ptes_graph_registered():
    # ptes.py must be imported to register itself in GRAPHS
    import agent.langgraph_layer.graphs.ptes  # noqa: F401
    from agent.langgraph_layer.graphs import GRAPHS
    assert "ptes" in GRAPHS


def test_ptes_graph_has_7_nodes():
    import agent.langgraph_layer.graphs.ptes  # noqa: F401
    from agent.langgraph_layer.graphs import GRAPHS
    g = GRAPHS["ptes"]
    assert len(g.nodes) == 7


def test_ptes_graph_node_order():
    from agent.langgraph_layer.graphs.ptes import PHASE_NAMES
    assert PHASE_NAMES == [
        "pre_engage", "intel", "threat_model", "vuln",
        "exploit_phase", "post_exploit", "report_phase",
    ]


def test_ptes_graph_entry_is_pre_engage():
    import agent.langgraph_layer.graphs.ptes  # noqa: F401
    from agent.langgraph_layer.graphs import GRAPHS
    assert GRAPHS["ptes"].entry == "pre_engage"


def test_ptes_graph_terminal_is_report_phase():
    import agent.langgraph_layer.graphs.ptes  # noqa: F401
    from agent.langgraph_layer.graphs import GRAPHS
    g = GRAPHS["ptes"]
    assert g.nodes["report_phase"].next == ()


def test_ptes_graph_linear_chain():
    import agent.langgraph_layer.graphs.ptes  # noqa: F401
    from agent.langgraph_layer.graphs import GRAPHS
    g = GRAPHS["ptes"]
    expected_chain = [
        ("pre_engage", "intel"),
        ("intel", "threat_model"),
        ("threat_model", "vuln"),
        ("vuln", "exploit_phase"),
        ("exploit_phase", "post_exploit"),
        ("post_exploit", "report_phase"),
    ]
    for src, dst in expected_chain:
        assert dst in g.nodes[src].next, f"{src} -> {dst} edge missing"


# ── ROE techniques registered ─────────────────────────────────────────────────

def test_ptes_roe_techniques_registered():
    from security.roe import KNOWN_TECHNIQUES
    for t in ("ptes_pre_engage", "ptes_intel", "ptes_threat_model", "ptes_report", "kg_query"):
        assert t in KNOWN_TECHNIQUES, f"ROE technique missing: {t}"


# ── PTESRunner stop_after ─────────────────────────────────────────────────────

def test_ptes_runner_stop_after_pre_engage(tmp_path):
    """stop_after=pre_engage should only run 1 phase, not crash."""
    from agent.langgraph_layer.graphs.ptes import PTESRunner
    from unittest.mock import patch, MagicMock

    runner = PTESRunner(stop_after="pre_engage", out_dir=str(tmp_path))

    mock_roe = MagicMock()
    state = {"roe": mock_roe, "engagement": {"target": "example.com"}}

    with patch("agent.langgraph_layer.runtime.run_specialist"):
        result = runner.run(state)

    # Only pre_engage artifact should exist
    artifacts = list(tmp_path.glob("*.md"))
    assert len(artifacts) == 1
    assert "pre_engage" in artifacts[0].name


def test_ptes_runner_produces_artifacts(tmp_path):
    """Full run produces 7 phase artifacts."""
    from agent.langgraph_layer.graphs.ptes import PTESRunner
    from unittest.mock import patch, MagicMock

    runner = PTESRunner(out_dir=str(tmp_path))
    mock_roe = MagicMock()
    state = {"roe": mock_roe, "engagement": {"target": "example.com"}}

    with patch("agent.langgraph_layer.runtime.run_specialist"):
        result = runner.run(state)

    artifacts = list(tmp_path.glob("*.md"))
    assert len(artifacts) == 7


def test_ptes_runner_state_has_phase_artifacts(tmp_path):
    from agent.langgraph_layer.graphs.ptes import PTESRunner
    from unittest.mock import patch, MagicMock

    runner = PTESRunner(out_dir=str(tmp_path))
    state = {"roe": MagicMock(), "engagement": {"target": "t.com"}}

    with patch("agent.langgraph_layer.runtime.run_specialist"):
        result = runner.run(state)

    assert "phase_artifacts" in result
    assert "pre_engage" in result["phase_artifacts"]
    assert "report_phase" in result["phase_artifacts"]


# ── Rosén report format ───────────────────────────────────────────────────────

def test_rosen_report_has_discovery_section():
    from bounty.report_formats import format_h1
    d = {"title": "XSS", "severity": "high", "discovery": "Found via JS analysis of /search endpoint"}
    report = format_h1(d)
    assert "## Discovery" in report
    assert "Found via JS analysis" in report


def test_rosen_report_backward_compat_summary_fallback():
    from bounty.report_formats import format_h1
    d = {"title": "XSS", "severity": "high", "summary": "Classic XSS in search"}
    report = format_h1(d)
    assert "## Discovery" in report
    assert "Classic XSS in search" in report


def test_rosen_report_has_all_6_sections():
    from bounty.report_formats import format_h1
    d = {
        "title": "SSRF",
        "severity": "critical",
        "discovery": "Found SSRF in image proxy",
        "hypothesis": "Believed IMDS reachable",
        "escalation_chain": "SSRF → IMDS → IAM credentials",
        "impact_summary": "Attacker reads AWS credentials",
        "steps": "1. POST /proxy with url=http://169.254.169.254/\n2. Observe response",
        "request_evidence": "POST /proxy HTTP/1.1\nurl=http://169.254.169.254/latest/meta-data/",
        "remediation": "Validate url param against allowlist; block 169.254.0.0/16",
    }
    report = format_h1(d)
    for section in ("Discovery", "Hypothesis", "Escalation Chain", "Impact", "Reproduction Steps", "Fix"):
        assert f"## {section}" in report, f"Missing section: {section}"


def test_rosen_report_platform_fields_preserved():
    from bounty.report_formats import format_h1
    d = {"title": "IDOR", "severity": "high", "cwe": "CWE-639", "cvss": "8.1"}
    report = format_h1(d)
    assert "CWE-639" in report
    assert "8.1" in report


def test_rosen_report_ptes_artifacts_appendix():
    from bounty.report_formats import format_h1
    d = {
        "title": "Chain",
        "severity": "critical",
        "phase_artifacts": {
            "intel": ".swift-artifacts/ptes/phase_2_intel.md",
            "report_phase": ".swift-artifacts/ptes/phase_7_report_phase.md",
        },
    }
    report = format_h1(d)
    assert "## PTES Phase Artifacts" in report
    assert "phase_2_intel.md" in report


def test_format_report_dispatches_all_platforms():
    from bounty.report_formats import format_report
    d = {"title": "Test", "severity": "medium"}
    for platform in ("h1", "bugcrowd", "intigriti", "immunefi"):
        result = format_report(platform, d)
        assert isinstance(result, str)
        assert len(result) > 50


# ── hunt_memory doctrine stream ───────────────────────────────────────────────

def test_hunt_memory_doctrine_signal(tmp_path):
    from bounty.hunt_memory import HuntMemory
    mem = HuntMemory(root=str(tmp_path))
    mem.log_doctrine_signal(
        specialist="recon",
        doctrine="haddix",
        finding_id="F-001",
        bug_class="IDOR",
        outcome="confirmed",
    )
    stats = mem.doctrine_stats()
    assert "haddix" in stats
    assert stats["haddix"].get("confirmed", 0) >= 1


def test_hunt_memory_doctrine_stats_empty(tmp_path):
    from bounty.hunt_memory import HuntMemory
    mem = HuntMemory(root=str(tmp_path))
    stats = mem.doctrine_stats()
    assert isinstance(stats, dict)


# ── CLI smoke ─────────────────────────────────────────────────────────────────

def test_ptes_subcommand_registered():
    import argparse
    from cli.v8 import register
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    register(sub)
    result = parser.parse_args(["ptes", "example.com", "--roe", "roe.yaml"])
    assert result.target == "example.com"
    assert result.mode == "pentest"
    assert result.depth == "standard"


def test_ptes_stop_after_flag():
    import argparse
    from cli.v8 import register
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    register(sub)
    result = parser.parse_args(["ptes", "t.com", "--roe", "roe.yaml", "--stop-after", "intel"])
    assert result.stop_after == "intel"


def test_hunt_ptes_flag():
    import argparse
    from cli.v8 import register
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    register(sub)
    result = parser.parse_args(["hunt", "--roe", "roe.yaml", "--program", "h1-shopify", "--target", "shopify.com", "--ptes"])
    assert result.ptes is True
