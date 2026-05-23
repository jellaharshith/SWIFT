"""v8.0 -- ROE KNOWN_TECHNIQUES regression."""
from __future__ import annotations

from security.roe import KNOWN_TECHNIQUES

V8_TECHNIQUES = {
    "tmux_interactive", "vuln_pipeline", "engagement_planning",
    "web3_audit", "auth_chain",
    "hunt_memory_read", "hunt_memory_write",
    "langgraph_subagent",
}


def test_all_v8_techniques_registered():
    missing = V8_TECHNIQUES - set(KNOWN_TECHNIQUES)
    assert not missing, f"v8 techniques missing from KNOWN_TECHNIQUES: {missing}"


def test_v7_techniques_preserved():
    """Regression: do not delete existing techniques while adding v8 ones."""
    for tech in ("osint", "active_scan", "exploit", "post_exploit",
                 "research", "kali", "probe"):
        assert tech in KNOWN_TECHNIQUES
