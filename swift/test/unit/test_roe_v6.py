# test/unit/test_roe_v6.py
"""Tests for ROE v6.0 extensions: ROEViolation + new technique strings."""
import datetime

import pytest

from security.roe import ROE, ROEViolation, assert_technique_allowed


def test_roeviolation_exception_exists():
    with pytest.raises(ROEViolation):
        raise ROEViolation("denied")


def test_new_techniques_recognized():
    roe = ROE(
        engagement_id="t",
        authorized_targets=["x.com"],
        allowed_techniques={"oob_ssrf", "oauth_attack", "websocket_attack", "bizlogic"},
        window_start=datetime.datetime(2025, 1, 1),
        window_end=datetime.datetime(2030, 1, 1),
        contact="ops",
    )
    # Should not raise or exit
    for t in ("oob_ssrf", "oauth_attack", "websocket_attack", "bizlogic"):
        result = assert_technique_allowed(roe, t, raise_on_violation=True)
        assert result is True


def test_unknown_technique_denied_with_exception():
    roe = ROE(
        engagement_id="t",
        authorized_targets=["x"],
        allowed_techniques={"osint"},
        window_start=datetime.datetime(2025, 1, 1),
        window_end=datetime.datetime(2030, 1, 1),
        contact="ops",
    )
    with pytest.raises(ROEViolation):
        assert_technique_allowed(roe, "oob_ssrf", raise_on_violation=True)


def test_unknown_technique_exits_by_default():
    """Without raise_on_violation, should sys.exit(2)"""
    roe = ROE(
        engagement_id="t",
        authorized_targets=["x"],
        allowed_techniques={"osint"},
        window_start=datetime.datetime(2025, 1, 1),
        window_end=datetime.datetime(2030, 1, 1),
        contact="ops",
    )
    with pytest.raises(SystemExit) as exc_info:
        assert_technique_allowed(roe, "oob_ssrf", raise_on_violation=False)
    assert exc_info.value.code == 2


def test_roeviolation_message_preserved():
    """ROEViolation should carry the denial message."""
    roe = ROE(
        engagement_id="eng-001",
        authorized_targets=["example.com"],
        allowed_techniques={"osint"},
        window_start=datetime.datetime(2025, 1, 1),
        window_end=datetime.datetime(2030, 1, 1),
        contact="ops@example.com",
    )
    with pytest.raises(ROEViolation, match="agentic_loop"):
        assert_technique_allowed(roe, "agentic_loop", raise_on_violation=True)


def test_v60_chain_execution_technique():
    """chain_execution is a valid v6.0 technique."""
    roe = ROE(
        engagement_id="chain-test",
        authorized_targets=["target.io"],
        allowed_techniques={"chain_execution", "agentic_loop"},
        window_start=datetime.datetime(2025, 1, 1),
        window_end=datetime.datetime(2030, 1, 1),
        contact="red@team.io",
    )
    assert assert_technique_allowed(roe, "chain_execution", raise_on_violation=True) is True
    assert assert_technique_allowed(roe, "agentic_loop", raise_on_violation=True) is True


def test_existing_techniques_still_work():
    """Ensure pre-v6.0 technique strings remain valid."""
    roe = ROE(
        engagement_id="legacy-test",
        authorized_targets=["legacy.com"],
        allowed_techniques={"osint", "active_scan", "exploit", "post_exploit"},
        window_start=datetime.datetime(2025, 1, 1),
        window_end=datetime.datetime(2030, 1, 1),
        contact="ops",
    )
    for t in ("osint", "active_scan", "exploit", "post_exploit"):
        assert assert_technique_allowed(roe, t, raise_on_violation=True) is True
