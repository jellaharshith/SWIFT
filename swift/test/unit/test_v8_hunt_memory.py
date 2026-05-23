"""v8.0 -- hunt memory append/read + rotation."""
from __future__ import annotations

import bounty.hunt_memory as hm_mod
from bounty.hunt_memory import HuntMemory


def test_append_then_read(tmp_path):
    mem = HuntMemory(tmp_path)
    mem.record_action(engagement="E1", action="probe", target="x.com", note="hi")
    recs = mem.recent_actions(engagement="E1", limit=10)
    assert len(recs) == 1 and recs[0]["target"] == "x.com"


def test_other_engagement_filtered(tmp_path):
    mem = HuntMemory(tmp_path)
    mem.record_action(engagement="E1", action="a", target="x")
    mem.record_action(engagement="E2", action="a", target="y")
    assert {r["engagement"] for r in mem.recent_actions(engagement="E1")} == {"E1"}


def test_pattern_persists(tmp_path):
    mem = HuntMemory(tmp_path)
    mem.record_pattern(name="idor-on-uuid", signal="numeric guess on /api/orders/<id>",
                       outcome="200 with other-user data")
    hits = mem.search_patterns(contains="IDOR".lower())
    assert any("idor" in p["name"] for p in hits)


def test_rotation_at_threshold(tmp_path, monkeypatch):
    monkeypatch.setattr(hm_mod, "_ROTATE_BYTES", 256)  # tiny threshold for the test
    mem = HuntMemory(tmp_path)
    for i in range(200):
        mem.record_action(engagement="E", action=f"a{i}",
                          target="x", padding="z" * 32)
    rotations = list((tmp_path).glob("audit.*.jsonl"))
    assert rotations, "rotation did not produce numbered files"
