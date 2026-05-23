"""v8.0 -- engagement workflow (quick path, no LLM)."""
from __future__ import annotations

import yaml

from engagement import engage_quick


def test_engage_quick_emits_three_artifacts(tmp_path):
    paths = engage_quick(
        engagement_id="E-TEST",
        targets=["example.com", "10.0.0.0/24"],
        contact="op@example.com",
        outdir=tmp_path,
    )
    for k in ("roe", "opplan", "conops"):
        assert paths[k].exists(), f"{k} not written"

    roe_doc = yaml.safe_load(paths["roe"].read_text(encoding="utf-8"))
    assert roe_doc["engagement_id"] == "E-TEST"
    assert "engagement_planning" in roe_doc["allowed_techniques"]

    op = paths["opplan"].read_text(encoding="utf-8")
    assert "OPPLAN -- E-TEST" in op

    co = paths["conops"].read_text(encoding="utf-8")
    assert "ConOps -- E-TEST" in co
