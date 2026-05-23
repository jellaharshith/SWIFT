"""v8.0 -- bounty platform report formatters."""
from __future__ import annotations

import pytest

from bounty.report_formats import format_report


_SAMPLE = {
    "title": "IDOR on /api/orders",
    "target_url": "https://example.com/api/orders/1",
    "bug_class": "idor",
    "severity": "high",
    "cwe": "CWE-639",
    "cvss": "7.5",
    "summary": "Numeric IDs let attackers fetch other users' orders.",
    "steps": "1. Login as A\n2. GET /api/orders/2 (B's order)",
    "request_evidence": "GET /api/orders/2 HTTP/1.1\nHost: example.com",
    "impact_summary": "Cross-tenant data exposure across all 50k orders.",
    "remediation": "Authorize per-resource, not per-login.",
}


@pytest.mark.parametrize("platform", ["h1", "bugcrowd", "intigriti", "immunefi"])
def test_renders_for_each_platform(platform):
    md = format_report(platform, _SAMPLE)
    assert "# IDOR on /api/orders" in md
    assert "## Impact" in md or "## Vulnerability" in md  # immunefi uses different headers


def test_unknown_platform_raises():
    with pytest.raises(ValueError):
        format_report("foobar", _SAMPLE)  # type: ignore[arg-type]
