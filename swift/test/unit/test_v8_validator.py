"""v8.0 -- 7-question + 4-gate validator."""
from __future__ import annotations

from bounty.validator import Finding, Verdict, validate, validate_dict


def _good() -> Finding:
    return Finding(
        title="IDOR on /api/orders",
        target_url="https://example.com/api/orders/1",
        bug_class="idor",
        severity="high",
        has_request_response=True,
        request_evidence="GET /api/orders/1 HTTP/1.1\nHost: example.com\n\n",
        program_accepts_class=True,
        in_scope=True,
        impact_evidence_level="full",
    )


def test_pass():
    res = validate(_good())
    assert res.verdict is Verdict.PASS
    assert res.gates["scope"]
    assert res.gates["reproducible"]


def test_kill_q1_no_evidence():
    f = _good()
    f.has_request_response = False
    f.request_evidence = ""
    res = validate(f)
    assert res.verdict is Verdict.KILL and res.failed_question == 1


def test_kill_q3_out_of_scope():
    f = _good()
    f.in_scope = False
    res = validate(f)
    assert res.verdict is Verdict.KILL and res.failed_question == 3


def test_downgrade_q6_partial_impact():
    f = _good()
    f.impact_evidence_level = "partial"
    res = validate(f)
    assert res.verdict is Verdict.DOWNGRADE
    assert res.suggested_severity == "medium"


def test_q7_never_submit_kills_or_chains():
    f = _good()
    f.bug_class = "missing_security_headers"
    res = validate(f)
    assert res.verdict is Verdict.KILL

    f.chain_with = ["xss"]
    res2 = validate(f)
    assert res2.verdict is Verdict.CHAIN_REQUIRED


def test_validate_dict_accepts_extra_keys():
    payload = {"title": "x", "target_url": "u", "bug_class": "idor",
               "has_request_response": True, "request_evidence": "GET / HTTP/1.1",
               "impact_evidence_level": "full",
               "weird_extra_key": True}  # extra keys ignored, not crashed
    res = validate_dict(payload)
    assert res.verdict is Verdict.PASS
