"""Unit tests for ConfidenceCalibrator."""
from __future__ import annotations

import pytest
from sdk.base import Finding, Severity, VulnType


def _make(confidence=0.90, oob_confirmed=False, request_evidence=None, response_evidence=None):
    return Finding(
        module="test",
        vuln_type=VulnType.XSS,
        severity=Severity.HIGH,
        title="Test finding",
        description="desc",
        target_url="https://example.com",
        confidence=confidence,
        oob_confirmed=oob_confirmed,
        request_evidence=request_evidence,
        response_evidence=response_evidence,
    )


def test_keyword_only_downscaled():
    from agent.confidence_calibrator import ConfidenceCalibrator
    cal = ConfidenceCalibrator()
    f = _make(confidence=0.90, oob_confirmed=False)
    result = cal.calibrate(f)
    assert result.confidence < 0.90
    assert result.confidence >= 0.6  # floor


def test_oob_confirmed_high_scaled_up():
    from agent.confidence_calibrator import ConfidenceCalibrator
    cal = ConfidenceCalibrator()
    f = _make(confidence=0.92, oob_confirmed=True, request_evidence="req", response_evidence="resp")
    result = cal.calibrate(f)
    assert result.confidence >= 0.92


def test_capped_at_one():
    from agent.confidence_calibrator import ConfidenceCalibrator
    cal = ConfidenceCalibrator()
    f = _make(confidence=0.99, oob_confirmed=True, request_evidence="req")
    result = cal.calibrate(f)
    assert result.confidence <= 1.0


def test_floor_applied():
    from agent.confidence_calibrator import ConfidenceCalibrator
    cal = ConfidenceCalibrator()
    f = _make(confidence=0.40, oob_confirmed=False)
    result = cal.calibrate(f)
    assert result.confidence >= 0.6


def test_calibrate_batch():
    from agent.confidence_calibrator import ConfidenceCalibrator
    cal = ConfidenceCalibrator()
    findings = [_make(confidence=0.80 + i * 0.01) for i in range(5)]
    results = cal.calibrate_batch(findings)
    assert len(results) == len(findings)
    assert all(r.confidence >= 0.6 for r in results)
