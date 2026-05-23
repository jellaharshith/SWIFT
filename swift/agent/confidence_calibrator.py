"""Rule-based + optional ML confidence calibration for SWIFT findings."""
from __future__ import annotations

import copy
import os
from pathlib import Path

from sdk.base import Finding


class ConfidenceCalibrator:
    """Calibrate finding confidence — rules first, optional sklearn LogisticRegression."""

    CALIBRATOR_PATH = Path(os.path.expanduser("~/.swift/intel/calibrator.pkl"))

    def __init__(self) -> None:
        self._ml_model = None
        self._try_load_ml()

    def _try_load_ml(self) -> None:
        if not self.CALIBRATOR_PATH.exists():
            return
        try:
            import pickle
            with open(self.CALIBRATOR_PATH, "rb") as f:
                self._ml_model = pickle.load(f)  # noqa: S301
        except Exception:
            self._ml_model = None

    def _rule_based(self, finding: Finding) -> float:
        confidence = finding.confidence

        # keyword-only (no evidence, not OOB) → scale down
        if not finding.oob_confirmed and not finding.request_evidence and not finding.response_evidence:
            confidence *= 0.7

        # tool + AI agree (OOB confirmed AND already high) → scale up, cap at 1.0
        if finding.oob_confirmed and finding.confidence >= 0.9:
            confidence = min(confidence * 1.1, 1.0)

        # noise floor
        confidence = max(confidence, 0.6)
        return round(confidence, 4)

    def _ml_adjust(self, finding: Finding, base: float) -> float:
        if self._ml_model is None:
            return base
        try:
            sev_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
            features = [[
                sev_map.get(finding.severity.value, 2),
                abs(hash(finding.vuln_type.value)) % 100,
                1 if finding.request_evidence else 0,
                1 if finding.response_evidence else 0,
                1 if finding.oob_confirmed else 0,
            ]]
            proba = self._ml_model.predict_proba(features)[0][1]
            return round(base * 0.7 + proba * 0.3, 4)
        except Exception:
            return base

    def calibrate(self, finding: Finding) -> Finding:
        calibrated = copy.copy(finding)
        base = self._rule_based(finding)
        calibrated.confidence = self._ml_adjust(finding, base)
        return calibrated

    def calibrate_batch(self, findings: list[Finding]) -> list[Finding]:
        return [self.calibrate(f) for f in findings]
