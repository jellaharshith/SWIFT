"""Integration tests for the unified scan pipeline (code + Kali + CVE)."""
from __future__ import annotations

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent.correlator import Correlator
from agent.models import (
    ExploitChain,
    MergedFinding,
    ScanResult,
    UnifiedScanResult,
    Vulnerability,
)
from config.consent import check_consent


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_vulnerability(
    id: str = "SWIFT-001",
    vuln_type: str = "sql_injection",
    severity: str = "HIGH",
    cwe_id: str = "CWE-89",
    file_path: str = "auth/views.py",
) -> Vulnerability:
    return Vulnerability(
        id=id,
        file_path=file_path,
        line_number=42,
        vuln_type=vuln_type,
        description="SQL injection via f-string",
        confidence=0.7,
        severity=severity,
        code_snippet="query = f'SELECT * FROM users WHERE id={uid}'",
        cwe_id=cwe_id,
        status="REVIEW_REQUIRED",
    )


def _make_scan_result(vulns: list[Vulnerability] | None = None) -> ScanResult:
    return ScanResult(
        scan_id="SCAN-001",
        repo_path="/tmp/repo",
        files_scanned=3,
        vulnerabilities=vulns or [],
        duration_seconds=1.0,
        total_cost_usd=0.01,
        timestamp="2026-04-27T00:00:00Z",
    )


def _make_kali_result(tool: str = "sqlmap", target: str = "http://example.com/login") -> dict:
    return {
        "target": target,
        "scan_time": "2026-04-27T00:00:00Z",
        "tools_run": [tool],
        "results": [
            {
                "tool": tool,
                "target": target,
                "output": "sql injection detected",
                "technique_id": "T1190",
                "technique": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
            }
        ],
        "mitre_techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}
        ],
    }


# ---------------------------------------------------------------------------
# Correlator unit tests
# ---------------------------------------------------------------------------

class TestCorrelator:
    def test_merge_code_only(self):
        vuln = _make_vulnerability()
        code_result = _make_scan_result([vuln])
        merged, code_only, kali_only = Correlator().merge(code_result, None, [])
        assert len(merged) == 0
        assert len(code_only) == 1
        assert len(kali_only) == 0

    def test_merge_kali_only(self):
        kali_result = _make_kali_result()
        merged, code_only, kali_only = Correlator().merge(None, kali_result, [])
        assert len(merged) == 0
        assert len(code_only) == 0
        assert len(kali_only) == 1

    def test_merge_matches_sqli_vuln_with_sqlmap(self):
        vuln = _make_vulnerability(vuln_type="sql_injection", file_path="auth/login.py")
        code_result = _make_scan_result([vuln])
        kali_result = _make_kali_result(tool="sqlmap", target="http://example.com/login")
        merged, code_only, kali_only = Correlator().merge(code_result, kali_result, [])
        assert len(merged) == 1
        assert "code" in merged[0].sources
        assert "kali" in merged[0].sources
        assert len(code_only) == 0
        assert len(kali_only) == 0

    def test_merge_severity_not_blanket_escalated(self):
        vuln = _make_vulnerability(severity="LOW")
        code_result = _make_scan_result([vuln])
        kali_result = _make_kali_result(tool="sqlmap")
        merged, _, _ = Correlator().merge(code_result, kali_result, [])
        if merged:
            # Severity should start at the code finding's level (LOW), not forced HIGH
            assert merged[0].severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
            # Should NOT be unconditionally HIGH — must stay LOW unless CVE escalated
            assert merged[0].severity == "LOW"

    def test_merge_cve_enrichment_cwe_match(self):
        from feeds.live_cve import CVEEntry

        vuln = _make_vulnerability(cwe_id="CWE-89")
        code_result = _make_scan_result([vuln])
        kali_result = _make_kali_result(tool="sqlmap")

        cve = CVEEntry(
            cve_id="CVE-2024-1234",
            description="SQL injection vulnerability",
            cvss_score=9.0,
            severity="CRITICAL",
            cwe_ids=["CWE-89"],
            published="2024-01-01T00:00:00Z",
            source="NVD",
            cisa_known_exploited=True,
        )
        merged, _, _ = Correlator().merge(code_result, kali_result, [cve])
        assert len(merged) == 1
        assert len(merged[0].cve_matches) >= 1
        assert merged[0].actively_exploited is True
        assert merged[0].severity == "CRITICAL"

    def test_merge_id_format(self):
        vuln = _make_vulnerability()
        code_result = _make_scan_result([vuln])
        kali_result = _make_kali_result(tool="sqlmap")
        merged, _, _ = Correlator().merge(code_result, kali_result, [])
        if merged:
            assert merged[0].id.startswith("MERGED-")
            assert len(merged[0].id) == len("MERGED-") + 8

    def test_merge_requires_none_for_both_returns_empty(self):
        merged, code_only, kali_only = Correlator().merge(None, None, [])
        assert merged == []
        assert code_only == []
        assert kali_only == []


# ---------------------------------------------------------------------------
# Unified orchestrator tests
# ---------------------------------------------------------------------------

class TestUnifiedOrchestrator:
    def test_raises_if_no_targets(self):
        from agent.unified_orchestrator import unified_scan
        with pytest.raises(ValueError, match="At least one"):
            asyncio.run(unified_scan(repo_path=None, kali_target=None))

    def test_code_only_scan(self):
        from agent.unified_orchestrator import unified_scan

        mock_code_result = _make_scan_result([_make_vulnerability()])

        with (
            patch("agent.unified_orchestrator._run_code_scan", new_callable=AsyncMock, return_value=mock_code_result),
            patch("agent.unified_orchestrator._run_kali_scan", new_callable=AsyncMock),
            patch("agent.unified_orchestrator.LiveCVEFeed") as mock_feed_cls,
        ):
            mock_feed = MagicMock()
            mock_feed.poll_forever = AsyncMock(side_effect=asyncio.CancelledError)
            mock_feed.close = AsyncMock()
            mock_feed_cls.return_value = mock_feed

            result = asyncio.run(unified_scan(repo_path="/tmp/repo"))

        assert isinstance(result, UnifiedScanResult)
        assert result.repo_path == "/tmp/repo"
        assert result.kali_target is None

    def test_kali_only_scan(self):
        from agent.unified_orchestrator import unified_scan

        mock_kali = _make_kali_result()

        with (
            patch("agent.unified_orchestrator._run_code_scan", new_callable=AsyncMock),
            patch("agent.unified_orchestrator._run_kali_scan", new_callable=AsyncMock, return_value=mock_kali),
            patch("agent.unified_orchestrator.LiveCVEFeed") as mock_feed_cls,
        ):
            mock_feed = MagicMock()
            mock_feed.poll_forever = AsyncMock(side_effect=asyncio.CancelledError)
            mock_feed.close = AsyncMock()
            mock_feed_cls.return_value = mock_feed

            result = asyncio.run(unified_scan(kali_target="192.168.1.1", skip_kali_build=True))

        assert isinstance(result, UnifiedScanResult)
        assert result.kali_target == "192.168.1.1"
        assert result.repo_path is None

    def test_both_sources_produces_merged_findings(self):
        from agent.unified_orchestrator import unified_scan

        mock_code = _make_scan_result([_make_vulnerability(vuln_type="sql_injection", file_path="auth/login.py")])
        mock_kali = _make_kali_result(tool="sqlmap", target="http://example.com/login")

        with (
            patch("agent.unified_orchestrator._run_code_scan", new_callable=AsyncMock, return_value=mock_code),
            patch("agent.unified_orchestrator._run_kali_scan", new_callable=AsyncMock, return_value=mock_kali),
            patch("agent.unified_orchestrator.LiveCVEFeed") as mock_feed_cls,
        ):
            mock_feed = MagicMock()
            mock_feed.poll_forever = AsyncMock(side_effect=asyncio.CancelledError)
            mock_feed.close = AsyncMock()
            mock_feed_cls.return_value = mock_feed

            result = asyncio.run(unified_scan(
                repo_path="/tmp/repo",
                kali_target="http://example.com",
                skip_kali_build=True,
            ))

        assert isinstance(result, UnifiedScanResult)
        assert len(result.merged_findings) == 1
        assert result.merged_findings[0].sources == ["code", "kali"]

    def test_scan_id_and_duration_populated(self):
        from agent.unified_orchestrator import unified_scan

        mock_code = _make_scan_result()

        with (
            patch("agent.unified_orchestrator._run_code_scan", new_callable=AsyncMock, return_value=mock_code),
            patch("agent.unified_orchestrator.LiveCVEFeed") as mock_feed_cls,
        ):
            mock_feed = MagicMock()
            mock_feed.poll_forever = AsyncMock(side_effect=asyncio.CancelledError)
            mock_feed.close = AsyncMock()
            mock_feed_cls.return_value = mock_feed

            result = asyncio.run(unified_scan(repo_path="/tmp/repo"))

        assert result.scan_id
        assert len(result.scan_id) == 12
        assert result.duration >= 0
        assert result.started_at


# ---------------------------------------------------------------------------
# Consent tests
# ---------------------------------------------------------------------------

class TestConsentCheckConsent:
    def test_returns_false_when_file_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr("config.consent.CONSENT_FILE", tmp_path / "consent.json")
        assert check_consent() is False

    def test_returns_true_when_accepted(self, tmp_path, monkeypatch):
        import json
        f = tmp_path / "consent.json"
        f.write_text(json.dumps({"accepted": True}))
        monkeypatch.setattr("config.consent.CONSENT_FILE", f)
        assert check_consent() is True
