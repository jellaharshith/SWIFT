"""Tests for audit decorators and EngagementManifest."""
import json
from pathlib import Path

import pytest

import audit
from audit.decorators import audit_logged
from audit.manifest import EngagementManifest
from audit.immutable_log import HashChainLogger


class _FakeProbe:
    name = "fake_probe"

    @audit_logged("probe_executed")
    async def probe(self, target, session=None):
        return ["finding1", "finding2"]


class _ErrorProbe:
    name = "error_probe"

    @audit_logged("probe_executed")
    async def probe(self, target, session=None):
        raise ValueError("intentional error")


async def test_audit_logged_no_logger():
    audit._global_logger = None
    p = _FakeProbe()
    result = await p.probe("http://target.com")
    assert result == ["finding1", "finding2"]


async def test_audit_logged_with_logger(tmp_path: Path):
    logger = HashChainLogger(tmp_path / "audit.jsonl", engagement_id="dec-test")
    audit._global_logger = logger
    try:
        p = _FakeProbe()
        result = await p.probe("http://target.com")
        assert result == ["finding1", "finding2"]
        lines = (tmp_path / "audit.jsonl").read_text().splitlines()
        assert len(lines) == 2
        start = json.loads(lines[0])
        end = json.loads(lines[1])
        assert start["event_type"] == "probe_executed_start"
        assert end["event_type"] == "probe_executed_end"
        assert end["data"]["finding_count"] == 2
        assert "duration_ms" in end["data"]
    finally:
        audit._global_logger = None


async def test_audit_logged_error_logged(tmp_path: Path):
    logger = HashChainLogger(tmp_path / "audit.jsonl", engagement_id="err-test")
    audit._global_logger = logger
    try:
        p = _ErrorProbe()
        with pytest.raises(ValueError):
            await p.probe("http://target.com")
        lines = (tmp_path / "audit.jsonl").read_text().splitlines()
        assert len(lines) == 2
        error_entry = json.loads(lines[1])
        assert error_entry["event_type"] == "probe_executed_error"
        assert error_entry["data"]["error"] == "ValueError"
    finally:
        audit._global_logger = None


def test_manifest_signing_payload_deterministic():
    m = EngagementManifest(
        engagement_id="eng-1",
        operator_email_hash="abc",
        roe_file_hash="def",
        swift_version="6.0.0",
        timestamp="2025-01-01T00:00:00Z",
    )
    assert m.signing_payload() == m.signing_payload()
    parsed = json.loads(m.signing_payload())
    assert parsed["engagement_id"] == "eng-1"


def test_manifest_hmac_sign(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("SWIFT_GPG_KEY_ID", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-12345")
    m = EngagementManifest(
        engagement_id="eng-2",
        operator_email_hash="aaa",
        roe_file_hash="bbb",
        swift_version="6.0.0",
        timestamp="2025-01-01T00:00:00Z",
    )
    sig = m.sign(tmp_path / "manifest.json")
    assert sig.exists()
    assert sig.read_text().startswith("HMAC-SHA256:")


def test_manifest_from_roe_file(tmp_path: Path):
    import hashlib
    roe = tmp_path / "roe.yaml"
    roe.write_text("engagement_id: test\n")
    m = EngagementManifest.from_roe_file(
        roe_path=roe,
        engagement_id="eng-3",
        operator_email="ops@test.com",
        swift_version="6.0.0",
        timestamp="2025-01-01T00:00:00Z",
    )
    assert m.roe_file_hash == hashlib.sha256(roe.read_bytes()).hexdigest()
    assert len(m.operator_email_hash) == 64
