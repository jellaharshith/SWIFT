import asyncio, json
from pathlib import Path
import pytest
from audit.immutable_log import HashChainLogger, LogEntry, ChainVerificationResult

@pytest.mark.asyncio
async def test_hash_chain_deterministic(tmp_path: Path):
    log = HashChainLogger(tmp_path / "audit.jsonl", engagement_id="eng-1")
    h1 = await log.log("probe_executed", {"probe": "oob_ssrf"})
    h2 = await log.log("finding_recorded", {"id": "f-1"})
    res = log.verify_chain(tmp_path / "audit.jsonl")
    assert res.valid
    assert res.entries_checked == 2
    assert h1 != h2

@pytest.mark.asyncio
async def test_tamper_detected(tmp_path: Path):
    log = HashChainLogger(tmp_path / "audit.jsonl", engagement_id="eng-2")
    await log.log("a", {"x": 1})
    await log.log("b", {"x": 2})
    p = tmp_path / "audit.jsonl"
    lines = p.read_text().splitlines()
    obj = json.loads(lines[0])
    obj["data"]["x"] = 99
    lines[0] = json.dumps(obj, sort_keys=True)
    p.write_text("\n".join(lines) + "\n")
    res = log.verify_chain(p)
    assert not res.valid
    assert res.first_tampered_entry == 0

@pytest.mark.asyncio
async def test_prev_hash_chain(tmp_path: Path):
    log = HashChainLogger(tmp_path / "audit.jsonl", engagement_id="eng-3")
    h1 = await log.log("start", {"phase": 0})
    h2 = await log.log("end", {"phase": 1})
    p = tmp_path / "audit.jsonl"
    lines = p.read_text().splitlines()
    entry2 = json.loads(lines[1])
    assert entry2["prev_hash"] == h1

@pytest.mark.asyncio
async def test_redaction_credit_card(tmp_path: Path):
    log = HashChainLogger(tmp_path / "audit.jsonl", engagement_id="eng-4")
    await log.log("probe", {"cc": "4111 1111 1111 1111", "safe": "value"})
    p = tmp_path / "audit.jsonl"
    content = p.read_text()
    assert "4111" not in content
    assert "[CC-REDACTED]" in content

@pytest.mark.asyncio
async def test_redaction_bearer_token(tmp_path: Path):
    log = HashChainLogger(tmp_path / "audit.jsonl", engagement_id="eng-5")
    await log.log("auth", {"header": "Bearer eyJhbGciOiJSUzI1NiJ9.abc"})
    content = (tmp_path / "audit.jsonl").read_text()
    assert "eyJhbGci" not in content
    assert "Bearer [REDACTED]" in content

@pytest.mark.asyncio
async def test_empty_log_verify(tmp_path: Path):
    log = HashChainLogger(tmp_path / "audit.jsonl", engagement_id="empty")
    await log.log("only_entry", {"x": 1})
    res = log.verify_chain(tmp_path / "audit.jsonl")
    assert res.valid
    assert res.entries_checked == 1

def test_logentry_hash_deterministic():
    e = LogEntry(seq=0, timestamp="2025-01-01T00:00:00+00:00",
                 engagement_id="x", event_type="test",
                 operator="abc", data={"k": "v"}, prev_hash="GENESIS")
    h1 = e.compute_hash()
    h2 = e.compute_hash()
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex

def test_genesis_first_entry(tmp_path: Path):
    import asyncio
    log = HashChainLogger(tmp_path / "audit.jsonl", engagement_id="gen")
    asyncio.run(log.log("first", {}))
    p = tmp_path / "audit.jsonl"
    entry = json.loads(p.read_text().splitlines()[0])
    assert entry["prev_hash"] == "GENESIS"
