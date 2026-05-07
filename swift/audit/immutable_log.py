"""Immutable audit log with SHA-256 hash chain for tamper detection."""

from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import asyncio, hashlib, json, gzip, os, re, threading

GENESIS = "GENESIS"
_LOCK = threading.Lock()


@dataclass
class LogEntry:
    seq: int
    timestamp: str
    engagement_id: str
    event_type: str
    operator: str          # SHA-256 of operator email
    data: dict
    prev_hash: str
    entry_hash: str = ""

    def to_hashable(self) -> str:
        d = asdict(self)
        d.pop("entry_hash")
        return json.dumps(d, sort_keys=True, separators=(",", ":"))

    def compute_hash(self) -> str:
        return hashlib.sha256(self.to_hashable().encode()).hexdigest()


@dataclass
class ChainVerificationResult:
    valid: bool
    entries_checked: int
    first_tampered_entry: Optional[int] = None
    tampered_fields: list = field(default_factory=list)


class HashChainLogger:
    def __init__(self, log_path: Path, engagement_id: str, operator_email: str = ""):
        self.log_path = Path(log_path)
        self.engagement_id = engagement_id
        self.operator_hash = hashlib.sha256(operator_email.encode()).hexdigest() if operator_email else ""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._seq = self._init_seq()
        self._prev = self._init_prev()
        self._rotate_if_large()

    def _init_seq(self) -> int:
        if not self.log_path.exists():
            return 0
        with self.log_path.open() as f:
            return sum(1 for _ in f)

    def _init_prev(self) -> str:
        if not self.log_path.exists():
            return GENESIS
        last = ""
        with self.log_path.open() as f:
            for line in f:
                last = line
        if not last.strip():
            return GENESIS
        return json.loads(last).get("entry_hash", GENESIS)

    def _rotate_if_large(self, max_bytes: int = 10 * 1024 * 1024) -> None:
        if self.log_path.exists() and self.log_path.stat().st_size > max_bytes:
            i = 1
            while True:
                rot = self.log_path.parent / f"{self.log_path.stem}.jsonl.{i}.gz"
                if not rot.exists():
                    break
                i += 1
            with self.log_path.open("rb") as src, gzip.open(rot, "wb") as dst:
                dst.write(src.read())
            self.log_path.unlink()
            self._seq = 0
            self._prev = GENESIS

    @staticmethod
    def _redact(data: dict) -> dict:
        s = json.dumps(data)
        s = re.sub(r"\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}", "[CC-REDACTED]", s)
        s = re.sub(r'Bearer\s+[^\s"]+', "Bearer [REDACTED]", s, flags=re.IGNORECASE)
        for k in ("password", "passwd", "secret", "api_key", "token"):
            s = re.sub(
                rf'"{k}"\s*:\s*"[^"]*"',
                f'"{k}":"[REDACTED]"',
                s,
                flags=re.IGNORECASE,
            )
        return json.loads(s)

    async def log(self, event_type: str, data: dict) -> str:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._log_sync, event_type, data)

    def _log_sync(self, event_type: str, data: dict) -> str:
        with _LOCK:
            entry = LogEntry(
                seq=self._seq,
                timestamp=datetime.now(timezone.utc).isoformat(),
                engagement_id=self.engagement_id,
                event_type=event_type,
                operator=self.operator_hash,
                data=self._redact(data),
                prev_hash=self._prev,
            )
            entry.entry_hash = entry.compute_hash()
            with self.log_path.open("a") as f:
                f.write(json.dumps(asdict(entry), sort_keys=True) + "\n")
            self._seq += 1
            self._prev = entry.entry_hash
            return entry.entry_hash

    def verify_chain(self, log_path: Path) -> "ChainVerificationResult":
        prev = GENESIS
        count = 0
        with Path(log_path).open() as f:
            for i, line in enumerate(f):
                if not line.strip():
                    continue
                obj = json.loads(line)
                stored = obj.pop("entry_hash")
                e = LogEntry(**obj, entry_hash="")
                if e.compute_hash() != stored:
                    return ChainVerificationResult(False, i, first_tampered_entry=i,
                                                   tampered_fields=["entry_hash"])
                if e.prev_hash != prev:
                    return ChainVerificationResult(False, i, first_tampered_entry=i,
                                                   tampered_fields=["prev_hash"])
                prev = stored
                count = i + 1
        return ChainVerificationResult(True, count)

    def export_report(self, log_path: Path, output: Path) -> None:
        from .reporter import write_markdown
        write_markdown(log_path, output)
