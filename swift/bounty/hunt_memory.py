"""Cross-engagement hunt memory.

Three append-only JSONL stores under ``~/.swift/hunt-memory`` (override with
``SWIFT_HUNT_MEMORY_DIR``):

* ``audit.jsonl``    -- every tool call and finding for replay
* ``patterns.jsonl`` -- distilled "pattern -> result" lessons across targets
* ``journal.jsonl``  -- operator notes

Each file rotates at 10 MB to ``<name>.<N>.jsonl``. Reads return iterators
across the current file + rotations newest-first so cross-target lookups
do not lose old context.

All read/write paths gate through ROE ``hunt_memory_read`` /
``hunt_memory_write`` -- enforced by the caller (typically the langgraph
runtime or :mod:`bounty.validator`).
"""
from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

_ROTATE_BYTES = 10 * 1024 * 1024


def _default_root() -> Path:
    env = os.getenv("SWIFT_HUNT_MEMORY_DIR")
    if env:
        return Path(env)
    return Path.home() / ".swift" / "hunt-memory"


class _RotatingJsonl:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def append(self, record: dict[str, Any]) -> None:
        record = {"ts": time.time(), **record}
        line = json.dumps(record, sort_keys=True, default=str) + "\n"
        with self._lock:
            self._rotate_if_needed(len(line))
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line)

    def _rotate_if_needed(self, incoming_bytes: int) -> None:
        if not self.path.exists():
            return
        if self.path.stat().st_size + incoming_bytes < _ROTATE_BYTES:
            return
        # find next free .N suffix
        n = 1
        while True:
            cand = self.path.with_suffix(f".{n}.jsonl")
            if not cand.exists():
                self.path.rename(cand)
                return
            n += 1

    def iter_records(self) -> Iterator[dict[str, Any]]:
        candidates: list[Path] = [self.path] if self.path.exists() else []
        n = 1
        while True:
            cand = self.path.with_suffix(f".{n}.jsonl")
            if not cand.exists():
                break
            candidates.append(cand)
            n += 1
        # newest first: current file, then highest-numbered rotation, ...
        for p in candidates[:1] + sorted(candidates[1:], reverse=True):
            with p.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue


class HuntMemory:
    def __init__(self, root: Path | str | None = None) -> None:
        self.root = Path(root) if root else _default_root()
        self.audit    = _RotatingJsonl(self.root / "audit.jsonl")
        self.patterns = _RotatingJsonl(self.root / "patterns.jsonl")
        self.journal  = _RotatingJsonl(self.root / "journal.jsonl")

    # -- writes -----------------------------------------------------------------

    def record_action(self, *, engagement: str, action: str, target: str, **meta: Any) -> None:
        self.audit.append({"engagement": engagement, "action": action, "target": target, **meta})

    def record_pattern(self, *, name: str, signal: str, outcome: str, **meta: Any) -> None:
        """A reusable lesson: 'when <signal>, <outcome>'."""
        self.patterns.append({"name": name, "signal": signal, "outcome": outcome, **meta})

    def journal_note(self, *, engagement: str, note: str, **meta: Any) -> None:
        self.journal.append({"engagement": engagement, "note": note, **meta})

    # -- reads ------------------------------------------------------------------

    def recent_actions(self, *, engagement: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for rec in self.audit.iter_records():
            if engagement and rec.get("engagement") != engagement:
                continue
            out.append(rec)
            if len(out) >= limit:
                break
        return out

    def search_patterns(self, *, contains: str | None = None) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for rec in self.patterns.iter_records():
            blob = json.dumps(rec)
            if contains and contains not in blob:
                continue
            out.append(rec)
        return out
