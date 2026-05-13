from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class IntelDocument:
    doc_id: str
    source: str
    title: str
    content: str
    metadata: dict = field(default_factory=dict)
    content_hash: str = ""
    ingested_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    url: str = ""

    def __post_init__(self) -> None:
        if not self.content_hash:
            self.content_hash = hashlib.sha256(self.content.encode()).hexdigest()
