"""Intel version tracker — manifest snapshots for rollback."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

VERSIONS_DIR = Path(os.path.expanduser("~/.swift/intel/versions"))


class IntelVersionTracker:
    def __init__(self, versions_dir: Path = VERSIONS_DIR) -> None:
        self.versions_dir = versions_dir
        self.versions_dir.mkdir(parents=True, exist_ok=True)

    def snapshot(self, doc_count: int = 0) -> str:
        version_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        manifest = {
            "version_id": version_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "doc_count": doc_count,
        }
        (self.versions_dir / f"{version_id}.json").write_text(json.dumps(manifest, indent=2))
        return version_id

    def list_versions(self) -> list[dict]:
        versions = []
        for f in sorted(self.versions_dir.glob("*.json"), reverse=True):
            try:
                versions.append(json.loads(f.read_text()))
            except Exception:
                continue
        return versions

    def rollback(self, version_id: str) -> None:
        target = self.versions_dir / f"{version_id}.json"
        if not target.exists():
            raise FileNotFoundError(f"Version {version_id} not found")
        manifest = json.loads(target.read_text())
        manifest["rolled_back_at"] = datetime.now(timezone.utc).isoformat()
        (self.versions_dir / "current.json").write_text(json.dumps(manifest, indent=2))
