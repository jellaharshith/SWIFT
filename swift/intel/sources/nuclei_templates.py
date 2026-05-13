"""Nuclei templates source — git clone/pull projectdiscovery/nuclei-templates."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from intel.sources.models import IntelDocument

REPO_URL = "https://github.com/projectdiscovery/nuclei-templates.git"


class NucleiTemplateSource:
    name = "nuclei_templates"

    def __init__(self) -> None:
        self.clone_dir = Path(os.path.expanduser("~/.swift/intel/nuclei-templates"))

    async def fetch(self) -> list[IntelDocument]:
        try:
            self._sync_repo()
        except Exception:
            return []
        docs = []
        try:
            import yaml
            for yaml_file in self.clone_dir.rglob("*.yaml"):
                try:
                    data = yaml.safe_load(yaml_file.read_text(encoding="utf-8", errors="replace"))
                    if not isinstance(data, dict):
                        continue
                    info = data.get("info", {})
                    template_id = data.get("id", yaml_file.stem)
                    name = info.get("name", template_id)
                    desc = info.get("description", "")
                    severity = info.get("severity", "unknown")
                    tags = info.get("tags", "")
                    content = f"Nuclei Template: {template_id}\nName: {name}\nSeverity: {severity}\nTags: {tags}\n\n{desc}"
                    docs.append(IntelDocument(
                        doc_id=f"nuclei_{template_id}",
                        source=self.name,
                        title=f"{name} ({severity})",
                        content=content[:2000],
                        metadata={"template_id": template_id, "severity": severity, "tags": str(tags)},
                    ))
                except Exception:
                    continue
        except Exception:
            pass
        return docs

    def _sync_repo(self) -> None:
        if self.clone_dir.exists():
            subprocess.run(
                ["git", "-C", str(self.clone_dir), "pull", "--ff-only"],
                timeout=120, check=False, capture_output=True,
            )
        else:
            self.clone_dir.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["git", "clone", "--depth=1", REPO_URL, str(self.clone_dir)],
                timeout=300, check=True, capture_output=True,
            )
