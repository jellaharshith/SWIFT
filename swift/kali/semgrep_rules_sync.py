"""Semgrep community rules sync — git clone/pull semgrep/semgrep-rules."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from log.audit import log_step

REPO_URL = "https://github.com/semgrep/semgrep-rules.git"
DEFAULT_RULES_DIR = Path(os.path.expanduser("~/.swift/intel/semgrep-rules"))
DEFAULT_LANGUAGES = ["python", "javascript", "java", "go", "ruby", "php"]


class SemgrepRulesSync:
    """Clone or pull semgrep-rules and provide per-language rule paths."""

    def __init__(self, rules_dir: str | Path = DEFAULT_RULES_DIR) -> None:
        self.rules_dir = Path(rules_dir)

    async def sync(self, languages: list[str] | None = None) -> dict:
        langs = languages or DEFAULT_LANGUAGES
        self._sync_repo()
        rule_counts: dict[str, int] = {}
        for lang in langs:
            lang_dir = self.rules_dir / lang
            rule_counts[lang] = sum(1 for _ in lang_dir.rglob("*.yaml")) if lang_dir.exists() else 0
        log_step("semgrep.sync.done", languages=langs, counts=rule_counts)
        return {"rules_dir": str(self.rules_dir), "languages": langs, "rule_counts": rule_counts}

    def get_rules_path(self, language: str) -> str:
        return str(self.rules_dir / language)

    def _sync_repo(self) -> None:
        try:
            import git  # type: ignore
            if self.rules_dir.exists():
                git.Repo(str(self.rules_dir)).remotes.origin.pull()
            else:
                self.rules_dir.parent.mkdir(parents=True, exist_ok=True)
                git.Repo.clone_from(REPO_URL, str(self.rules_dir), depth=1)
            return
        except ImportError:
            pass
        # subprocess fallback
        if self.rules_dir.exists():
            subprocess.run(
                ["git", "-C", str(self.rules_dir), "pull", "--ff-only"],
                timeout=120, check=False, capture_output=True,
            )
        else:
            self.rules_dir.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["git", "clone", "--depth=1", REPO_URL, str(self.rules_dir)],
                timeout=300, check=True, capture_output=True,
            )
