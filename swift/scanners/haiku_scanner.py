"""Stage 1 scanner: Semgrep OWASP rules replace Claude Haiku API calls."""
from __future__ import annotations

import json
import subprocess
from typing import Any, Optional, Set


class HaikuTriageScanner:
    """Semgrep-based triage scanner.

    Replaces the former Claude Haiku API stage. No API key required.
    Runs semgrep with OWASP Top 10 + CWE Top 25 + secrets rulesets.
    Falls back to returning all regex-flagged lines if semgrep is not
    installed or times out.

    Args:
        client: Ignored (kept for import compatibility with orchestrator).
        model:  Ignored.
        max_retries: Ignored.
        mode:   Scan persona (informational only).
        semgrep_timeout: Per-file semgrep timeout in seconds (default 30).
    """

    _SEMGREP_CONFIGS = [
        "p/owasp-top-ten",
        "p/cwe-top-25",
        "p/secrets",
    ]

    def __init__(
        self,
        client: Any = None,
        model: str = "",
        max_retries: int = 3,
        mode: str = "pentester",
        semgrep_timeout: int = 30,
        **_kwargs: Any,
    ) -> None:
        self._mode = mode
        self._timeout = semgrep_timeout
        self._cache: dict[str, set[int]] = {}

    def scan_lines(
        self, file_path: str, source_code: str, flagged_lines: Set[int]
    ) -> Set[int]:
        """Return suspicious line numbers using semgrep.

        Unions semgrep findings with regex-flagged lines so nothing is lost
        when semgrep is unavailable or returns an empty set.

        Args:
            file_path: Path to the file on disk (semgrep reads it directly).
            source_code: File content (unused; kept for interface compat).
            flagged_lines: Lines pre-flagged by regex triage.

        Returns:
            Union of semgrep-detected lines and regex-flagged lines.
        """
        if file_path not in self._cache:
            self._cache[file_path] = self._run_semgrep(file_path)

        semgrep_lines = self._cache[file_path]
        # Always union: if semgrep finds nothing, regex flags still surface.
        return semgrep_lines | set(flagged_lines)

    def _run_semgrep(self, file_path: str) -> set[int]:
        """Run semgrep and return the set of flagged line numbers."""
        cmd = [
            "semgrep",
            "--json",
            "--quiet",
            "--no-git-ignore",
        ]
        for cfg in self._SEMGREP_CONFIGS:
            cmd += ["--config", cfg]
        cmd.append(file_path)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
            # semgrep exit codes: 0 = clean, 1 = findings, 2+ = error
            if result.returncode > 1:
                return set()
            data = json.loads(result.stdout)
            return {r["start"]["line"] for r in data.get("results", [])}
        except FileNotFoundError:
            # semgrep not installed — degrade gracefully
            return set()
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            return set()

    @classmethod
    def semgrep_available(cls) -> bool:
        """Return True if semgrep is installed and reachable."""
        try:
            subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                timeout=5,
                check=True,
            )
            return True
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return False
