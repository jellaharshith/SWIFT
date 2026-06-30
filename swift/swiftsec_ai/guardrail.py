"""Pre/post inspection on every LLM call — local AI runtime firewall.

``LLMGuardrail.enforce`` runs before a prompt reaches a backend; raises
``GuardrailViolation`` on injection/scope-override language and halts the call.
``LLMGuardrail.scan_response`` runs after a backend reply comes back; masks
credential-shaped substrings before the text is written to disk or logs.

Every flag event is appended to ``logs/guardrail-<date>.jsonl`` (one file per
UTC day) so a run's guardrail history survives process restarts.
"""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

PROMPT_INJECTION_PATTERNS = [
    r"ignore (all |previous |prior )*instructions",
    r"you are now",
    r"disregard (your |the )?(system |operator )?prompt",
    r"act as (?!a security|an authorized)",
    r"jailbreak",
    r"DAN mode",
]

SENSITIVE_OUTPUT_PATTERNS = [
    r"\b(?:password|passwd|secret|api[_\-]?key|token|bearer)\s*[:=]\s*\S+",
    r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
    r"\b4[0-9]{12}(?:[0-9]{3})?\b",  # Visa
    r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
]


class GuardrailViolation(RuntimeError):
    """Raised by :meth:`LLMGuardrail.enforce` when a prompt fails the pre-flight scan."""

    def __init__(self, flags: list[str]) -> None:
        self.flags = flags
        super().__init__(f"prompt blocked by guardrail: {', '.join(flags)}")


class LLMGuardrail:
    """Pre/post filter wrapping every LLM call (Anthropic and Ollama backends)."""

    def __init__(self, log_dir: str | Path = "logs") -> None:
        self.log_dir = Path(log_dir)
        self._injection_re = [re.compile(p, re.IGNORECASE) for p in PROMPT_INJECTION_PATTERNS]
        self._sensitive_re = [re.compile(p, re.IGNORECASE) for p in SENSITIVE_OUTPUT_PATTERNS]

    def scan_prompt(self, prompt: str) -> dict:
        flags = [
            pattern.pattern
            for pattern in self._injection_re
            if pattern.search(prompt or "")
        ]
        return {"clean": not flags, "flags": flags}

    def scan_response(self, response: str) -> dict:
        text = response or ""
        flags: list[str] = []
        masked = text
        for pattern in self._sensitive_re:
            if pattern.search(masked):
                flags.append(pattern.pattern)
                masked = pattern.sub("[REDACTED]", masked)
        return {"clean": not flags, "flags": flags, "masked": masked}

    def enforce(self, prompt: str) -> None:
        result = self.scan_prompt(prompt)
        if not result["clean"]:
            self._log("prompt_blocked", flags=result["flags"], excerpt=prompt[:200])
            raise GuardrailViolation(result["flags"])

    def log_response_flags(self, flags: list[str]) -> None:
        if flags:
            self._log("response_masked", flags=flags)

    def _log(self, event: str, **fields) -> None:
        self.log_dir.mkdir(parents=True, exist_ok=True)
        day = datetime.now(timezone.utc).strftime("%Y%m%d")
        path = self.log_dir / f"guardrail-{day}.jsonl"
        entry = {"ts": time.time(), "event": event, **fields}
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
