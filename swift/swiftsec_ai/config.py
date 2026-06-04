"""Settings for swiftsec_ai, loaded from environment / .env.

No hard dependency on python-dotenv: if it is importable we use it, otherwise a
tiny built-in parser reads a `.env` file in the current working directory.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# NVD 2.0 REST endpoint (same one feeds/live_cve.py uses).
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _load_dotenv(path: str = ".env") -> None:
    """Populate os.environ from a .env file without clobbering existing keys.

    Prefers python-dotenv when installed; falls back to a minimal parser so the
    package keeps `requests` as its only hard dependency.
    """
    try:
        from dotenv import load_dotenv  # type: ignore

        load_dotenv(path, override=False)
        return
    except Exception:
        pass

    p = Path(path)
    if not p.exists():
        return
    try:
        for raw in p.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val
    except Exception:
        # A malformed .env should never break the assistant.
        return


def _get(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _get_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "").strip() or default)
    except (ValueError, TypeError):
        return default


def _get_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "").strip() or default)
    except (ValueError, TypeError):
        return default


@dataclass
class Settings:
    """Runtime configuration for the assistant.

    Backend selection:
        ``llm_backend`` is one of ``auto | ollama | anthropic``. ``auto`` resolves
        to ``anthropic`` when ``ANTHROPIC_API_KEY`` is set, otherwise ``ollama``.
        Read :pyattr:`resolved_backend` for the collapsed value.
    """

    # --- backend selector ------------------------------------------------
    llm_backend: str = "auto"  # auto | ollama | anthropic

    # --- ollama ----------------------------------------------------------
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "llama3.1"
    ollama_timeout: float = 120.0

    # --- anthropic (REST, no SDK) ---------------------------------------
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-opus-4-8"
    anthropic_max_tokens: int = 4096

    # --- NVD / CVE store -------------------------------------------------
    nvd_api_key: str = ""
    cve_db_path: str = "swiftsec_cve.db"
    cve_initial_days: int = 30
    cve_min_sync_interval_seconds: int = 7200  # 2h

    # --- retrieval / loop ------------------------------------------------
    context_results: int = 5
    max_tool_iterations: int = 6

    @property
    def resolved_backend(self) -> str:
        """Collapse ``auto`` into a concrete backend name."""
        backend = (self.llm_backend or "auto").strip().lower()
        if backend == "auto":
            return "anthropic" if self.anthropic_api_key.strip() else "ollama"
        return backend


def load_settings(env_file: str | None = ".env") -> Settings:
    """Build :class:`Settings` from environment (and an optional .env file)."""
    if env_file:
        _load_dotenv(env_file)

    return Settings(
        llm_backend=_get("SWIFTSEC_LLM_BACKEND", "auto") or "auto",
        ollama_host=_get("OLLAMA_HOST", "http://localhost:11434"),
        ollama_model=_get("OLLAMA_MODEL", "llama3.1"),
        ollama_timeout=_get_float("OLLAMA_TIMEOUT", 120.0),
        anthropic_api_key=_get("ANTHROPIC_API_KEY", ""),
        anthropic_model=_get("ANTHROPIC_MODEL", "claude-opus-4-8"),
        anthropic_max_tokens=_get_int("ANTHROPIC_MAX_TOKENS", 4096),
        nvd_api_key=_get("NVD_API_KEY", ""),
        cve_db_path=_get("SWIFTSEC_CVE_DB", "swiftsec_cve.db"),
        cve_initial_days=_get_int("SWIFTSEC_CVE_INITIAL_DAYS", 30),
        cve_min_sync_interval_seconds=_get_int("SWIFTSEC_CVE_MIN_SYNC_INTERVAL", 7200),
        context_results=_get_int("SWIFTSEC_CONTEXT_RESULTS", 5),
        max_tool_iterations=_get_int("SWIFTSEC_MAX_TOOL_ITERS", 6),
    )
