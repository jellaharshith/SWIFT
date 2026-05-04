"""Configuration management for SWIFT."""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from dotenv import load_dotenv


@dataclass
class Config:
    """SWIFT runtime configuration.

    Attributes:
        api_key: Anthropic API key for Claude model access.
        confidence_threshold: Minimum confidence to report a finding (default 0.95).
        sandbox_timeout: Docker sandbox execution timeout in seconds (default 30).
        max_retries: Maximum API retry attempts on transient failures (default 3).
        log_level: Python logging level string (default INFO).
        haiku_model: Claude Haiku model ID for triage scanning.
        sonnet_model: Claude Sonnet model ID for deep analysis and patching.
        kali_image_tag: Kali Linux Docker image tag for offensive scanning.
        nvd_api_key: NVD API key for higher rate limits (optional).
        cve_poll_interval: Seconds between live CVE API polls (default 2).
        kali_container_timeout: Seconds before killing Kali scan container (default 300).
    """

    api_key: str
    confidence_threshold: float = 0.95
    sandbox_timeout: int = 30
    max_retries: int = 3
    log_level: str = "INFO"
    haiku_model: str = "claude-haiku-4-5-20251001"
    sonnet_model: str = "claude-sonnet-4-6"
    kali_image_tag: str = "swift-kali:latest"
    nvd_api_key: str = ""
    cve_poll_interval: int = 2
    kali_container_timeout: int = 300


_config: Optional[Config] = None


def get_config() -> Config:
    """Load config from environment variables, caching after first load.

    Returns:
        A fully-validated Config instance.

    Raises:
        ValueError: If ANTHROPIC_API_KEY is missing or confidence_threshold
            is outside [0.0, 1.0].
    """
    global _config
    if _config is not None:
        return _config

    load_dotenv()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError(
            "ANTHROPIC_API_KEY not set. Add it to .env or environment."
        )

    threshold = float(os.environ.get("SWIFT_CONFIDENCE_THRESHOLD", "0.95"))
    if not 0.0 <= threshold <= 1.0:
        raise ValueError(
            f"confidence_threshold must be between 0.0 and 1.0, got {threshold}"
        )

    _config = Config(
        api_key=api_key,
        confidence_threshold=threshold,
        sandbox_timeout=int(os.environ.get("SWIFT_SANDBOX_TIMEOUT", "30")),
        max_retries=int(os.environ.get("SWIFT_MAX_RETRIES", "3")),
        log_level=os.environ.get("SWIFT_LOG_LEVEL", "INFO"),
        kali_image_tag=os.environ.get("KALI_IMAGE_TAG", "swift-kali:latest"),
        nvd_api_key=os.environ.get("NVD_API_KEY", ""),
        cve_poll_interval=int(os.environ.get("CVE_POLL_INTERVAL", "2")),
        kali_container_timeout=int(os.environ.get("KALI_CONTAINER_TIMEOUT", "300")),
    )
    return _config


def reset_config() -> None:
    """Reset cached Config. Only for use in tests."""
    global _config
    _config = None
