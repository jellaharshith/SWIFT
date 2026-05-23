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
        confidence_threshold: Minimum confidence to report a finding (default 0.95).
        sandbox_timeout: Docker sandbox execution timeout in seconds (default 30).
        max_retries: Maximum retry attempts on transient failures (default 3).
        log_level: Python logging level string (default INFO).
        kali_image_tag: Kali Linux Docker image tag for offensive scanning.
        nvd_api_key: NVD API key for higher rate limits (optional).
        cve_poll_interval: Seconds between live CVE API polls (default 2).
        kali_container_timeout: Seconds before killing Kali scan container (default 300).
        semgrep_timeout: Per-file semgrep timeout in seconds (default 30).
    """

    confidence_threshold: float = 0.95
    sandbox_timeout: int = 30
    max_retries: int = 3
    log_level: str = "INFO"
    kali_image_tag: str = "swift-kali:latest"
    nvd_api_key: str = ""
    cve_poll_interval: int = 2
    kali_container_timeout: int = 300
    intel_db_path: str = ""
    intel_sync_interval_hours: int = 24
    github_token: str = ""
    semgrep_timeout: int = 30


_config: Optional[Config] = None


def get_config() -> Config:
    """Load config from environment variables, caching after first load.

    Returns:
        A fully-validated Config instance.

    Raises:
        ValueError: If confidence_threshold is outside [0.0, 1.0].
    """
    global _config
    if _config is not None:
        return _config

    load_dotenv()

    threshold = float(os.environ.get("SWIFT_CONFIDENCE_THRESHOLD", "0.95"))
    if not 0.0 <= threshold <= 1.0:
        raise ValueError(
            f"confidence_threshold must be between 0.0 and 1.0, got {threshold}"
        )

    _config = Config(
        confidence_threshold=threshold,
        sandbox_timeout=int(os.environ.get("SWIFT_SANDBOX_TIMEOUT", "30")),
        max_retries=int(os.environ.get("SWIFT_MAX_RETRIES", "3")),
        log_level=os.environ.get("SWIFT_LOG_LEVEL", "INFO"),
        kali_image_tag=os.environ.get("KALI_IMAGE_TAG", "swift-kali:latest"),
        nvd_api_key=os.environ.get("NVD_API_KEY", ""),
        cve_poll_interval=int(os.environ.get("CVE_POLL_INTERVAL", "2")),
        kali_container_timeout=int(os.environ.get("KALI_CONTAINER_TIMEOUT", "300")),
        intel_db_path=os.environ.get("INTEL_DB_PATH", ""),
        intel_sync_interval_hours=int(os.environ.get("INTEL_SYNC_INTERVAL_HOURS", "24")),
        github_token=os.environ.get("GITHUB_TOKEN", ""),
        semgrep_timeout=int(os.environ.get("SWIFT_SEMGREP_TIMEOUT", "30")),
    )
    return _config


def reset_config() -> None:
    """Reset cached Config. Only for use in tests."""
    global _config
    _config = None
