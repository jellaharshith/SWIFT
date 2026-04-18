"""Agent orchestrator stub — replaced in Task 10."""
from __future__ import annotations

from agent.models import ScanResult


def scan_codebase(repo_path: str, generate_patches_flag: bool = False) -> ScanResult:
    """Stub — implemented in Task 10."""
    raise NotImplementedError("Orchestrator not yet implemented")


def generate_patches(scan_result: ScanResult) -> ScanResult:
    """Stub — implemented in Task 10."""
    raise NotImplementedError("Orchestrator not yet implemented")
