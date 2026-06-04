"""swiftsec_ai — LLM-powered ethical-hacker assistant for SWIFTSEC.

A thin, SDK-free reasoning layer over the existing SWIFTSEC modules:

* Stays current on CVEs via RAG — :class:`~swiftsec_ai.cve.CVEStore` incrementally
  syncs the NVD feed into local SQLite/FTS5 and injects relevant CVEs into the
  prompt at query time (currency lives in retrieval, never in the weights).
* Reasons like a pentester via :data:`~swiftsec_ai.prompts.SYSTEM_PROMPT`
  (authorized-only, ROE/scope-aware, methodology-driven, never fabricates CVE IDs,
  drafts but never auto-submits reports).
* Drives the real SWIFTSEC modules (recon / scan / scope-check / H1 report) through
  tool-calling on two interchangeable backends (Ollama local, Anthropic REST).

Only hard dependency is :mod:`requests`; :mod:`python-dotenv` is used if present.
No LLM SDKs.
"""
from __future__ import annotations

from .assistant import SwiftSecAssistant
from .config import Settings, load_settings

__all__ = ["Settings", "SwiftSecAssistant", "load_settings"]

__version__ = "1.0.0"
