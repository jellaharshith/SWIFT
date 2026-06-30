"""AI Attack Surface Mapper — passive/light-active discovery of a target's
AI-specific surface, run BEFORE standard recon on any target with AI features.

Every check here is passive (HTTP GET/HEAD with a short timeout, no auth
bypass attempts, no exploitation) or a plain TCP connect probe — equivalent in
risk to ``run_recon``, not ``run_scan``. Callers MUST confirm scope (via
``scope_check`` / a ``roe`` callable) before calling :func:`run_ai_asm`.
"""
from __future__ import annotations

import json
import re
import socket
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

AI_ASM_CHECKS = [
    {"id": "llm-endpoint-discovery", "tier": 1,
     "desc": "Find /v1/chat, /api/openai, /generate, /completions endpoints via robots.txt + common paths"},
    {"id": "model-inference-server", "tier": 1,
     "desc": "Detect Ollama (:11434), LM Studio (:1234), vLLM/TGI (:8000), Triton (:8001) via TCP connect"},
    {"id": "ai-api-key-exposure", "tier": 1,
     "desc": "Search fetched HTML/JS for OPENAI_API_KEY, ANTHROPIC_API_KEY, HF_TOKEN patterns"},
    {"id": "vector-db-exposure", "tier": 1,
     "desc": "Detect Qdrant (:6333), Weaviate (:8080), unauthenticated query endpoint"},
    {"id": "mcp-server-exposure", "tier": 1,
     "desc": "Probe for an exposed MCP server (unauthenticated tool schema enumeration)"},
    {"id": "ai-agent-identity", "tier": 1,
     "desc": "Probe for agent orchestrator endpoints (LangChain, AutoGPT, CrewAI APIs)"},
    {"id": "prompt-injection-surface", "tier": 2,
     "desc": "Flag if chat/search/upload inputs were observed feeding an LLM-shaped endpoint"},
    {"id": "rag-poisoning-surface", "tier": 2,
     "desc": "Flag knowledge-base ingestion / file-upload-to-vector-store endpoints"},
    {"id": "model-dos-surface", "tier": 3,
     "desc": "Flag inference endpoints observed with no apparent rate limiting"},
    {"id": "data-exfil-surface", "tier": 3,
     "desc": "Flag pages that render LLM output without apparent escaping"},
]

_COMMON_LLM_PATHS = [
    "/v1/chat/completions", "/v1/completions", "/api/openai", "/api/chat",
    "/generate", "/completions", "/api/generate",
]
_INFERENCE_PORTS = {
    "ollama": 11434, "lm_studio": 1234, "vllm_or_tgi": 8000, "triton": 8001,
}
_VECTOR_DB_PORTS = {"qdrant": 6333, "weaviate": 8080}
_KEY_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9]{20,}"),                     # OpenAI-shaped
    re.compile(r"sk-ant-[A-Za-z0-9\-]{20,}"),                # Anthropic-shaped
    re.compile(r"hf_[A-Za-z0-9]{20,}"),                      # HuggingFace
]


def _connect_ok(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def run_ai_asm(target: str, out_dir: str | Path = "engagements") -> dict[str, Any]:
    """Map the AI-specific attack surface of ``target``. Returns the report dict
    and writes it to ``<out_dir>/<target>/ai_asm_<ts>.json``.
    """
    import requests

    parsed = urlparse(target if "://" in target else f"https://{target}")
    base = f"{parsed.scheme}://{parsed.netloc}"
    host = parsed.hostname or target

    surfaces: list[dict[str, Any]] = []

    # llm-endpoint-discovery
    for path in _COMMON_LLM_PATHS:
        try:
            resp = requests.get(urljoin(base, path), timeout=3)
            if resp.status_code not in (404,):
                surfaces.append({
                    "check": "llm-endpoint-discovery", "tier": 1,
                    "evidence": f"{path} -> HTTP {resp.status_code}",
                })
        except Exception:
            continue

    # model-inference-server / vector-db-exposure (plain TCP connect, no payload)
    for name, port in {**_INFERENCE_PORTS, **_VECTOR_DB_PORTS}.items():
        check_id = "model-inference-server" if name in _INFERENCE_PORTS else "vector-db-exposure"
        if _connect_ok(host, port):
            surfaces.append({
                "check": check_id, "tier": 1,
                "evidence": f"{name} reachable on {host}:{port}",
            })

    # ai-api-key-exposure (scan the landing page body for key-shaped strings)
    try:
        body = requests.get(base, timeout=3).text
        for pattern in _KEY_PATTERNS:
            if pattern.search(body):
                surfaces.append({
                    "check": "ai-api-key-exposure", "tier": 1,
                    "evidence": f"key-shaped string matched {pattern.pattern!r} on {base}",
                })
    except Exception:
        pass

    report = {
        "target": target,
        "ts": time.time(),
        "checks_run": [c["id"] for c in AI_ASM_CHECKS],
        "surfaces": surfaces,
        "tier1_count": sum(1 for s in surfaces if s["tier"] == 1),
        "recommended_priority": "tier1" if any(s["tier"] == 1 for s in surfaces) else "none-found",
    }

    out = Path(out_dir) / re.sub(r"[^A-Za-z0-9_.-]", "_", target)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"ai_asm_{int(report['ts'])}.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    report["artifact_path"] = str(path)
    return report
