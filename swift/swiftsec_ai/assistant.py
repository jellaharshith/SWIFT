"""SwiftSecAssistant — orchestrates settings, CVE RAG, backend, and tools."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .config import Settings, load_settings
from .cve import CVEStore
from .guardrail import GuardrailViolation, LLMGuardrail
from .llm import build_backend
from .prompts import SYSTEM_PROMPT
from .telemetry import Telemetry
from .tools import MCPValidator, build_registry


class SwiftSecAssistant:
    """The reasoning core. Construct with the real SWIFTSEC callables wired in.

    Args:
        settings: explicit :class:`Settings`, or ``None`` to load from env/.env.
        roe:      ``(target, technique="active_scan") -> dict`` scope verdict, or None.
        recon:    ``run_osint(target)`` (sync/async), or None.
        scanner:  ``scan_url(target)``, or None.
        h1:       ``(fields: dict) -> str`` report formatter, or None.
    """

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        roe: Callable[..., Any] | None = None,
        recon: Callable[..., Any] | None = None,
        scanner: Callable[..., Any] | None = None,
        h1: Callable[[dict], str] | None = None,
        engagement_id: str = "default",
    ) -> None:
        self.settings = settings or load_settings()
        self.engagement_id = engagement_id
        self.cve = CVEStore(self.settings.cve_db_path, nvd_api_key=self.settings.nvd_api_key)
        # Persist the configured interval so CVEStore.sync can honor it.
        self.cve.set_meta(
            "min_sync_interval_seconds", str(self.settings.cve_min_sync_interval_seconds)
        )
        self.guardrail = LLMGuardrail()
        self.telemetry = Telemetry()
        self.backend = build_backend(self.settings, guardrail=self.guardrail)
        self.registry = build_registry(
            self.cve, roe=roe, recon=recon, scanner=scanner, h1=h1, validator=MCPValidator()
        )
        self.last_trace: list[dict[str, Any]] = []

    # ------------------------------------------------------------------ CVE RAG
    def update_cves(self, force: bool = False, initial_days: int | None = None) -> dict[str, Any]:
        """Incrementally sync the local NVD mirror."""
        return self.cve.sync(
            force=force, initial_days=initial_days or self.settings.cve_initial_days
        )

    def _inject_cve_context(self, message: str) -> str:
        if self.cve.count() <= 0:
            return message
        ctx = self.cve.retrieve_context(message, limit=self.settings.context_results)
        if not ctx:
            return message
        return (
            f"{ctx}\n\n"
            "(Use the CVE context above where relevant. Never invent CVE IDs; call "
            "cve_lookup for anything not shown.)\n\n"
            f"# Operator request\n{message}"
        )

    # ------------------------------------------------------------------ ask
    def ask(self, message: str) -> str:
        """Answer a request, auto-injecting retrieved CVE context and tool-calling."""
        self.last_trace = []

        def _on_tool(name: str, args: dict, result: str) -> None:
            self.last_trace.append({"tool": name, "args": args, "result_len": len(result)})
            self.telemetry.log(
                self.engagement_id, "tool_call", tool_name=name,
                target=args.get("target") or args.get("endpoint"),
                summary=result[:200],
            )

        user_message = self._inject_cve_context(message)
        try:
            return self.backend.run(
                system=SYSTEM_PROMPT,
                user_message=user_message,
                tools=self.registry.to_neutral_schema(),
                executor=self.registry.execute,
                max_iterations=self.settings.max_tool_iterations,
                on_tool=_on_tool,
            )
        except GuardrailViolation as e:
            self.telemetry.log(
                self.engagement_id, "guardrail_violation",
                summary=str(e), flags=e.flags,
            )
            raise

    # ------------------------------------------------------------------ info
    def info(self) -> dict[str, Any]:
        backend = self.backend.name
        configured = (
            bool(self.settings.anthropic_api_key)
            if backend == "anthropic"
            else True  # ollama needs no key; assumed reachable locally
        )
        return {
            "backend": backend,
            "model": getattr(self.backend, "model", "?"),
            "configured": configured,
            "cve_count": self.cve.count(),
            "cve_db": self.settings.cve_db_path,
            "last_sync": self.cve.get_meta("last_sync"),
            "tools": self.registry.names(),
        }

    def close(self) -> None:
        self.telemetry.log(self.engagement_id, "run_stop", summary="assistant closed")
        self.telemetry.write_coverage(self.engagement_id)
        self.telemetry.close()
        self.cve.close()
