"""Adapter wrappers that expose existing browser/ probe functions as BaseModule subclasses.

Existing probes are async functions returning list[XFinding]. These adapters
implement the BaseModule interface without modifying any existing code.
"""
from __future__ import annotations

from typing import Any

from .base import BaseModule, Finding, Phase, Severity, VulnType
from .decorators import roe_gated


def _safe_severity(raw: Any) -> Severity:
    try:
        return Severity[str(raw).upper()]
    except KeyError:
        return Severity.MEDIUM


class _FunctionalAdapter(BaseModule):
    """Generic adapter: wraps an existing async probe_xxx() function."""

    _func = None
    _technique = "active_scan"

    @roe_gated("active_scan")
    async def probe(self, target, session, roe) -> list[Finding]:
        url = target.url if hasattr(target, "url") else str(target)
        raw = await self.__class__._func(url, session=session)
        return [self._convert(r) for r in (raw or [])]

    def _convert(self, r: Any) -> Finding:
        return Finding(
            module=self.name,
            vuln_type=self.vuln_types[0],
            severity=_safe_severity(getattr(r, "severity", "MEDIUM")),
            title=getattr(r, "kind", getattr(r, "attack_type", self.name)),
            description=getattr(r, "evidence", getattr(r, "response_excerpt", "")),
            target_url=getattr(r, "url", ""),
            confidence=float(getattr(r, "confidence", 0.7)),
            request_evidence=getattr(r, "payload", None),
        )


# ── Concrete adapters ────────────────────────────────────────────────────────

class GraphQLAdapter(_FunctionalAdapter):
    name = "graphql"
    phase = Phase.ACTIVE
    vuln_types = [VulnType.GRAPHQL]
    author = "swift-core"
    version = "5.0"

    @classmethod
    def _load(cls) -> None:
        from browser.graphql_probe import probe_graphql
        cls._func = staticmethod(probe_graphql)


class DomIdorAdapter(_FunctionalAdapter):
    name = "idor"
    phase = Phase.ACTIVE
    vuln_types = [VulnType.IDOR]
    author = "swift-core"
    version = "5.0"

    @classmethod
    def _load(cls) -> None:
        from browser.dom_idor import probe_dom_idor
        cls._func = staticmethod(probe_dom_idor)


class ApiKeyAdapter(_FunctionalAdapter):
    name = "api_key"
    phase = Phase.ACTIVE
    vuln_types = [VulnType.API_KEY]
    author = "swift-core"
    version = "5.0"

    @classmethod
    def _load(cls) -> None:
        from browser.api_key_bruteforce import probe_api_keys
        cls._func = staticmethod(probe_api_keys)


class RaceConditionAdapter(_FunctionalAdapter):
    name = "race_condition"
    phase = Phase.ACTIVE
    vuln_types = [VulnType.BIZLOGIC]
    author = "swift-core"
    version = "5.0"

    @classmethod
    def _load(cls) -> None:
        from browser.race_condition import probe_race_condition
        cls._func = staticmethod(probe_race_condition)


class SmugglingAdapter(_FunctionalAdapter):
    name = "smuggling"
    phase = Phase.ACTIVE
    vuln_types = [VulnType.SMUGGLING]
    author = "swift-core"
    version = "5.0"

    @classmethod
    def _load(cls) -> None:
        from browser.smuggling_probe import probe_smuggling
        cls._func = staticmethod(probe_smuggling)


# Eagerly load functions (import errors are non-fatal at module load time)
for _cls in (GraphQLAdapter, DomIdorAdapter, ApiKeyAdapter, RaceConditionAdapter, SmugglingAdapter):
    try:
        _cls._load()
    except Exception:
        pass

ALL_ADAPTERS = [GraphQLAdapter, DomIdorAdapter, ApiKeyAdapter, RaceConditionAdapter, SmugglingAdapter]
