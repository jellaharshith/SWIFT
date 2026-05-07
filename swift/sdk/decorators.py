"""SDK decorators: @roe_gated, @cached_result, @retry."""
from __future__ import annotations

import asyncio
import functools
import hashlib
import time
from pathlib import Path
from typing import Callable


def roe_gated(technique: str) -> Callable:
    """Gate a probe on ROE.allowed_techniques; return synthetic INFO finding if simulate_only."""
    def deco(fn: Callable) -> Callable:
        @functools.wraps(fn)
        async def wrap(self, target, session, roe, *a, **kw):
            from security.roe import assert_technique_allowed
            assert_technique_allowed(roe, technique, raise_on_violation=True)
            if getattr(roe, "simulate_only", False):
                from .base import Finding, Severity
                return [Finding(
                    module=self.name,
                    vuln_type=self.vuln_types[0],
                    severity=Severity.INFO,
                    title=f"[SIM] {self.name}",
                    description="simulate_only=True: synthetic finding",
                    target_url=str(target),
                    confidence=0.5,
                )]
            return await fn(self, target, session, roe, *a, **kw)
        return wrap
    return deco


def cached_result(ttl: int = 3600) -> Callable:
    """Cache probe results for ttl seconds keyed by sha256(target)."""
    def deco(fn: Callable) -> Callable:
        @functools.wraps(fn)
        async def wrap(self, target, session, roe, *a, **kw):
            import diskcache
            cache_dir = Path.home() / ".swift" / "cache" / self.name
            cache = diskcache.Cache(str(cache_dir))
            key = hashlib.sha256(str(target).encode()).hexdigest()
            ts_key = f"{key}:t"
            if key in cache and (time.time() - cache.get(ts_key, 0.0)) < ttl:
                return cache[key]
            result = await fn(self, target, session, roe, *a, **kw)
            cache[key] = result
            cache[ts_key] = time.time()
            return result
        return wrap
    return deco


def retry(max_attempts: int = 3, backoff: str = "exponential") -> Callable:
    """Retry probe on httpx network errors with exponential backoff."""
    def deco(fn: Callable) -> Callable:
        @functools.wraps(fn)
        async def wrap(*a, **kw):
            import httpx
            last_exc: Exception | None = None
            for i in range(max_attempts):
                try:
                    return await fn(*a, **kw)
                except (httpx.NetworkError, httpx.TimeoutException) as exc:
                    last_exc = exc
                    if backoff == "exponential":
                        await asyncio.sleep(2 ** i)
            raise last_exc  # type: ignore[misc]
        return wrap
    return deco
