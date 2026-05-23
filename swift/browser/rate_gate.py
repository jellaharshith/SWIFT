"""Async token-bucket rate gate for web-scan probes.

Honors ROE.rate_limit_rps. Every network-traffic-generating request in
playwright_runner is guarded by AsyncRateGate.acquire() before firing.

Bug it fixes: prior to v7.1, swiftsec web-scan fired probes at ~10 req/sec
regardless of `rate_limit_rps` in the ROE. Bug bounty programs with strict
throttle requirements (e.g. PortSwigger's <=1 req/sec rule) were violated.
"""
from __future__ import annotations

import asyncio
import time


class AsyncRateGate:
    """Leaky-bucket async rate limiter.

    Args:
        rps: Max requests per second.
        burst: Bucket depth — number of requests allowed back-to-back before
               throttling kicks in. Default 1 (strict pace).

    Example:
        gate = AsyncRateGate(rps=1.0, burst=1)
        for url in urls:
            await gate.acquire()
            await page.goto(url)
    """

    def __init__(self, rps: float, burst: int = 1) -> None:
        if rps <= 0:
            raise ValueError(f"rps must be > 0, got {rps}")
        if burst < 1:
            raise ValueError(f"burst must be >= 1, got {burst}")
        self._rps = float(rps)
        self._burst = int(burst)
        self._tokens: float = float(burst)
        self._last_refill: float = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Block until a token is available, then consume one."""
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._last_refill
                self._tokens = min(self._burst, self._tokens + elapsed * self._rps)
                self._last_refill = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait = (1.0 - self._tokens) / self._rps
                await asyncio.sleep(wait)

    @property
    def rps(self) -> float:
        return self._rps

    @property
    def burst(self) -> int:
        return self._burst
