"""Tests for browser.rate_gate.AsyncRateGate.

Regression for the v7.1 rate-limit bug: swiftsec web-scan fired probes at
~10 rps regardless of ROE rate_limit_rps. AsyncRateGate fixes that — every
network request acquires a token first.
"""
from __future__ import annotations

import asyncio
import time

import pytest

from browser.rate_gate import AsyncRateGate


def test_invalid_rps_rejected() -> None:
    with pytest.raises(ValueError):
        AsyncRateGate(rps=0)
    with pytest.raises(ValueError):
        AsyncRateGate(rps=-1.0)


def test_invalid_burst_rejected() -> None:
    with pytest.raises(ValueError):
        AsyncRateGate(rps=1.0, burst=0)


def test_first_acquire_immediate() -> None:
    """First acquire on a fresh gate consumes the initial burst token without sleeping."""
    async def run():
        gate = AsyncRateGate(rps=1.0, burst=1)
        t0 = time.monotonic()
        await gate.acquire()
        return time.monotonic() - t0

    elapsed = asyncio.run(run())
    assert elapsed < 0.05, f"first acquire should be near-instant, took {elapsed:.3f}s"


def test_10_acquires_at_1rps_burst1_takes_at_least_9s() -> None:
    """At 1 rps with burst=1, 10 sequential acquires take >=9s.

    First token comes from the burst (free), then 9 more each wait ~1s.
    """
    async def run():
        gate = AsyncRateGate(rps=1.0, burst=1)
        t0 = time.monotonic()
        for _ in range(10):
            await gate.acquire()
        return time.monotonic() - t0

    elapsed = asyncio.run(run())
    assert elapsed >= 8.9, f"expected >=9s for 10 acquires at 1rps, took {elapsed:.3f}s"
    assert elapsed < 11.0, f"expected <11s, took {elapsed:.3f}s (gate over-throttling?)"


def test_burst_allows_immediate_acquires() -> None:
    """burst=5 lets 5 acquires fire instantly, then throttles."""
    async def run():
        gate = AsyncRateGate(rps=1.0, burst=5)
        t0 = time.monotonic()
        for _ in range(5):
            await gate.acquire()
        burst_elapsed = time.monotonic() - t0
        # 6th acquire should wait ~1s
        await gate.acquire()
        return burst_elapsed, time.monotonic() - t0

    burst_elapsed, total_elapsed = asyncio.run(run())
    assert burst_elapsed < 0.1, f"burst of 5 should be near-instant, took {burst_elapsed:.3f}s"
    assert total_elapsed >= 0.9, f"6th acquire should wait ~1s, total {total_elapsed:.3f}s"


def test_higher_rps_drains_faster() -> None:
    """At 5 rps, 10 acquires take ~ (10-1)/5 = 1.8s, not 9s."""
    async def run():
        gate = AsyncRateGate(rps=5.0, burst=1)
        t0 = time.monotonic()
        for _ in range(10):
            await gate.acquire()
        return time.monotonic() - t0

    elapsed = asyncio.run(run())
    assert 1.5 <= elapsed <= 2.5, f"expected ~1.8s for 10 acquires at 5rps, took {elapsed:.3f}s"
