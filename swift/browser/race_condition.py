"""Race condition probe: asyncio burst on state-change endpoints."""
from __future__ import annotations

import asyncio
import statistics
import time
from dataclasses import dataclass, field
from typing import Optional

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

from log.audit import log_step

# URL path fragments that indicate a state-change endpoint worth probing
_STATE_CHANGE_KEYWORDS = (
    "/transfer", "/purchase", "/redeem", "/vote", "/like",
    "/apply", "/checkout", "/buy", "/pay", "/claim",
)


@dataclass
class RaceFinding:
    url: str
    method: str
    payload: dict | None
    response_codes: list[int] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)
    confidence: float = 0.0


def _is_state_change_url(url: str) -> bool:
    """Return True if the URL looks like a state-mutation endpoint."""
    lower = url.lower()
    return any(kw in lower for kw in _STATE_CHANGE_KEYWORDS)


async def probe_race_condition(
    url: str,
    method: str = "POST",
    payload: dict | None = None,
    n: int = 20,
    session=None,
) -> RaceFinding | None:
    """Send N concurrent requests and detect race-condition anomalies.

    Only fires on state-change endpoint URL patterns. Uses asyncio.gather
    for tight burst timing. Detects duplicate 2xx successes, inconsistent
    response codes, and timing variance > 2 standard deviations.

    Args:
        url: Target endpoint URL.
        method: HTTP method (POST, PUT, PATCH, DELETE).
        payload: Request body dict (JSON-encoded). None sends empty body.
        n: Burst size (20-50 recommended).
        session: Unused; kept for interface parity with other probes.

    Returns:
        RaceFinding if anomalies detected, else None.
    """
    if not _HTTPX_AVAILABLE:
        log_step("race.probe.skip", url=url, reason="httpx not installed")
        return None

    if not _is_state_change_url(url):
        log_step("race.probe.skip", url=url, reason="not a state-change endpoint")
        return None

    log_step("race.probe.start", url=url, method=method, burst=n)

    json_body = payload or {}

    async def _single_request(client: "httpx.AsyncClient") -> tuple[int, float]:
        t0 = time.monotonic()
        try:
            resp = await client.request(method, url, json=json_body, timeout=10)
            return resp.status_code, time.monotonic() - t0
        except Exception:  # noqa: BLE001
            return 0, time.monotonic() - t0

    try:
        async with httpx.AsyncClient(verify=False) as client:  # noqa: S501
            results = await asyncio.gather(*[_single_request(client) for _ in range(n)])
    except Exception as exc:  # noqa: BLE001
        log_step("race.probe.error", url=url, err=str(exc), level="warning")
        return None

    codes = [r[0] for r in results]
    timings = [r[1] for r in results]

    anomalies: list[str] = []

    # Duplicate 2xx: count successful responses — more than 1 is suspicious for idempotency-breaking ops
    success_count = sum(1 for c in codes if 200 <= c < 300)
    if success_count > 1:
        anomalies.append(f"duplicate 2xx success: {success_count}/{n} requests succeeded")

    # Inconsistent responses: mix of 2xx and non-2xx for identical requests
    unique_codes = set(codes) - {0}
    if len(unique_codes) > 2:
        anomalies.append(f"inconsistent response codes: {sorted(unique_codes)}")

    # Timing variance > 2σ from mean
    valid_timings = [t for t in timings if t > 0]
    if len(valid_timings) >= 3:
        mean_t = statistics.mean(valid_timings)
        stdev_t = statistics.stdev(valid_timings) if len(valid_timings) > 1 else 0.0
        if stdev_t > 0 and max(valid_timings) > mean_t + 2 * stdev_t:
            anomalies.append(
                f"timing variance detected: mean={mean_t:.3f}s stdev={stdev_t:.3f}s max={max(valid_timings):.3f}s"
            )

    if not anomalies:
        log_step("race.probe.clean", url=url, codes=sorted(unique_codes))
        return None

    # Confidence: 0.95 for duplicate 2xx (strongest signal), 0.7 for timing/inconsistency
    confidence = 0.95 if success_count > 1 else 0.7

    finding = RaceFinding(
        url=url,
        method=method,
        payload=payload,
        response_codes=codes,
        anomalies=anomalies,
        confidence=confidence,
    )
    log_step("race.finding", url=url, anomalies=anomalies, confidence=confidence)
    return finding
