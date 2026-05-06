"""GraphQL security probe: introspection, batching, alias overload, BOLA."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
import json

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

from log.audit import log_step


@dataclass
class GraphQLFinding:
    url: str
    attack_type: str          # introspection, batching, alias_overload, bola
    payload: str
    response_excerpt: str
    severity: str             # CRITICAL, HIGH, MEDIUM, LOW
    confidence: float         # 0.0-1.0


_INTROSPECTION_QUERY = '{"query":"{__schema{types{name}}}"}'

_BATCH_QUERY = json.dumps([
    {"query": "{__typename}"},
    {"query": "{__typename}"},
])

_ALIAS_OVERLOAD_QUERY = json.dumps({
    "query": "{ " + " ".join(f"a{i}: __typename" for i in range(100)) + " }"
})

_BOLA_USER1_QUERY = json.dumps({"query": "{user(id: 1){email id}}"})
_BOLA_USER2_QUERY = json.dumps({"query": "{user(id: 2){email id}}"})


async def probe_graphql(
    url: str,
    session=None,
    timeout: int = 15,
) -> list[GraphQLFinding]:
    """Probe a GraphQL endpoint for common security misconfigurations.

    Args:
        url: Full URL of the GraphQL endpoint (must contain /graphql).
        session: Unused; kept for interface parity with other probes.
        timeout: HTTP request timeout in seconds.

    Returns:
        List of GraphQLFinding objects for confirmed or suspected issues.
    """
    if not _HTTPX_AVAILABLE:
        log_step("graphql.probe.skip", url=url, reason="httpx not installed")
        return []

    findings: list[GraphQLFinding] = []
    headers = {"Content-Type": "application/json"}

    async with httpx.AsyncClient(verify=False, timeout=timeout) as client:  # noqa: S501
        # ── Test 1: Introspection enabled ────────────────────────────────
        log_step("graphql.probe.introspection", url=url)
        try:
            resp = await client.post(url, content=_INTROSPECTION_QUERY, headers=headers)
            body = resp.text
            if resp.status_code == 200 and "__Schema" in body:
                findings.append(GraphQLFinding(
                    url=url,
                    attack_type="introspection",
                    payload=_INTROSPECTION_QUERY,
                    response_excerpt=body[:300],
                    severity="MEDIUM",
                    confidence=0.95,
                ))
                log_step("graphql.finding", url=url, type="introspection")
        except Exception as exc:  # noqa: BLE001
            log_step("graphql.probe.error", url=url, test="introspection", err=str(exc), level="warning")

        # ── Test 2: Query batching ────────────────────────────────────────
        log_step("graphql.probe.batching", url=url)
        try:
            resp = await client.post(url, content=_BATCH_QUERY, headers=headers)
            body = resp.text
            # A 200 response to a JSON array indicates batching is enabled
            if resp.status_code == 200 and body.startswith("["):
                findings.append(GraphQLFinding(
                    url=url,
                    attack_type="batching",
                    payload=_BATCH_QUERY,
                    response_excerpt=body[:300],
                    severity="LOW",
                    confidence=0.7,
                ))
                log_step("graphql.finding", url=url, type="batching")
        except Exception as exc:  # noqa: BLE001
            log_step("graphql.probe.error", url=url, test="batching", err=str(exc), level="warning")

        # ── Test 3: Alias overload ────────────────────────────────────────
        log_step("graphql.probe.alias_overload", url=url)
        try:
            resp = await client.post(url, content=_ALIAS_OVERLOAD_QUERY, headers=headers)
            body = resp.text
            if resp.status_code == 200 and "a0" in body:
                findings.append(GraphQLFinding(
                    url=url,
                    attack_type="alias_overload",
                    payload=_ALIAS_OVERLOAD_QUERY[:200],
                    response_excerpt=body[:300],
                    severity="LOW",
                    confidence=0.7,
                ))
                log_step("graphql.finding", url=url, type="alias_overload")
        except Exception as exc:  # noqa: BLE001
            log_step("graphql.probe.error", url=url, test="alias_overload", err=str(exc), level="warning")

        # ── Test 4: BOLA — cross-user data access ─────────────────────────
        log_step("graphql.probe.bola", url=url)
        try:
            resp1 = await client.post(url, content=_BOLA_USER1_QUERY, headers=headers)
            resp2 = await client.post(url, content=_BOLA_USER2_QUERY, headers=headers)
            body1 = resp1.text
            body2 = resp2.text
            # Both returned 200 with different non-error data → BOLA confirmed
            if (
                resp1.status_code == 200
                and resp2.status_code == 200
                and body1 != body2
                and "error" not in body2.lower()
                and "null" not in body2
            ):
                findings.append(GraphQLFinding(
                    url=url,
                    attack_type="bola",
                    payload=_BOLA_USER2_QUERY,
                    response_excerpt=f"user1: {body1[:150]} | user2: {body2[:150]}",
                    severity="HIGH",
                    confidence=0.95,
                ))
                log_step("graphql.finding", url=url, type="bola")
        except Exception as exc:  # noqa: BLE001
            log_step("graphql.probe.error", url=url, test="bola", err=str(exc), level="warning")

    return findings
