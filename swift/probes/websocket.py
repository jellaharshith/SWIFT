"""WebSocket attack probe (Module 3)."""
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Optional

import websockets  # module-level import enables test patching via probes.websocket.websockets
from audit.decorators import audit_logged
from sdk.base import BaseModule, Finding, Phase, Severity, VulnType
from sdk.decorators import roe_gated

_REDACT_CC = re.compile(r"\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}")
_REDACT_BEARER = re.compile(r"Bearer\s+[^\s\"]+", re.IGNORECASE)
_MAX_MSG_BYTES = 4096


def _sanitize(data: str) -> str:
    """Truncate and redact sensitive patterns from captured WS messages."""
    data = data[:_MAX_MSG_BYTES]
    data = _REDACT_CC.sub("[CC-REDACTED]", data)
    data = _REDACT_BEARER.sub("Bearer [REDACTED]", data)
    return data


@dataclass
class WebSocketEndpoint:
    url: str
    protocol: Optional[str] = None
    requires_auth: bool = False
    message_schema: dict = field(default_factory=dict)
    upgrade_headers: dict = field(default_factory=dict)
    is_socket_io: bool = False
    is_sockjs: bool = False


class WebSocketDiscovery:
    """Discover WebSocket endpoints by parsing JS source and intercepting upgrades."""

    async def discover(self, base_url: str, session=None) -> list[WebSocketEndpoint]:
        endpoints: list[WebSocketEndpoint] = []
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                # Fetch main page JS for new WebSocket() patterns
                resp = await client.get(base_url)
                if resp.status_code == 200:
                    # Find ws:// and wss:// URLs in JS
                    ws_urls = re.findall(
                        r"""(?:new WebSocket\(|["'])(wss?://[^"'\s)]+)""", resp.text
                    )
                    for ws_url in set(ws_urls):
                        ep = WebSocketEndpoint(url=ws_url)
                        # Detect socket.io
                        if "EIO=" in ws_url or "socket.io" in ws_url:
                            ep.is_socket_io = True
                        endpoints.append(ep)

                    # Check for socket.io on common paths
                    for path in ["/socket.io/", "/ws", "/websocket"]:
                        try:
                            r = await client.get(base_url.rstrip("/") + path + "?EIO=4&transport=polling")
                            if r.status_code == 200 and ("0{" in r.text or "EIO" in r.text):
                                ws_url = base_url.replace("http://", "ws://").replace(
                                    "https://", "wss://"
                                ).rstrip("/") + path
                                ep = WebSocketEndpoint(url=ws_url, is_socket_io=True)
                                endpoints.append(ep)
                        except Exception:
                            pass

                    # Check for SockJS
                    try:
                        r = await client.get(base_url.rstrip("/") + "/sockjs/info")
                        if r.status_code == 200:
                            ws_url = base_url.replace("http://", "ws://").replace(
                                "https://", "wss://"
                            ).rstrip("/") + "/sockjs/websocket"
                            endpoints.append(WebSocketEndpoint(url=ws_url, is_sockjs=True))
                    except Exception:
                        pass
        except Exception:
            pass
        return endpoints


class WebSocketProbe(BaseModule):
    name = "websocket"
    phase = Phase.ACTIVE
    vuln_types = [VulnType.WEBSOCKET]
    author = "swift-core"
    version = "1.0"

    @roe_gated("websocket_attack")
    @audit_logged("probe_executed")
    async def probe(self, target, session, roe) -> list[Finding]:
        base_url = str(target)
        findings: list[Finding] = []

        endpoints = await WebSocketDiscovery().discover(base_url, session)
        if not endpoints:
            # Try a direct WS URL
            ws_url = base_url.replace("http://", "ws://").replace("https://", "wss://")
            endpoints = [WebSocketEndpoint(url=ws_url)]

        for ep in endpoints[:5]:  # cap at 5 endpoints
            results = await asyncio.gather(
                self._unauthenticated_upgrade(ep),
                self._message_injection(ep),
                return_exceptions=True,
            )
            for r in results:
                if isinstance(r, list):
                    findings.extend(r)

            if ep.is_socket_io:
                ns_findings = await self._socket_io_namespace_abuse(ep)
                findings.extend(ns_findings)

        return findings

    async def _unauthenticated_upgrade(self, ep: WebSocketEndpoint) -> list[Finding]:
        """Attempt unauthenticated WebSocket upgrade."""
        findings = []
        try:
            import websockets
            async with websockets.connect(
                ep.url,
                open_timeout=5,
                close_timeout=3,
                additional_headers={},
            ) as ws:
                # Send 5 probe messages
                probe_msgs = ["ping", "null", "{}", "[]", "test"]
                responses = []
                for msg in probe_msgs:
                    try:
                        await asyncio.wait_for(ws.send(msg), timeout=3)
                        resp = await asyncio.wait_for(ws.recv(), timeout=3)
                        responses.append(_sanitize(str(resp)))
                    except Exception:
                        pass

                severity = Severity.HIGH if responses else Severity.MEDIUM
                findings.append(Finding(
                    module=self.name,
                    vuln_type=VulnType.WEBSOCKET,
                    severity=severity,
                    title=f"Unauthenticated WebSocket upgrade accepted at {ep.url}",
                    description=(
                        "WebSocket connection established without authentication. "
                        + (f"Received {len(responses)} response(s)." if responses else "No data returned.")
                    ),
                    target_url=ep.url,
                    confidence=0.85 if responses else 0.65,
                    cwe_id=306,
                    remediation="Require authentication tokens on WebSocket upgrade handshake.",
                    response_evidence="\n".join(responses[:3]) if responses else None,
                ))
        except Exception:
            pass
        return findings

    async def _message_injection(self, ep: WebSocketEndpoint) -> list[Finding]:
        """Inject XSS, SQLi, and prototype pollution into WS messages."""
        findings = []
        xss_payload = "<script>alert('xss')</script>"
        sqli_payload = "' OR '1'='1"
        proto_payload = json.dumps({"__proto__": {"admin": True}})
        payloads = [
            (xss_payload, "XSS"),
            (sqli_payload, "SQLi"),
            (proto_payload, "prototype_pollution"),
        ]
        try:
            import websockets
            async with websockets.connect(ep.url, open_timeout=5, close_timeout=3) as ws:
                for payload, ptype in payloads:
                    try:
                        await asyncio.wait_for(ws.send(payload), timeout=3)
                        resp = await asyncio.wait_for(ws.recv(), timeout=3)
                        resp_str = _sanitize(str(resp))
                        if payload in resp_str or "error" in resp_str.lower():
                            findings.append(Finding(
                                module=self.name,
                                vuln_type=VulnType.WEBSOCKET,
                                severity=Severity.MEDIUM,
                                title=f"WebSocket message injection ({ptype}) reflected",
                                description=f"WebSocket endpoint reflected injected {ptype} payload.",
                                target_url=ep.url,
                                confidence=0.75,
                                request_evidence=payload,
                                response_evidence=resp_str[:500],
                            ))
                    except Exception:
                        pass
        except Exception:
            pass
        return findings

    async def _socket_io_namespace_abuse(self, ep: WebSocketEndpoint) -> list[Finding]:
        """Test for unrestricted socket.io namespace access."""
        findings = []
        dangerous_namespaces = ["/admin", "/internal", "/debug", "/system"]
        try:
            import httpx
            base = ep.url.replace("ws://", "http://").replace("wss://", "https://")
            base = base.rstrip("/socket.io").rstrip("/ws")
            async with httpx.AsyncClient(timeout=5, verify=False) as client:
                for ns in dangerous_namespaces:
                    poll_url = f"{base}/socket.io/?EIO=4&transport=polling&nsp={ns}"
                    try:
                        r = await client.get(poll_url)
                        if r.status_code == 200 and "0{" in r.text:
                            findings.append(Finding(
                                module=self.name,
                                vuln_type=VulnType.WEBSOCKET,
                                severity=Severity.HIGH,
                                title=f"Socket.io namespace {ns!r} accessible without auth",
                                description=f"Privileged socket.io namespace {ns!r} accepted connection without authentication.",
                                target_url=ep.url + ns,
                                confidence=0.8,
                                remediation=f"Restrict access to {ns!r} namespace with middleware auth check.",
                                request_evidence=poll_url,
                                response_evidence=r.text[:200],
                            ))
                    except Exception:
                        pass
        except Exception:
            pass
        return findings
