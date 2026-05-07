"""Local TCP server for OOB (out-of-band) SSRF callback detection."""
import asyncio
import os
import secrets
import socket
import time
from dataclasses import dataclass, field


@dataclass
class CallbackEvent:
    token: str
    received_at: float
    source_ip: str
    protocol: str
    data: dict = field(default_factory=dict)


class OOBCallbackServer:
    """Asyncio TCP listener that catches OOB HTTP callbacks.

    Falls back to Interactsh when INTERACTSH_URL env var is set.
    Use as async context manager.
    """

    @staticmethod
    def _validate_interactsh_url(url: str) -> None:
        """Reject attacker-controlled INTERACTSH_URL values at startup."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise ValueError(f"INTERACTSH_URL must use https://, got: {url!r}")
        if not parsed.netloc or parsed.netloc.startswith("localhost") or parsed.netloc.startswith("127."):
            raise ValueError(f"INTERACTSH_URL must not be localhost: {url!r}")

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        if os.getenv("INTERACTSH_URL"):
            interactsh_url = os.environ["INTERACTSH_URL"]
            self._validate_interactsh_url(interactsh_url)
            from .interactsh import InteractshClient
            self._impl: InteractshClient | None = InteractshClient(interactsh_url)
            self._mode = "interactsh"
        else:
            self._impl = None
            self._mode = "local"
        self.host = host
        self.port = port
        self._events: dict[str, list[CallbackEvent]] = {}
        self._server: asyncio.base_events.Server | None = None
        self._serve_task: asyncio.Task | None = None
        self._MAX_TOKENS = 1_000  # cap dict size to bound memory usage

    async def __aenter__(self) -> "OOBCallbackServer":
        if self._mode == "local":
            self._server = await asyncio.start_server(
                self._handle_conn, self.host, self.port
            )
            self.port = self._server.sockets[0].getsockname()[1]
            self._serve_task = asyncio.create_task(self._server.serve_forever())
        else:
            await self._impl.start()  # type: ignore[union-attr]
        return self

    async def __aexit__(self, *_exc) -> None:
        if self._mode == "local" and self._server:
            self._server.close()
            await self._server.wait_closed()
            if self._serve_task:
                self._serve_task.cancel()
        elif self._impl:
            await self._impl.stop()

    def alloc_url(self, token: str | None = None) -> str:
        token = token or secrets.token_hex(8)
        if self._mode == "interactsh":
            return self._impl.alloc(token)  # type: ignore[union-attr]
        host = self.host if self.host not in ("0.0.0.0", "") else socket.getfqdn()
        return f"http://{host}:{self.port}/{token}"

    async def _handle_conn(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        try:
            raw = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            line = raw.split(b"\r\n", 1)[0].decode("ascii", "replace")
            parts = line.split(" ")
            if len(parts) >= 2 and len(self._events) < self._MAX_TOKENS:
                token = parts[1].strip("/").split("/")[0][:64]  # bound token length
                evt = CallbackEvent(
                    token=token,
                    received_at=time.time(),
                    source_ip=peer[0] if peer else "",
                    protocol="http",
                    data={"method": parts[0], "raw_request": line[:512]},
                )
                self._events.setdefault(token, []).append(evt)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    async def wait_for_callback(
        self, token: str, timeout: float = 30.0
    ) -> CallbackEvent | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._mode == "interactsh":
                evt = await self._impl.poll(token)  # type: ignore[union-attr]
                if evt:
                    return evt
            else:
                if self._events.get(token):
                    return self._events[token][0]
            await asyncio.sleep(0.25)
        return None
