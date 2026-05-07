"""Minimal Interactsh HTTP poll client."""
import time
from typing import Optional
import httpx


class InteractshClient:
    def __init__(self, base_url: str) -> None:
        self._base = base_url.rstrip("/")

    async def start(self) -> None: pass
    async def stop(self) -> None: pass

    def alloc(self, token: str) -> str:
        return f"{self._base}/c/{token}"

    async def poll(self, token: str) -> Optional[object]:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"{self._base}/poll", params={"id": token})
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("data"):
                        from .server import CallbackEvent
                        return CallbackEvent(
                            token=token,
                            received_at=time.time(),
                            source_ip=data.get("remote-address", ""),
                            protocol=data.get("protocol", "http"),
                            data=data,
                        )
        except Exception:
            pass
        return None
