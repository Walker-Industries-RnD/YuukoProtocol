"""
eclipse_client.py — Production IYuukoApi over the Eclipse RPC server
Python mirror of EclipseBroker.cs
Walker Industries R&D

Requires:  pip install httpx websockets
"""

from __future__ import annotations
import asyncio
import json
from typing import Callable, Awaitable, List

from .packet import YuukoPacket, YuukoFlags, PayloadType
from .api import IYuukoApi, Handler


class EclipseClient(IYuukoApi):
    """
    Production broker: delegates pub/sub to the C# Eclipse RPC server.
    Requires EclipseServer to be running (default port 5050).

    publish / request  → HTTP POST to /dirac/Yuuko*
    subscribe          → WebSocket to /subscribe/{topic}
    ping               → GET /health
    """

    def __init__(self, base_url: str = "http://localhost:5050"):
        self._base = base_url.rstrip("/")
        self._ws_base = (self._base
                         .replace("https://", "wss://")
                         .replace("http://",  "ws://"))
        self._subs:     dict[str, list[Handler]]  = {}
        self._ws_tasks: list[asyncio.Task]        = []
        self._closed    = False

        # lazy-import so the rest of the module works without httpx installed
        try:
            import httpx
            self._http = httpx.AsyncClient(base_url=self._base)
        except ImportError:
            self._http = None  # type: ignore

    # ── IYuukoApi ────────────────────────────────────────────────────────────

    async def publish(self, topic: str, packet: YuukoPacket) -> None:
        self._require_httpx()
        payload = {"topic": topic, "packet": packet.to_dict()}
        resp = await self._http.post("/dirac/YuukoPublish", json=payload)
        resp.raise_for_status()

    async def request(self, topic: str) -> List[YuukoPacket]:
        self._require_httpx()
        resp = await self._http.post("/dirac/YuukoRequest", json={"topic": topic})
        resp.raise_for_status()
        body = resp.json()
        return [YuukoPacket.from_dict(p) for p in (body.get("packets") or [])]

    async def subscribe(self, topic: str, handler: Handler) -> None:
        self._subs.setdefault(topic, []).append(handler)
        task = asyncio.create_task(self._listen_ws(topic))
        self._ws_tasks.append(task)

    async def unsubscribe(self, topic: str, handler: Handler) -> None:
        subs = self._subs.get(topic, [])
        self._subs[topic] = [h for h in subs if h is not handler]

    # ── Health ────────────────────────────────────────────────────────────────

    async def ping(self) -> bool:
        """Returns True if the Eclipse server is reachable."""
        if self._http is None:
            return False
        try:
            resp = await self._http.get("/health")
            return resp.is_success
        except Exception:
            return False

    # ── WebSocket listener ────────────────────────────────────────────────────

    async def _listen_ws(self, topic: str) -> None:
        try:
            import websockets
        except ImportError:
            return  # websockets not installed, skip silently

        from urllib.parse import quote
        uri = f"{self._ws_base}/subscribe/{quote(topic, safe='')}"

        while not self._closed:
            try:
                async with websockets.connect(uri) as ws:
                    async for raw in ws:
                        try:
                            packet = YuukoPacket.from_json(raw)
                        except Exception:
                            continue
                        for h in list(self._subs.get(topic, [])):
                            try:
                                await h(packet)
                            except Exception:
                                pass
            except asyncio.CancelledError:
                break
            except Exception:
                if self._closed:
                    break
                await asyncio.sleep(2)

    # ── Cleanup ───────────────────────────────────────────────────────────────

    async def close(self) -> None:
        self._closed = True
        for task in self._ws_tasks:
            task.cancel()
        if self._http is not None:
            await self._http.aclose()

    async def __aenter__(self): return self
    async def __aexit__(self, *_): await self.close()

    # ── Internals ─────────────────────────────────────────────────────────────

    def _require_httpx(self):
        if self._http is None:
            raise RuntimeError(
                "httpx is required for EclipseClient. "
                "Install it with: pip install httpx"
            )
