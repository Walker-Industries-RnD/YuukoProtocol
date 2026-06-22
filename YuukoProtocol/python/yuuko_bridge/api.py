"""
api.py — IYuukoApi contract + LocalBroker
Python mirror of IYuukoApi.cs (LocalBroker section)
Walker Industries R&D
"""

from __future__ import annotations
import asyncio
from abc import ABC, abstractmethod
from typing import Callable, Awaitable, List
from .packet import YuukoPacket, YuukoFlags


# ── IYuukoApi ─────────────────────────────────────────────────────────────────

Handler = Callable[[YuukoPacket], Awaitable[None]]


class IYuukoApi(ABC):
    @abstractmethod
    async def publish(self, topic: str, packet: YuukoPacket) -> None: ...

    @abstractmethod
    async def request(self, topic: str) -> List[YuukoPacket]: ...

    @abstractmethod
    async def subscribe(self, topic: str, handler: Handler) -> None: ...

    @abstractmethod
    async def unsubscribe(self, topic: str, handler: Handler) -> None: ...

    async def tombstone(self, topic: str, name: str) -> None:
        """Convenience: publish a tombstone (delete signal) for a named packet."""
        await self.publish(topic, YuukoPacket(
            name=name, type=__import__("yuuko_bridge.packet", fromlist=["PayloadType"]).PayloadType.BYTES,
            data=b"", flags=[YuukoFlags.TOMBSTONE]
        ))


# ── LocalBroker ───────────────────────────────────────────────────────────────

class LocalBroker(IYuukoApi):
    """
    In-process pub/sub broker. Zero network dependency.
    Thread-safe via asyncio.Lock. Swap for EclipseClient in production.
    """

    def __init__(self):
        self._lock   = asyncio.Lock()
        self._store: dict[str, list[YuukoPacket]] = {}
        self._subs:  dict[str, list[Handler]]     = {}

    async def publish(self, topic: str, packet: YuukoPacket) -> None:
        async with self._lock:
            store = self._store.setdefault(topic, [])

            if packet.is_tombstone():
                self._store[topic] = [p for p in store if p.name != packet.name]
            else:
                self._store[topic] = [p for p in store if p.name != packet.name]
                if not packet.is_ephemeral():
                    self._store[topic].append(packet)

            handlers = list(self._subs.get(topic, []))

        for h in handlers:
            try:
                await h(packet)
            except Exception:
                pass  # isolate faults per handler

    async def request(self, topic: str) -> List[YuukoPacket]:
        async with self._lock:
            return list(self._store.get(topic, []))

    async def subscribe(self, topic: str, handler: Handler) -> None:
        async with self._lock:
            self._subs.setdefault(topic, []).append(handler)

    async def unsubscribe(self, topic: str, handler: Handler) -> None:
        async with self._lock:
            subs = self._subs.get(topic, [])
            self._subs[topic] = [h for h in subs if h is not handler]

    def clear(self) -> None:
        self._store.clear()
        self._subs.clear()
