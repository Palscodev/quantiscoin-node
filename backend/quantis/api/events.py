"""Thread-safe fan-out of node events to Server-Sent-Event subscribers."""
from __future__ import annotations

import asyncio
import json
import threading
import time


class EventBus:
    def __init__(self) -> None:
        self._subs: set[tuple[asyncio.AbstractEventLoop, asyncio.Queue]] = set()
        self._lock = threading.Lock()
        self.counter = 0

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        with self._lock:
            self._subs.add((asyncio.get_running_loop(), q))
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        with self._lock:
            self._subs = {s for s in self._subs if s[1] is not q}

    @staticmethod
    def _put(q: asyncio.Queue, item: str) -> None:
        if q.full():
            try:
                q.get_nowait()  # drop the oldest event for slow consumers
            except asyncio.QueueEmpty:
                pass
        q.put_nowait(item)

    def publish(self, kind: str, data) -> None:
        self.counter += 1
        payload = f"event: {kind}\ndata: {json.dumps({'t': time.time(), 'data': data})}\n\n"
        with self._lock:
            subs = list(self._subs)
        for loop, q in subs:
            try:
                loop.call_soon_threadsafe(self._put, q, payload)
            except RuntimeError:
                self.unsubscribe(q)  # loop closed
