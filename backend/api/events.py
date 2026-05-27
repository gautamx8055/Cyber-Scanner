"""
In-process pub/sub for live scan progress (Phase 6.3).

The background executor publishes JSON-able event dicts keyed by scan_id; each
connected WebSocket client holds one asyncio.Queue subscribed to that scan_id
and drains it. This is in-process only — fine for the single-worker dev server.
A multi-worker / multi-host deployment would swap this for Redis pub/sub
(Phase 11.4); the hub interface is intentionally small so that swap is local.
"""

import asyncio


class ScanEventHub:
    """Fan-out of progress events to per-scan subscribers."""

    def __init__(self) -> None:
        self._subscribers: dict[str, set[asyncio.Queue]] = {}

    def subscribe(self, scan_id: str) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue()
        self._subscribers.setdefault(scan_id, set()).add(queue)
        return queue

    def unsubscribe(self, scan_id: str, queue: asyncio.Queue) -> None:
        subscribers = self._subscribers.get(scan_id)
        if subscribers is None:
            return
        subscribers.discard(queue)
        if not subscribers:
            self._subscribers.pop(scan_id, None)

    def publish(self, scan_id: str, event: dict) -> None:
        """Fan `event` out to every subscriber of scan_id.

        Best-effort and non-blocking: with no subscribers it's a no-op (the DB
        row stays the source of truth). Queues are unbounded, so put_nowait
        never raises here.
        """
        for queue in tuple(self._subscribers.get(scan_id, ())):
            queue.put_nowait(event)


# Module-level singleton shared by the executor (producer) and the WebSocket
# route (consumers).
hub = ScanEventHub()
