"""In-memory log store with live subscribers and aggregate statistics.

The Docker tailer runs in a plain thread while FastAPI serves from an
asyncio event loop. The store bridges the two: the thread appends entries
and the store fans them out to per-client asyncio queues via
`loop.call_soon_threadsafe`.
"""

import asyncio
import threading
from collections import deque
from datetime import datetime, timedelta, timezone

from app.config import settings
from app.parser import LogEntry


class LogStore:
    """Ring buffer of parsed log entries plus SSE subscriber fan-out."""

    def __init__(self, maxlen: int | None = None) -> None:
        self._entries: deque[LogEntry] = deque(maxlen=maxlen or settings.log_history)
        self._lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._subscribers: set[asyncio.Queue] = set()
        self._seen: set[tuple[str, str]] = set()
        self._seen_order: deque[tuple[str, str]] = deque(maxlen=settings.log_history)
        self.connected: bool = False
        self.container_name: str = ""

    def attach_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Register the serving event loop (called once at startup)."""
        self._loop = loop

    # ------------------------------------------------------------------
    # Writing (called from the tailer thread)
    # ------------------------------------------------------------------

    def add(self, entry: LogEntry) -> bool:
        """Append an entry, skipping duplicates seen across reconnects.

        Returns True when the entry was new (and fanned out to clients).
        """
        key = (entry.ts.isoformat(), entry.raw or entry.msg)
        with self._lock:
            if key in self._seen:
                return False
            if len(self._seen_order) == self._seen_order.maxlen:
                self._seen.discard(self._seen_order[0])
            self._seen.add(key)
            self._seen_order.append(key)
            self._entries.append(entry)

        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._fanout, entry)
        return True

    def _fanout(self, entry: LogEntry) -> None:
        """Push an entry to every connected SSE client (loop thread only)."""
        for queue in list(self._subscribers):
            if queue.full():
                continue  # slow client: drop rather than block everyone
            queue.put_nowait(entry)

    # ------------------------------------------------------------------
    # Reading (called from request handlers)
    # ------------------------------------------------------------------

    def subscribe(self) -> asyncio.Queue:
        """Create a queue receiving all future entries."""
        queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers.discard(queue)

    def entries(
        self,
        level: str = "",
        query: str = "",
        limit: int = 500,
    ) -> list[LogEntry]:
        """Return the newest entries first, optionally filtered."""
        with self._lock:
            snapshot = list(self._entries)

        if level:
            wanted = {level}
            if level == "error":
                wanted |= {"fatal", "panic"}
            snapshot = [e for e in snapshot if e.level in wanted]
        if query:
            needle = query.lower()
            snapshot = [
                e
                for e in snapshot
                if needle in e.msg.lower()
                or any(needle in v.lower() for v in e.fields.values())
            ]
        return list(reversed(snapshot[-limit:]))

    def stats(self) -> dict:
        """Aggregate numbers for the dashboard header and stat tiles."""
        with self._lock:
            snapshot = list(self._entries)

        now = datetime.now(timezone.utc)
        day_ago = now - timedelta(hours=24)

        last_session: LogEntry | None = None
        updates_24h = 0
        failures_24h = 0
        errors_24h = 0
        recent_updates: list[dict] = []

        for entry in snapshot:
            if entry.msg == "Session done":
                last_session = entry
                if entry.ts >= day_ago:
                    updates_24h += _int_field(entry, "Updated")
                    failures_24h += _int_field(entry, "Failed")
            elif entry.msg.startswith("Found new "):
                recent_updates.append({"ts": entry.ts.isoformat(), "msg": entry.msg})
            if entry.level in ("warning", "error", "fatal", "panic") and entry.ts >= day_ago:
                errors_24h += 1

        next_check = None
        if last_session is not None:
            next_check = last_session.ts + timedelta(seconds=settings.scan_interval_seconds)

        return {
            "connected": self.connected,
            "container": self.container_name,
            "host": settings.host_label,
            "interval_seconds": settings.scan_interval_seconds,
            "last_session_at": last_session.ts.isoformat() if last_session else None,
            "next_check_at": next_check.isoformat() if next_check else None,
            "scanned": _int_field(last_session, "Scanned") if last_session else 0,
            "updates_24h": updates_24h,
            "failures_24h": failures_24h,
            "errors_24h": errors_24h,
            "recent_updates": recent_updates[-10:][::-1],
            "entry_count": len(snapshot),
            "ntfy_topic": settings.ntfy_topic,
            "ntfy_url": settings.ntfy_url,
        }


def _int_field(entry: LogEntry | None, key: str) -> int:
    """Read an integer logrus field, defaulting to 0."""
    if entry is None:
        return 0
    try:
        return int(entry.fields.get(key, "0"))
    except ValueError:
        return 0


store = LogStore()
