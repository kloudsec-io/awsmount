"""In-memory value cache for ``awsmount secrets``.

See ARCHITECTURE: awsmount secrets.

Values live only in ``bytearray`` objects inside this process. An entry
is overwritten with zeros when it expires, when it is dropped and when
the store is closed. This is best effort: the AWS response, the reading
process and the kernel page cache may hold other copies that this
module cannot reach.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Hashable
from dataclasses import dataclass

__all__ = ["ValueStore"]

REAP_INTERVAL = 5.0


@dataclass
class _Entry:
    data: bytearray
    expires: float
    fetched_at: float


def _wipe(data: bytearray) -> None:
    data[:] = bytes(len(data))


class ValueStore:
    """TTL cache of secret values held as wipeable ``bytearray``."""

    def __init__(self, ttl: float, *,
                 clock: Callable[[], float] = time.monotonic,
                 wall: Callable[[], float] = time.time,
                 reap_interval: float = REAP_INTERVAL) -> None:
        if ttl < 0:
            raise ValueError("ttl must be >= 0")
        self._ttl = ttl
        self._clock = clock
        self._wall = wall
        self._interval = reap_interval
        self._lock = threading.Lock()
        self._entries: dict[Hashable, _Entry] = {}
        self._denied: dict[Hashable, tuple[float, Exception]] = {}
        self._closed = False
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    @property
    def ttl(self) -> float:
        """Seconds a value is kept (0 = never kept)."""
        return self._ttl

    def get(self, key: Hashable) -> bytes | None:
        """A copy of the live value, or None (expired values are wiped)."""
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if self._clock() >= entry.expires:
                self._drop_locked(key)
                return None
            return bytes(entry.data)

    def fetched_at(self, key: Hashable) -> float | None:
        """Wall-clock time the live value was fetched, or None."""
        with self._lock:
            entry = self._entries.get(key)
            if entry is None or self._clock() >= entry.expires:
                return None
            return entry.fetched_at

    def size(self, key: Hashable) -> int | None:
        """Length of the live value without copying it, or None."""
        with self._lock:
            entry = self._entries.get(key)
            if entry is None or self._clock() >= entry.expires:
                return None
            return len(entry.data)

    def put(self, key: Hashable, value: bytes) -> None:
        """Keep ``value`` for the TTL (nothing is kept when TTL is 0)."""
        if self._ttl <= 0:
            return
        with self._lock:
            if self._closed:
                return
            self._drop_locked(key)
            self._entries[key] = _Entry(bytearray(value),
                                        self._clock() + self._ttl,
                                        self._wall())
            self._start_reaper_locked()

    def denied(self, key: Hashable) -> Exception | None:
        """The remembered refusal of ``key``, while it is still fresh."""
        with self._lock:
            found = self._denied.get(key)
            if found is None:
                return None
            if self._clock() >= found[0]:
                del self._denied[key]
                return None
            return found[1]

    def put_denied(self, key: Hashable, error: Exception,
                   ttl: float) -> None:
        """Remember that AWS refused ``key`` for ``ttl`` seconds.

        A client that retries a refused read (the macOS WebDAV client
        retries ten times) would otherwise make ten AWS calls and ten
        CloudTrail events. The error holds no value.
        """
        if ttl <= 0:
            return
        with self._lock:
            if not self._closed:
                self._denied[key] = (self._clock() + ttl, error)

    def discard(self, key: Hashable) -> None:
        """Wipe and forget one value."""
        with self._lock:
            self._drop_locked(key)
            self._denied.pop(key, None)

    def wipe_all(self) -> int:
        """Wipe and forget every value; return how many were held."""
        with self._lock:
            count = len(self._entries)
            for key in list(self._entries):
                self._drop_locked(key)
            self._denied.clear()
            return count

    def reap(self) -> int:
        """Wipe expired values; return how many were removed."""
        with self._lock:
            now = self._clock()
            expired = [k for k, e in self._entries.items()
                       if now >= e.expires]
            for key in expired:
                self._drop_locked(key)
            return len(expired)

    def close(self) -> None:
        """Stop the reaper and wipe everything; later puts are ignored."""
        with self._lock:
            self._closed = True
        self._stop.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)
        self.wipe_all()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def _drop_locked(self, key: Hashable) -> None:
        entry = self._entries.pop(key, None)
        if entry is not None:
            _wipe(entry.data)

    def _start_reaper_locked(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run, name="awsmount-secrets-reaper", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        interval = max(0.05, min(self._interval, self._ttl / 2 or 1.0))
        while not self._stop.wait(interval):
            self.reap()
