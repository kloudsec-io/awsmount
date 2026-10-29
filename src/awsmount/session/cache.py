"""Thread-safe TTL cache with single-flight loading (ARCHITECTURE: Cache)."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Hashable
from dataclasses import dataclass
from typing import Any, TypeVar, cast

from awsmount.errors import UpstreamError

__all__ = ["CacheStats", "TTLCache"]

T = TypeVar("T")


@dataclass(frozen=True)
class CacheStats:
    """Counters describing cache behaviour."""

    hits: int
    misses: int
    coalesced: int
    entries: int
    evictions: int
    negative: int


class _Entry:
    __slots__ = ("value", "error", "expires", "fetched_at")

    def __init__(self, value: Any, error: BaseException | None,
                 expires: float, fetched_at: float) -> None:
        self.value = value
        self.error = error
        self.expires = expires
        self.fetched_at = fetched_at


class _Flight:
    __slots__ = ("event", "value", "error")

    def __init__(self) -> None:
        self.event = threading.Event()
        self.value: Any = None
        self.error: BaseException | None = None


class TTLCache:
    """LRU + TTL cache; identical concurrent loads run once."""

    def __init__(self, ttl: float, *, negative_ttl: float = 10.0,
                 max_entries: int = 50_000,
                 clock: Callable[[], float] = time.monotonic,
                 wallclock: Callable[[], float] = time.time) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be >= 1")
        self._ttl = ttl
        self._negative_ttl = negative_ttl
        self._max = max_entries
        self._clock = clock
        self._wall = wallclock
        self._lock = threading.Lock()
        self._data: OrderedDict[Hashable, _Entry] = OrderedDict()
        self._flights: dict[Hashable, _Flight] = {}
        self._hits = 0
        self._misses = 0
        self._coalesced = 0
        self._evictions = 0
        self._negative = 0

    def _lookup(self, key: Hashable) -> _Entry | None:
        entry = self._data.get(key)
        if entry is None:
            return None
        if self._clock() >= entry.expires:
            del self._data[key]
            return None
        self._data.move_to_end(key)
        return entry

    def _store(self, key: Hashable, entry: _Entry) -> None:
        self._data[key] = entry
        self._data.move_to_end(key)
        while len(self._data) > self._max:
            self._data.popitem(last=False)
            self._evictions += 1

    def get_or_load(self, key: Hashable, loader: Callable[[], T],
                    ttl: float | None = None) -> T:
        """Return the cached value or run ``loader`` once for all callers.

        ``PermissionDenied``/``UpstreamError`` are cached for
        ``negative_ttl``; other errors (incl. ``BudgetExceeded``) are not.
        """
        lifetime = self._ttl if ttl is None else ttl
        with self._lock:
            entry = self._lookup(key)
            if entry is not None:
                self._hits += 1
                if entry.error is not None:
                    raise entry.error
                return cast(T, entry.value)
            flight = self._flights.get(key)
            leader = flight is None
            if flight is None:
                flight = _Flight()
                self._flights[key] = flight
                self._misses += 1
            else:
                self._coalesced += 1
        if not leader:
            flight.event.wait()
            if flight.error is not None:
                raise flight.error
            return cast(T, flight.value)
        try:
            value = loader()
        except BaseException as exc:
            self._finish_error(key, flight, exc)
            raise
        self._finish_value(key, flight, value, lifetime)
        return value

    def _finish_error(self, key: Hashable, flight: _Flight,
                      exc: BaseException) -> None:
        with self._lock:
            flight.error = exc
            self._flights.pop(key, None)
            if isinstance(exc, UpstreamError) and self._negative_ttl > 0:
                self._store(key, _Entry(None, exc,
                                        self._clock() + self._negative_ttl,
                                        self._wall()))
                self._negative += 1
        flight.event.set()

    def _finish_value(self, key: Hashable, flight: _Flight, value: Any,
                      lifetime: float) -> None:
        with self._lock:
            flight.value = value
            self._flights.pop(key, None)
            if lifetime > 0:
                self._store(key, _Entry(value, None,
                                        self._clock() + lifetime,
                                        self._wall()))
        flight.event.set()

    def peek(self, key: Hashable) -> Any:
        """Return a fresh cached value without loading (None if absent)."""
        with self._lock:
            entry = self._lookup(key)
            if entry is None or entry.error is not None:
                return None
            return entry.value

    def fetched_at(self, key: Hashable) -> float | None:
        """Wall-clock fetch time of a fresh entry."""
        with self._lock:
            entry = self._lookup(key)
            return entry.fetched_at if entry is not None else None

    def invalidate(self, predicate: Callable[[Hashable], bool]
                   | None = None) -> int:
        """Drop entries matching ``predicate`` (all if None)."""
        with self._lock:
            if predicate is None:
                count = len(self._data)
                self._data.clear()
                return count
            doomed = [k for k in self._data if predicate(k)]
            for key in doomed:
                del self._data[key]
            return len(doomed)

    def stats(self) -> CacheStats:
        """Return current counters."""
        with self._lock:
            return CacheStats(hits=self._hits, misses=self._misses,
                              coalesced=self._coalesced,
                              entries=len(self._data),
                              evictions=self._evictions,
                              negative=self._negative)

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)
