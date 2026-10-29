"""TTLCache: TTL, LRU, single-flight, negative caching.

See ARCHITECTURE: Cache.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

import pytest

from awsmount.errors import BudgetExceeded, PermissionDenied
from awsmount.errors import UpstreamError
from awsmount.session.cache import TTLCache
from awsmount.session.context import Context, Scope


def _wait_for(predicate: Callable[[], bool], timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("condition not reached in time")
        time.sleep(0.005)


def _counter(value: Any = "v") -> tuple[list[int], Callable[[], Any]]:
    calls: list[int] = []

    def loader() -> Any:
        calls.append(1)
        return value

    return calls, loader


def test_caches_within_ttl(clock: Any) -> None:
    """Second get within TTL is a hit; loader runs once."""
    cache = TTLCache(60, clock=clock)
    calls, loader = _counter()
    assert cache.get_or_load("k", loader) == "v"
    clock.advance(59.9)
    assert cache.get_or_load("k", loader) == "v"
    assert calls == [1]
    stats = cache.stats()
    assert stats.misses == 1
    assert stats.hits == 1
    assert stats.entries == 1


def test_expires_after_ttl(clock: Any) -> None:
    """After the TTL the loader runs again."""
    cache = TTLCache(60, clock=clock)
    calls, loader = _counter()
    cache.get_or_load("k", loader)
    clock.advance(60.1)
    cache.get_or_load("k", loader)
    assert len(calls) == 2


def test_per_call_ttl_override(clock: Any) -> None:
    """An explicit ttl argument wins over the default."""
    cache = TTLCache(60, clock=clock)
    calls, loader = _counter()
    cache.get_or_load("k", loader, ttl=5)
    clock.advance(6)
    cache.get_or_load("k", loader, ttl=5)
    assert len(calls) == 2


def test_falsy_values_cached(clock: Any) -> None:
    """None/empty results are cached like any other value."""
    cache = TTLCache(60, clock=clock)
    for key, value in (("none", None), ("zero", 0), ("empty", {})):
        calls, loader = _counter(value)
        assert cache.get_or_load(key, loader) == value
        assert cache.get_or_load(key, loader) == value
        assert calls == [1]


def test_lru_eviction(clock: Any) -> None:
    """Least-recently-used entry is evicted past max_entries."""
    cache = TTLCache(60, max_entries=2, clock=clock)
    cache.get_or_load("a", lambda: 1)
    cache.get_or_load("b", lambda: 2)
    cache.get_or_load("a", lambda: 99)
    cache.get_or_load("c", lambda: 3)
    assert cache.peek("b") is None
    assert cache.peek("a") == 1
    assert cache.peek("c") == 3
    stats = cache.stats()
    assert stats.evictions == 1
    assert stats.entries == 2


def test_peek_never_loads(clock: Any) -> None:
    """peek returns fresh values only and never calls a loader."""
    cache = TTLCache(60, clock=clock)
    assert cache.peek("k") is None
    cache.get_or_load("k", lambda: "v")
    assert cache.peek("k") == "v"
    clock.advance(61)
    assert cache.peek("k") is None


def test_fetched_at_is_wallclock(clock: Any) -> None:
    """fetched_at reports the wall clock at load time."""
    cache = TTLCache(60, clock=clock, wallclock=lambda: 1234.5)
    assert cache.fetched_at("k") is None
    cache.get_or_load("k", lambda: 1)
    assert cache.fetched_at("k") == 1234.5


def test_invalidate(clock: Any) -> None:
    """invalidate drops matching entries and returns the count."""
    cache = TTLCache(60, clock=clock)
    for region in ("r1", "r1", "r2"):
        cache.get_or_load(("p", region, "ec2", len(cache)), lambda: 1)
    assert cache.invalidate(lambda k: k[1] == "r1") == 2
    assert len(cache) == 1
    assert cache.invalidate() == 1
    assert len(cache) == 0


def test_single_flight_twenty_threads() -> None:
    """20 concurrent identical loads: 1 loader call, 19 coalesced."""
    cache = TTLCache(60)
    started = threading.Event()
    release = threading.Event()
    sentinel = object()
    calls: list[int] = []
    results: list[Any] = []
    lock = threading.Lock()

    def loader() -> object:
        calls.append(1)
        started.set()
        release.wait(5)
        return sentinel

    def worker() -> None:
        value = cache.get_or_load("k", loader)
        with lock:
            results.append(value)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    assert started.wait(5)
    _wait_for(lambda: cache.stats().coalesced == 19)
    release.set()
    for t in threads:
        t.join(5)
        assert not t.is_alive()
    assert calls == [1]
    assert len(results) == 20
    assert all(r is sentinel for r in results)
    assert cache.stats().coalesced == 19


def test_exception_fans_out_to_waiters() -> None:
    """Waiters receive the very same exception as the leader."""
    cache = TTLCache(60)
    started = threading.Event()
    release = threading.Event()
    boom = ValueError("boom")
    caught: list[BaseException] = []
    lock = threading.Lock()

    def loader() -> None:
        started.set()
        release.wait(5)
        raise boom

    def worker() -> None:
        try:
            cache.get_or_load("k", loader)
        except ValueError as exc:
            with lock:
                caught.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    assert started.wait(5)
    _wait_for(lambda: cache.stats().coalesced == 4)
    release.set()
    for t in threads:
        t.join(5)
    assert len(caught) == 5
    assert all(exc is boom for exc in caught)


def test_ttl_zero_no_storage_but_coalesces() -> None:
    """ttl=0: nothing stored, concurrent loads still coalesce."""
    cache = TTLCache(0)
    started = threading.Event()
    release = threading.Event()
    calls: list[int] = []

    def loader() -> str:
        calls.append(1)
        started.set()
        release.wait(5)
        return "v"

    threads = [threading.Thread(target=cache.get_or_load,
                                args=("k", loader)) for _ in range(5)]
    for t in threads:
        t.start()
    assert started.wait(5)
    _wait_for(lambda: cache.stats().coalesced == 4)
    release.set()
    for t in threads:
        t.join(5)
    assert calls == [1]
    assert len(cache) == 0
    release.set()
    cache.get_or_load("k", loader)
    assert len(calls) == 2


def test_negative_caching_upstream(clock: Any) -> None:
    """UpstreamError is cached for negative_ttl, then retried."""
    cache = TTLCache(60, negative_ttl=10, clock=clock)
    calls: list[int] = []
    err = UpstreamError("down", code="X", kind="other")

    def loader() -> None:
        calls.append(1)
        raise err

    with pytest.raises(UpstreamError):
        cache.get_or_load("k", loader)
    clock.advance(9)
    with pytest.raises(UpstreamError) as info:
        cache.get_or_load("k", loader)
    assert info.value is err
    assert calls == [1]
    assert cache.stats().negative == 1
    assert cache.peek("k") is None
    clock.advance(1.5)
    with pytest.raises(UpstreamError):
        cache.get_or_load("k", loader)
    assert len(calls) == 2


def test_negative_caching_permission_denied(clock: Any) -> None:
    """PermissionDenied is negatively cached too."""
    cache = TTLCache(60, negative_ttl=10, clock=clock)
    calls: list[int] = []

    def loader() -> None:
        calls.append(1)
        raise PermissionDenied("nope", code="AccessDenied",
                               kind="access-denied")

    for _ in range(3):
        with pytest.raises(PermissionDenied):
            cache.get_or_load("k", loader)
    assert calls == [1]


def test_budget_errors_never_cached(clock: Any) -> None:
    """BudgetExceeded is never cached."""
    cache = TTLCache(60, negative_ttl=10, clock=clock)
    calls: list[int] = []

    def loader() -> None:
        calls.append(1)
        raise BudgetExceeded("budget")

    for _ in range(3):
        with pytest.raises(BudgetExceeded):
            cache.get_or_load("k", loader)
    assert len(calls) == 3
    assert cache.stats().negative == 0


def test_failure_does_not_block_other_keys(clock: Any) -> None:
    """A failing key leaves other keys usable."""
    cache = TTLCache(60, clock=clock)

    def bad() -> None:
        raise RuntimeError("x")

    with pytest.raises(RuntimeError):
        cache.get_or_load("bad", bad)
    assert cache.get_or_load("good", lambda: 1) == 1


def test_nested_load_does_not_deadlock() -> None:
    """Loaders run outside the lock and may use the cache."""
    cache = TTLCache(60)
    out: list[Any] = []

    def outer() -> Any:
        return cache.get_or_load("inner", lambda: "in") + "-out"

    t = threading.Thread(
        target=lambda: out.append(cache.get_or_load("outer", outer)))
    t.start()
    t.join(5)
    assert not t.is_alive()
    assert out == ["in-out"]


def test_context_call_key_ignores_param_order(ctx: Context,
                                              scope: Scope,
                                              backend: Any) -> None:
    """Cache key uses canonical params; one backend call."""
    a = ctx.call(scope, "fake", "get_widget_details", Id="w-1",
                 Extra="x")
    b = ctx.call(scope, "fake", "get_widget_details", Extra="x",
                 Id="w-1")
    assert a == b
    assert backend.count("fake", "get_widget_details") == 1
    ctx.call(scope, "fake", "get_widget_details", Id="w-2")
    assert backend.count("fake", "get_widget_details") == 2
