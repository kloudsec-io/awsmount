"""The in-memory value store: TTL, overwrite on drop, no persistence."""

from __future__ import annotations

import threading
from collections.abc import Iterator

import pytest

from awsmount.secrets.store import ValueStore


class Clock:
    """Manually advanced monotonic and wall clocks."""

    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


_OPENED: list[ValueStore] = []


@pytest.fixture(autouse=True)
def _close_stores() -> Iterator[None]:
    """Stop the reaper thread of every store a test opened."""
    yield
    while _OPENED:
        _OPENED.pop().close()


def make(ttl: float = 10.0) -> tuple[ValueStore, Clock]:
    clock = Clock()
    store = ValueStore(ttl, clock=clock, wall=clock)
    _OPENED.append(store)
    return store, clock


def held(store: ValueStore, key: str) -> bytearray:
    """The live buffer of ``key`` (white box: to check it is wiped)."""
    return store._entries[key].data


def test_put_get_returns_a_copy() -> None:
    store, _clock = make()
    store.put("k", b"CANARY")
    first = store.get("k")
    assert first == b"CANARY"
    assert isinstance(first, bytes)
    assert store.size("k") == 6
    assert store.get("missing") is None


def test_value_expires_after_ttl_and_is_wiped() -> None:
    store, clock = make(10.0)
    store.put("k", b"CANARY")
    buf = held(store, "k")
    clock.now += 9.9
    assert store.get("k") == b"CANARY"
    clock.now += 0.2
    assert store.get("k") is None
    assert bytes(buf) == bytes(6)
    assert len(store) == 0


def test_reap_wipes_expired_values_nobody_reads_again() -> None:
    store, clock = make(10.0)
    store.put("a", b"AAAA")
    store.put("b", b"BBBB")
    buf = held(store, "a")
    clock.now += 11
    assert store.reap() == 2
    assert bytes(buf) == bytes(4)
    assert len(store) == 0


def test_discard_wipes_one_value() -> None:
    store, _clock = make()
    store.put("a", b"AAAA")
    store.put("b", b"BBBB")
    buf = held(store, "a")
    store.discard("a")
    assert bytes(buf) == bytes(4)
    assert store.get("a") is None
    assert store.get("b") == b"BBBB"


def test_put_over_a_live_key_wipes_the_old_buffer() -> None:
    store, _clock = make()
    store.put("a", b"OLD1")
    old = held(store, "a")
    store.put("a", b"NEW22")
    assert bytes(old) == bytes(4)
    assert store.get("a") == b"NEW22"


def test_wipe_all_and_close_overwrite_everything() -> None:
    store, _clock = make()
    for key in "abc":
        store.put(key, key.encode() * 8)
    bufs = [held(store, key) for key in "abc"]
    assert store.wipe_all() == 3
    assert all(bytes(b) == bytes(8) for b in bufs)
    store.put("d", b"DDDD")
    buf = held(store, "d")
    store.close()
    assert bytes(buf) == bytes(4)
    store.put("e", b"EEEE")
    assert store.get("e") is None


def test_ttl_zero_keeps_nothing() -> None:
    store, _clock = make(0.0)
    store.put("k", b"CANARY")
    assert store.get("k") is None
    assert len(store) == 0
    assert store.size("k") is None


def test_negative_ttl_is_refused() -> None:
    with pytest.raises(ValueError):
        ValueStore(-1)


def test_fetched_at_is_the_wall_time_of_the_put() -> None:
    store, clock = make()
    store.put("k", b"x")
    assert store.fetched_at("k") == clock.now
    assert store.fetched_at("missing") is None


def test_reaper_thread_wipes_an_expired_value_by_itself() -> None:
    store = ValueStore(0.2, reap_interval=0.05)
    try:
        store.put("k", b"CANARY")
        buf = held(store, "k")
        done = threading.Event()

        def wait() -> None:
            for _ in range(100):
                if bytes(buf) == bytes(6):
                    done.set()
                    return
                done.wait(0.05)

        wait()
        assert bytes(buf) == bytes(6)
        assert len(store) == 0
    finally:
        store.close()


def test_close_stops_the_reaper_thread() -> None:
    store = ValueStore(5.0, reap_interval=0.05)
    store.put("k", b"x")
    thread = store._thread
    assert thread is not None and thread.is_alive()
    store.close()
    assert not thread.is_alive()


def test_a_refusal_is_remembered_for_its_ttl_only() -> None:
    store, clock = make()
    err = PermissionError("no")
    store.put_denied("k", err, 10.0)
    assert store.denied("k") is err
    clock.now += 11
    assert store.denied("k") is None


def test_a_refusal_needs_a_ttl_and_goes_with_a_wipe() -> None:
    store, _clock = make()
    store.put_denied("k", PermissionError("no"), 0.0)
    assert store.denied("k") is None
    store.put_denied("k", PermissionError("no"), 10.0)
    store.wipe_all()
    assert store.denied("k") is None
