"""Per-service and global concurrency limits.

See ARCHITECTURE: Budget and limits.
"""

from __future__ import annotations

import errno
import threading
import time

import pytest

from awsmount.errors import UpstreamError
from awsmount.session.limiter import Limiter


def _meet(limiter: Limiter, services: list[str],
          timeout: float = 0.5) -> list[str]:
    """Each thread holds a slot and waits at a barrier of all threads.

    Returns the services whose threads passed the barrier: all of them
    when the limiter lets every thread in at once, none otherwise.
    """
    barrier = threading.Barrier(len(services), timeout=timeout)
    passed: list[str] = []
    lock = threading.Lock()

    def worker(service: str) -> None:
        with limiter.slot(service):
            try:
                barrier.wait()
            except threading.BrokenBarrierError:
                return
            with lock:
                passed.append(service)

    threads = [threading.Thread(target=worker, args=(s,))
               for s in services]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
        assert not t.is_alive()
    return passed


def test_per_service_cap_blocks_extra_threads() -> None:
    """per_service=2: three same-service threads never coexist."""
    assert _meet(Limiter(2, 16), ["ec2"] * 3) == []


def test_per_service_cap_allows_up_to_limit() -> None:
    """per_service=3: three same-service threads coexist."""
    assert len(_meet(Limiter(3, 16), ["ec2"] * 3)) == 3


def test_services_are_independent() -> None:
    """Different services do not share a per-service slot."""
    passed = _meet(Limiter(1, 16), ["ec2", "s3", "sqs"])
    assert sorted(passed) == ["ec2", "s3", "sqs"]


def test_global_cap() -> None:
    """global_limit=2 caps across services."""
    assert _meet(Limiter(5, 2), ["ec2", "s3", "sqs"]) == []
    assert len(_meet(Limiter(5, 3), ["ec2", "s3", "sqs"])) == 3


def _hold(limiter: Limiter, service: str
          ) -> tuple[threading.Thread, threading.Event]:
    entered = threading.Event()
    release = threading.Event()

    def holder() -> None:
        with limiter.slot(service):
            entered.set()
            release.wait(10)

    t = threading.Thread(target=holder)
    t.start()
    assert entered.wait(5)
    return t, release


def test_timeout_raises_upstream_error() -> None:
    """Acquisition timeout -> UpstreamError('concurrency ...')."""
    limiter = Limiter(1, 16, timeout=0.2)
    thread, release = _hold(limiter, "ec2")
    start = time.monotonic()
    with pytest.raises(UpstreamError) as info:
        with limiter.slot("ec2"):
            pass
    assert time.monotonic() - start < 2.0
    assert "concurrency limiter timeout" in str(info.value)
    assert info.value.errno == errno.EIO
    release.set()
    thread.join(5)
    with limiter.slot("ec2"):
        pass


def test_global_timeout_does_not_leak_service_slot() -> None:
    """A global-slot timeout releases the per-service slot."""
    limiter = Limiter(1, 1, timeout=0.2)
    thread, release = _hold(limiter, "ec2")
    with pytest.raises(UpstreamError):
        with limiter.slot("s3"):
            pass
    release.set()
    thread.join(5)
    for _ in range(2):
        with limiter.slot("s3"):
            pass


def test_exception_in_body_releases() -> None:
    """Slots are released when the body raises."""
    limiter = Limiter(1, 1, timeout=0.2)
    with pytest.raises(RuntimeError):
        with limiter.slot("ec2"):
            raise RuntimeError("boom")
    with limiter.slot("ec2"):
        pass
    with limiter.slot("s3"):
        pass


def test_invalid_limits() -> None:
    """Limits below 1 are rejected."""
    with pytest.raises(ValueError):
        Limiter(0, 1)
    with pytest.raises(ValueError):
        Limiter(1, 0)
