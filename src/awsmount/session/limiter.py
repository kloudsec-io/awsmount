"""Per-service and global concurrency limits.

See ARCHITECTURE: Budget and limits.
"""

from __future__ import annotations

import contextlib
import threading
import time
from collections.abc import Iterator

from awsmount.errors import UpstreamError

__all__ = ["Limiter"]

TIMEOUT_MESSAGE = "concurrency limiter timeout"


class Limiter:
    """Bounded semaphores per boto3 service plus one global semaphore."""

    def __init__(self, per_service: int, global_limit: int,
                 timeout: float = 120.0) -> None:
        if per_service < 1 or global_limit < 1:
            raise ValueError("limits must be >= 1")
        self._per_service = per_service
        self._timeout = timeout
        self._global = threading.BoundedSemaphore(global_limit)
        self._lock = threading.Lock()
        self._sems: dict[str, threading.BoundedSemaphore] = {}

    def _semaphore(self, service: str) -> threading.BoundedSemaphore:
        with self._lock:
            sem = self._sems.get(service)
            if sem is None:
                sem = threading.BoundedSemaphore(self._per_service)
                self._sems[service] = sem
            return sem

    @contextlib.contextmanager
    def slot(self, service: str) -> Iterator[None]:
        """Hold one service slot and one global slot."""
        deadline = time.monotonic() + self._timeout
        sem = self._semaphore(service)
        if not sem.acquire(timeout=self._timeout):
            raise UpstreamError(TIMEOUT_MESSAGE, kind="other",
                                service=service)
        try:
            remaining = max(0.0, deadline - time.monotonic())
            if not self._global.acquire(timeout=remaining):
                raise UpstreamError(TIMEOUT_MESSAGE, kind="other",
                                    service=service)
            try:
                yield
            finally:
                self._global.release()
        finally:
            sem.release()
