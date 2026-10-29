"""Rolling-window global API call budget (ARCHITECTURE: Budget and limits)."""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable

from awsmount.errors import BudgetExceeded

__all__ = ["ApiBudget"]


class ApiBudget:
    """Counts API calls; raises ``BudgetExceeded`` past the limit."""

    def __init__(self, limit: int, window: float,
                 clock: Callable[[], float] = time.monotonic, *,
                 on_exhausted: Callable[[str], None] | None = None
                 ) -> None:
        if limit < 0 or window < 0:
            raise ValueError("limit and window must be >= 0")
        self._limit = limit
        self._window = window
        self._clock = clock
        self._on_exhausted = on_exhausted
        self._lock = threading.Lock()
        self._stamps: deque[float] = deque()
        self._count = 0
        self._notified = False

    @property
    def limit(self) -> int:
        """Configured limit (0 = unlimited)."""
        return self._limit

    @property
    def window(self) -> float:
        """Window length in seconds (0 = session lifetime)."""
        return self._window

    def message(self) -> str:
        """Human explanation shown when the budget is exhausted."""
        span = f"{self._window:g}s" if self._window > 0 else "session"
        return (f"API call budget exhausted ({self._limit} calls / {span})."
                " Cached data is still served. Raise --max-api-calls, "
                "narrow --services/--region, or run 'refresh'.")

    def _prune(self, now: float) -> None:
        if self._window <= 0:
            return
        horizon = now - self._window
        while self._stamps and self._stamps[0] <= horizon:
            self._stamps.popleft()

    def _used_locked(self) -> int:
        if self._window <= 0:
            return self._count
        return len(self._stamps)

    def charge(self, label: str) -> int:
        """Record one call; return calls used in the window."""
        notify: str | None = None
        with self._lock:
            now = self._clock()
            self._prune(now)
            used = self._used_locked()
            if self._limit > 0 and used >= self._limit:
                message = self.message()
                if not self._notified:
                    self._notified = True
                    notify = message
            else:
                if self._window <= 0:
                    self._count += 1
                else:
                    self._stamps.append(now)
                self._notified = False
                return used + 1
        if notify is not None and self._on_exhausted is not None:
            self._on_exhausted(notify)
        raise BudgetExceeded(f"{message} [{label}]")

    def used(self) -> int:
        """Calls used in the current window."""
        with self._lock:
            self._prune(self._clock())
            return self._used_locked()

    def reset(self) -> None:
        """Forget every recorded call."""
        with self._lock:
            self._stamps.clear()
            self._count = 0
            self._notified = False
