"""stderr progress counter for --verbose (ARCHITECTURE: Progress counter)."""

from __future__ import annotations

import sys
import threading
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, TextIO

if TYPE_CHECKING:
    from awsmount.session.budget import ApiBudget

__all__ = ["Progress", "clear_line"]

TTY_INTERVAL = 0.2
LINE_EVERY = 100

_active: Progress | None = None
"""The progress counter whose in-place line may be unfinished."""


def clear_line() -> None:
    """Erase an unfinished in-place progress line.

    Call it before writing anything else to stderr, so that the message
    starts on a clean line instead of being glued to the counter.
    """
    progress = _active
    if progress is not None:
        progress.clear()


class Progress:
    """Prints ``[awsmount] api calls N/LIMIT label`` while enabled."""

    def __init__(self, enabled: bool, stream: TextIO = sys.stderr,
                 budget: ApiBudget | None = None, *,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.enabled = enabled
        self._stream = stream
        self._budget = budget
        self._clock = clock
        self._lock = threading.Lock()
        self._count = 0
        self._last = 0.0
        self._dirty = False
        try:
            self._tty = bool(stream.isatty())
        except (AttributeError, ValueError):
            self._tty = False

    @property
    def count(self) -> int:
        """Ticks seen so far."""
        return self._count

    def _text(self, label: str) -> str:
        used = self._budget.used() if self._budget else self._count
        limit = self._budget.limit if self._budget else 0
        total = f"{used}/{limit}" if limit else f"{used}"
        return f"[awsmount] api calls {total} {label}"

    def tick(self, label: str) -> None:
        """Count one API call and maybe print the progress line."""
        global _active
        with self._lock:
            self._count += 1
            if not self.enabled:
                return
            try:
                if self._tty:
                    now = self._clock()
                    if now - self._last < TTY_INTERVAL:
                        return
                    self._last = now
                    self._stream.write("\r" + self._text(label) + "\x1b[K")
                    self._dirty = True
                    _active = self
                elif self._count % LINE_EVERY == 0:
                    self._stream.write(self._text(label) + "\n")
                self._stream.flush()
            except (OSError, ValueError):
                return

    def clear(self) -> None:
        """Erase the in-place line, if one is unfinished."""
        with self._lock:
            if self._tty and self._dirty:
                try:
                    self._stream.write("\r\x1b[K")
                    self._stream.flush()
                except (OSError, ValueError):
                    pass
                self._dirty = False

    def finish(self) -> None:
        """Terminate an in-place tty line."""
        with self._lock:
            if self.enabled and self._tty and self._dirty:
                try:
                    self._stream.write("\n")
                    self._stream.flush()
                except (OSError, ValueError):
                    pass
                self._dirty = False
