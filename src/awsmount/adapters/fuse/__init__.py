"""FUSE adapter: mount the VFS read-only through mfusepy (ARCHITECTURE: FUSE).

:mod:`~awsmount.adapters.fuse.operations` holds :class:`AwsFuseOps`, a
plain class that implements every FUSE operation over the VFS and
raises :class:`FuseError` (an ``OSError``). It never imports mfusepy,
so it can be imported and tested on machines without libfuse.

:mod:`~awsmount.adapters.fuse.mount` imports mfusepy lazily (importing
mfusepy loads libfuse and raises ``OSError`` when it is absent). It
builds the real ``mfusepy.Operations`` subclass that wraps
:class:`AwsFuseOps`, and it runs the mount lifecycle.
"""

from __future__ import annotations

from awsmount.adapters.fuse.operations import (
    MAX_SNAPSHOT,
    READ_ONLY_OPS,
    AwsFuseOps,
    FuseError,
    OpenResult,
)

__all__ = [
    "AwsFuseOps",
    "FuseError",
    "MAX_SNAPSHOT",
    "OpenResult",
    "READ_ONLY_OPS",
]
