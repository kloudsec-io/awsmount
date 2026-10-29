"""Adapters exposing the VFS: shell, export, WebDAV and FUSE.

Every adapter shares the one pure-python VFS core. Adapters that need
native libraries or optional packages (FUSE, WebDAV) are imported lazily
by the CLI so that a missing dependency never breaks the shell.
"""

from __future__ import annotations

__all__: list[str] = []
