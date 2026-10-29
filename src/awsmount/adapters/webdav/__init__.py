"""WebDAV adapter: serve the VFS over HTTP on 127.0.0.1 (ARCHITECTURE: WebDAV).

Modules:

* :mod:`~awsmount.adapters.webdav.auth`: per-session URL token and
  Basic/Digest credentials. The URL token is not a secret (on macOS it
  is visible in ``mount_webdav``'s argv and in ``mount`` output); it
  only scopes the share path. The password is the secret, it is never
  written to disk, and HTTP authentication is always required.
* :mod:`~awsmount.adapters.webdav.provider`: wsgidav ``DAVProvider``
  over the VFS. It is read-only, and symlinks are served as files or
  followed.
* :mod:`~awsmount.adapters.webdav.server`: cheroot server and the
  middleware chain (Host check, macOS junk filter, token prefix and
  method filter).
* :mod:`~awsmount.adapters.webdav.macos`: ``mount_webdav`` driven
  through a pseudo-terminal, plus unmounting.

The submodules that need wsgidav or cheroot are not imported here. A
missing optional dependency therefore only fails when the WebDAV
adapter is actually used.
"""

from __future__ import annotations

__all__ = ["auth", "macos", "provider", "server"]
