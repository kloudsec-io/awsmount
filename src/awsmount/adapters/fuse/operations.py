"""mfusepy ``Operations`` subclass over the VFS (ARCHITECTURE: FUSE).

The module never requires libfuse at import time: when ``mfusepy``
cannot be loaded (package missing, or libfuse not found, which mfusepy
reports as ``OSError``), a pure-Python fallback base class and
``FuseOSError`` are used instead. Only an actual mount (``mount.py``)
needs the native library; the operations can always be instantiated
and exercised directly.

``AwsFuse`` is the operations class; ``AwsFuseOps`` is an alias kept
for the package ``__init__`` and ``mount.py``, which import it under
that name. Likewise ``FuseError`` is an alias of ``FuseOSError``.
``OpenResult`` is the return type of :meth:`AwsFuse.open`: ``0`` with
``raw_fi=True`` (the handle is stored in the file-info struct), or the
new handle id otherwise.
"""

from __future__ import annotations

import errno
import itertools
import os
import sys
import threading
from typing import Any, Literal

from awsmount import platform as _platform
from awsmount.vfs.node import DirNode, FileNode, SymlinkNode
from awsmount.vfs.resolver import VFS
from awsmount.vfs.stat import DIR_MODE, FILE_MODE, LINK_MODE, inode_for

__all__ = [
    "AwsFuse",
    "AwsFuseOps",
    "FUSE_IMPORT_ERROR",
    "FuseError",
    "FuseOSError",
    "MAX_SNAPSHOT",
    "OpenResult",
    "Operations",
    "READ_ONLY_OPS",
]

FUSE_IMPORT_ERROR: str | None = None

_platform.prefer_libfuse3()
try:
    import mfusepy as _mfusepy
except (ImportError, OSError) as _exc:  # no mfusepy or no libfuse
    FUSE_IMPORT_ERROR = str(_exc)
    _mfusepy = None

if _mfusepy is not None:
    Operations: Any = _mfusepy.Operations
    FuseOSError: Any = _mfusepy.FuseOSError
else:
    class _FallbackFuseOSError(OSError):
        """Stand-in for ``mfusepy.FuseOSError`` when it cannot load."""

        def __init__(self, code: int) -> None:
            super().__init__(code, os.strerror(code))

    class _FallbackOperations:
        """Stand-in for ``mfusepy.Operations`` when it cannot load."""

        def __call__(self, op: str, *args: Any) -> Any:
            """Dispatch ``op`` to the method of the same name."""
            method = getattr(self, op, None)
            if method is None:
                raise _FallbackFuseOSError(errno.EFAULT)
            return method(*args)

    Operations = _FallbackOperations
    FuseOSError = _FallbackFuseOSError

#: Alias of :data:`FuseOSError` under the name imported by the package
#: ``__init__`` and by ``mount.py``.
FuseError: Any = FuseOSError

#: Return type of ``open``: 0 with a raw file-info struct (the handle
#: id is written to ``fi.fh``), otherwise the handle id itself.
OpenResult = int

MAX_SNAPSHOT = 64 * 1024 * 1024

#: FUSE operations that would mutate the filesystem; every one of them
#: is refused with EROFS because the mount is read-only (ARCHITECTURE: FUSE).
READ_ONLY_OPS: frozenset[str] = frozenset({
    "write", "create", "mkdir", "rmdir", "unlink", "rename", "symlink",
    "link", "chmod", "chown", "truncate", "utimens", "setxattr",
    "removexattr", "mknod", "fallocate",
})

_WRITE_FLAGS = os.O_APPEND | os.O_CREAT | os.O_TRUNC
_NO_XATTR = (getattr(errno, "ENOATTR", errno.ENODATA)
             if sys.platform == "darwin" else errno.ENODATA)

_ERRNO_BY_CLASS = {
    "NotFound": errno.ENOENT,
    "NotADirectory": errno.ENOTDIR,
    "IsADirectory": errno.EISDIR,
    "SymlinkLoop": errno.ELOOP,
    "ReadOnly": errno.EROFS,
    "PermissionDenied": errno.EACCES,
    "BudgetExceeded": errno.EIO,
    "UpstreamError": errno.EIO,
    "ForbiddenOperation": errno.EPERM,
}


def _errno_of(exc: BaseException) -> int:
    """Map an exception to an errno value."""
    code = getattr(exc, "errno", None)
    if isinstance(code, int) and code > 0:
        return code
    for cls in type(exc).__mro__:
        mapped = _ERRNO_BY_CLASS.get(cls.__name__)
        if mapped is not None:
            return mapped
    return errno.EIO


def _erofs() -> Any:
    """Return the EROFS FuseOSError."""
    return FuseOSError(errno.EROFS)


def _handle_id(fh: Any) -> int:
    """Extract the integer handle from an int or a file-info struct."""
    if isinstance(fh, int):
        return fh
    return int(getattr(fh, "fh", 0) or 0)


class AwsFuse(Operations):  # type: ignore[misc]
    """Read-only FUSE operations; every write path gives EROFS."""

    def __init__(self, vfs: VFS, *,
                 lazy_size: Literal["render", "zero"] = "render") -> None:
        super().__init__()
        self.vfs = vfs
        self.lazy_size = lazy_size
        self._handles: dict[int, bytes] = {}
        self._lock = threading.Lock()
        self._ids = itertools.count(1)

    # -- helpers --------------------------------------------------------

    def _resolve(self, path: str, *, follow: bool) -> Any:
        try:
            return self.vfs.resolve(path, follow=follow)
        except Exception as exc:
            raise FuseOSError(_errno_of(exc)) from exc

    # -- read operations ------------------------------------------------

    def getattr(self, path: str, fh: Any = None) -> dict[str, Any]:
        """lstat of ``path``; zero lazy sizes when ``lazy_size=zero``."""
        node = self._resolve(path, follow=False)
        try:
            if isinstance(node, FileNode) and self.lazy_size == "zero":
                st = node.stat(render=False)
            else:
                st = node.stat()
        except Exception as exc:
            raise FuseOSError(_errno_of(exc)) from exc
        return dict(st.to_fuse())

    def readdir(self, path: str, fh: Any = None) -> list[Any]:
        """``.``, ``..`` and the escaped child names with type and inode.

        Entries are ``(name, {"st_mode", "st_ino"}, 0)`` tuples. A bare
        name reaches the kernel with ``d_ino`` 0, and bash's glob drops
        such entries, so ``*/describe.json`` would match nothing.
        """
        node = self._resolve(path, follow=True)
        if not isinstance(node, DirNode):
            raise FuseOSError(errno.ENOTDIR)
        try:
            children = node.children()
        except Exception as exc:
            raise FuseOSError(_errno_of(exc)) from exc
        parent = node.parent if node.parent is not None else node
        entries: list[Any] = [
            (".", {"st_mode": DIR_MODE, "st_ino": inode_for(node.path)}, 0),
            ("..", {"st_mode": DIR_MODE, "st_ino": inode_for(parent.path)},
             0)]
        for name, child in children.items():
            if isinstance(child, DirNode):
                mode = DIR_MODE
            elif isinstance(child, SymlinkNode):
                mode = LINK_MODE
            else:
                mode = FILE_MODE
            entries.append(
                (name, {"st_mode": mode, "st_ino": inode_for(child.path)},
                 0))
        return entries

    def readlink(self, path: str) -> str:
        """Relative target of a symlink; EINVAL for other nodes."""
        node = self._resolve(path, follow=False)
        if not isinstance(node, SymlinkNode):
            raise FuseOSError(errno.EINVAL)
        return node.readlink()

    def open(self, path: str, flags: Any) -> OpenResult:
        """Snapshot the content; write intent gives EROFS."""
        raw = not isinstance(flags, int)
        mode = int(getattr(flags, "flags", 0) or 0) if raw else flags
        if (mode & os.O_ACCMODE) != os.O_RDONLY or mode & _WRITE_FLAGS:
            raise _erofs()
        node = self._resolve(path, follow=True)
        if isinstance(node, DirNode):
            raise FuseOSError(errno.EISDIR)
        if not isinstance(node, FileNode):
            raise FuseOSError(errno.EIO)
        lazy = bool(node.lazy)
        try:
            data = node.content()
        except Exception as exc:
            raise FuseOSError(_errno_of(exc)) from exc
        if len(data) > MAX_SNAPSHOT:
            raise FuseOSError(errno.EFBIG)
        with self._lock:
            fid = next(self._ids)
            self._handles[fid] = data
        if raw:
            flags.fh = fid
            flags.direct_io = self.lazy_size == "zero" and lazy
            flags.keep_cache = False
            return 0
        return fid

    def read(self, path: str, size: int, offset: int, fh: Any) -> bytes:
        """Slice of the handle's snapshot."""
        with self._lock:
            data = self._handles.get(_handle_id(fh))
        if data is None:
            raise FuseOSError(errno.EBADF)
        if size <= 0 or offset >= len(data):
            return b""
        start = max(0, offset)
        return data[start:start + size]

    def release(self, path: str, fh: Any) -> int:
        """Drop the snapshot."""
        with self._lock:
            self._handles.pop(_handle_id(fh), None)
        return 0

    def opendir(self, path: str) -> int:
        """No-op."""
        return 0

    def releasedir(self, path: str, fh: Any) -> int:
        """No-op."""
        return 0

    def access(self, path: str, amode: int) -> int:
        """W_OK gives EROFS; otherwise the path must exist."""
        if amode & os.W_OK:
            raise _erofs()
        self._resolve(path, follow=True)
        return 0

    def statfs(self, path: str) -> dict[str, int]:
        """Static filesystem statistics."""
        return {"f_bsize": 4096, "f_frsize": 4096, "f_namemax": 255,
                "f_blocks": 0, "f_bfree": 0, "f_bavail": 0,
                "f_files": 0, "f_ffree": 0, "f_favail": 0}

    def getxattr(self, path: str, name: str, position: int = 0) -> bytes:
        """No extended attributes."""
        raise FuseOSError(_NO_XATTR)

    def listxattr(self, path: str) -> list[str]:
        """No extended attributes."""
        return []

    # -- write operations: all EROFS ------------------------------------

    def write(self, path: str, data: bytes, offset: int, fh: Any) -> int:
        """Refused (read-only)."""
        raise _erofs()

    def create(self, path: str, mode: int, fi: Any = None) -> int:
        """Refused (read-only)."""
        raise _erofs()

    def mkdir(self, path: str, mode: int) -> int:
        """Refused (read-only)."""
        raise _erofs()

    def rmdir(self, path: str) -> int:
        """Refused (read-only)."""
        raise _erofs()

    def unlink(self, path: str) -> int:
        """Refused (read-only)."""
        raise _erofs()

    def rename(self, old: str, new: str) -> int:
        """Refused (read-only)."""
        raise _erofs()

    def symlink(self, target: str, source: str) -> int:
        """Refused (read-only)."""
        raise _erofs()

    def link(self, target: str, source: str) -> int:
        """Refused (read-only)."""
        raise _erofs()

    def chmod(self, path: str, mode: int) -> int:
        """Refused (read-only)."""
        raise _erofs()

    def chown(self, path: str, uid: int, gid: int) -> int:
        """Refused (read-only)."""
        raise _erofs()

    def truncate(self, path: str, length: int, fh: Any = None) -> int:
        """Refused (read-only)."""
        raise _erofs()

    def utimens(self, path: str, times: Any = None) -> int:
        """Refused (read-only)."""
        raise _erofs()

    def setxattr(self, path: str, name: str, value: bytes,
                 options: int, position: int = 0) -> int:
        """Refused (read-only)."""
        raise _erofs()

    def removexattr(self, path: str, name: str) -> int:
        """Refused (read-only)."""
        raise _erofs()

    def mknod(self, path: str, mode: int, dev: int) -> int:
        """Refused (read-only)."""
        raise _erofs()

    def fallocate(self, path: str, mode: int, offset: int, length: int,
                  fh: Any = None) -> int:
        """Refused (read-only)."""
        raise _erofs()


#: Alias of :class:`AwsFuse` under the name used by the package
#: ``__init__`` and by ``mount.py``.
AwsFuseOps = AwsFuse


_MISSING_REFUSALS = sorted(op for op in READ_ONLY_OPS
                           if op not in vars(AwsFuse))
if _MISSING_REFUSALS:  # programming error: keep the set and class in sync
    raise RuntimeError(
        f"AwsFuse lacks EROFS handlers for {_MISSING_REFUSALS}")
