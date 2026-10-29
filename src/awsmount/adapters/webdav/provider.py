"""wsgidav DAV provider over the awsmount VFS (ARCHITECTURE: WebDAV).

wsgidav hands :meth:`VFSDavProvider.get_resource_inst` a path that is
already *share-relative* (the ``/<token>`` prefix has been removed by
wsgidav's request resolver) and already URL-decoded once by the HTTP
server. The path is therefore used as-is: stripping the share prefix
again, or unquoting a second time, would corrupt it (escaped names such
as ``team%2Fowner`` must reach the VFS unchanged).
"""

from __future__ import annotations

import hashlib
import io
from typing import Any, Literal

from wsgidav.dav_error import DAVError
from wsgidav.dav_provider import (
    DAVCollection,
    DAVNonCollection,
    DAVProvider,
)

from awsmount.errors import (
    AwsMountError,
    ForbiddenOperation,
    IsADirectory,
    NotADirectory,
    NotFound,
    PermissionDenied,
    SymlinkLoop,
)
from awsmount.vfs.node import DirNode, FileNode, Node, SymlinkNode
from awsmount.vfs.resolver import VFS

__all__ = [
    "LinksMode",
    "VFSCollection",
    "VFSDavProvider",
    "VFSFile",
    "dav_error",
]

LinksMode = Literal["file", "follow"]

HTTP_NOT_FOUND = 404
HTTP_UNAUTHORIZED = 401
HTTP_FORBIDDEN = 403
HTTP_SERVICE_UNAVAILABLE = 503
LINK_CONTENT_TYPE = "text/plain; charset=utf-8"


def dav_error(exc: AwsMountError,
              denied_status: int = HTTP_FORBIDDEN) -> DAVError:
    """Map a VFS error to the HTTP status described in ARCHITECTURE: WebDAV.

    ``denied_status`` is the status for an AWS AccessDenied. It is 403 for
    ``awsmount serve``. The macOS mount passes 401: ``mount_webdav`` shows
    a 403 as "Operation not permitted" (EPERM, the guard's error) but a
    401 as "Permission denied" (EACCES), which is what FUSE reports. A
    guard refusal stays 403.
    """
    if isinstance(exc, (NotFound, NotADirectory, SymlinkLoop)):
        return DAVError(HTTP_NOT_FOUND, context_info=str(exc))
    if isinstance(exc, PermissionDenied):
        return DAVError(denied_status, context_info=str(exc))
    if isinstance(exc, ForbiddenOperation):
        return DAVError(HTTP_FORBIDDEN, context_info=str(exc))
    return DAVError(HTTP_SERVICE_UNAVAILABLE,
                    context_info=str(exc) or type(exc).__name__)


def _components(path: str) -> list[str]:
    """Non-empty components of a share-relative path."""
    return [c for c in path.split("/") if c]


class VFSCollection(DAVCollection):  # type: ignore[misc]
    """A VFS directory exposed as a WebDAV collection."""

    def __init__(self, path: str, environ: dict[str, Any],
                 provider: VFSDavProvider, vpath: str) -> None:
        super().__init__(path, environ)
        self._dav = provider
        self._vpath = vpath

    def _mtime(self) -> float:
        try:
            return float(self._dav.vfs.stat(self._vpath).mtime)
        except AwsMountError as exc:
            raise dav_error(exc, self._dav.denied_status) from exc

    def get_member_names(self) -> list[str]:
        """Escaped child names of the directory."""
        try:
            return list(self._dav.vfs.listdir(self._vpath))
        except AwsMountError as exc:
            raise dav_error(exc, self._dav.denied_status) from exc

    def get_display_info(self) -> dict[str, str]:
        """Display info used by directory browsers."""
        return {"type": "Directory"}

    def get_creation_date(self) -> float:
        """Fetch time of the backing data."""
        return self._mtime()

    def get_last_modified(self) -> float:
        """Fetch time of the backing data."""
        return self._mtime()

    def support_etag(self) -> bool:
        """Collections carry an ETag derived from path and mtime."""
        return True

    def get_etag(self) -> str:
        """``blake2b(path + mtime)`` (unquoted)."""
        raw = f"{self._vpath}\0{self._mtime()!r}".encode("utf-8")
        return hashlib.blake2b(raw, digest_size=16).hexdigest()


class VFSFile(DAVNonCollection):  # type: ignore[misc]
    """A VFS file (or, in ``file`` links mode, a symlink) as a resource."""

    def __init__(self, path: str, environ: dict[str, Any],
                 provider: VFSDavProvider, node: Node) -> None:
        super().__init__(path, environ)
        self._dav = provider
        self._node = node
        self._data: bytes | None = None

    def _content(self) -> bytes:
        if self._data is None:
            node = self._node
            try:
                if isinstance(node, SymlinkNode):
                    data = (node.readlink() + "\n").encode("utf-8")
                elif isinstance(node, FileNode):
                    data = node.content()
                else:
                    raise IsADirectory(node.path)
            except AwsMountError as exc:
                raise dav_error(exc, self._dav.denied_status) from exc
            self._data = data
        return self._data

    def _content_or_none(self) -> bytes | None:
        """The rendered bytes, or None when rendering fails.

        Size, times and ETag are properties of a PROPFIND. When rendering
        fails (AccessDenied, an upstream error) they are left out instead
        of failing the whole PROPFIND: macOS treats such a file as missing
        and reports ENOENT. The error then comes from the GET, as it does
        after a directory listing.
        """
        try:
            return self._content()
        except DAVError:
            return None

    def _cheap(self) -> bool:
        """True when answering must NOT render this file.

        A directory listing (``PROPFIND`` with ``Depth`` other than 0) asks
        for the size, ETag and times of every child. Rendering a lazy file
        costs AWS API calls, so ``find`` or ``ls -l`` over a mount used to
        fetch every lazy file of the whole tree (hundreds of calls for a
        small account, minutes on a large one). In a listing, a lazy file
        that is not already cached therefore reports no size and a cheap
        ETag. Asking about that one file (``Depth: 0``), reading it, or
        listing it again once it is cached renders or reuses it as before.
        """
        node = self._node
        if not isinstance(node, FileNode) or not node.lazy:
            return False
        env = self.environ
        if env.get("REQUEST_METHOD") != "PROPFIND":
            return False
        if str(env.get("HTTP_DEPTH", "0")).strip() == "0":
            return False
        return node.known_size() is None

    def get_content_length(self) -> int | None:
        """Length of the rendered bytes (``None`` while a listing skips it)."""
        if self._cheap():
            return None
        data = self._content_or_none()
        return None if data is None else len(data)

    def get_content_type(self) -> str:
        """``application/json`` for ``.json``, else text/plain."""
        node = self._node
        if isinstance(node, FileNode):
            return node.content_type
        return LINK_CONTENT_TYPE

    def get_content(self) -> io.BytesIO:
        """The rendered bytes; Range is handled by wsgidav."""
        return io.BytesIO(self._content())

    def get_display_info(self) -> dict[str, str]:
        """Display info used by directory browsers."""
        return {"type": "File"}

    def _mtime(self) -> float:
        if not self._cheap():
            self._content_or_none()
        return float(self._node.mtime())

    def get_creation_date(self) -> float:
        """Fetch time of the backing data."""
        return self._mtime()

    def get_last_modified(self) -> float:
        """Fetch time of the backing data."""
        return self._mtime()

    def support_etag(self) -> bool:
        """Files carry a content-derived ETag."""
        return True

    def get_etag(self) -> str:
        """``blake2b(content, 16)`` (unquoted); path-based while skipped."""
        data = None if self._cheap() else self._content_or_none()
        if data is None:
            raw = f"{self._node.path}\0unrendered".encode("utf-8")
            return hashlib.blake2b(raw, digest_size=16).hexdigest()
        return hashlib.blake2b(data, digest_size=16).hexdigest()

    def support_ranges(self) -> bool:
        """Byte ranges are served from the rendered bytes."""
        return True


class VFSDavProvider(DAVProvider):  # type: ignore[misc]
    """Read-only wsgidav provider backed by a :class:`VFS`."""

    def __init__(self, vfs: VFS, links_mode: LinksMode = "file",
                 denied_status: int = HTTP_FORBIDDEN) -> None:
        if links_mode not in ("file", "follow"):
            raise ValueError(f"invalid links mode {links_mode!r}")
        if denied_status not in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
            raise ValueError(f"invalid denied status {denied_status!r}")
        super().__init__()
        self.vfs = vfs
        self.links_mode: LinksMode = links_mode
        self.denied_status = denied_status

    def is_readonly(self) -> bool:
        """The provider never accepts writes."""
        return True

    def _walk_physical(self, path: str) -> Node | None:
        """Resolve without traversing symlinks (``file`` links mode).

        A symlink is only valid as the last component, where it is
        served as a file; a path continuing through a link or a file
        does not exist.
        """
        parts = _components(path)
        cur: Node = self.vfs.root
        for index, name in enumerate(parts):
            if not isinstance(cur, DirNode):
                return None
            if name == ".":
                continue
            if name == "..":
                cur = cur.parent if cur.parent is not None else cur
                continue
            child = cur.child(name)
            if child is None:
                return None
            if isinstance(child, SymlinkNode) and index < len(parts) - 1:
                return None
            cur = child
        return cur

    def _lookup(self, path: str) -> Node | None:
        try:
            if self.links_mode == "follow":
                return self.vfs.resolve(path or "/", follow=True)
            return self._walk_physical(path)
        except (NotFound, NotADirectory, SymlinkLoop):
            return None
        except AwsMountError as exc:
            raise dav_error(exc, self.denied_status) from exc

    def get_resource_inst(self, path: str,
                          environ: dict[str, Any]
                          ) -> VFSCollection | VFSFile | None:
        """Map a share-relative path to a DAV resource (None = 404)."""
        node = self._lookup(path)
        if node is None:
            return None
        if isinstance(node, DirNode):
            return VFSCollection(path, environ, self, node.path)
        return VFSFile(path, environ, self, node)
