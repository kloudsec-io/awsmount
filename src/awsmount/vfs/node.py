"""Filesystem node classes (ARCHITECTURE: Nodes and rendering)."""

from __future__ import annotations

import abc
import enum
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar

from awsmount.vfs.path import join
from awsmount.vfs.render import (
    Content,
    JSONValue,
    content_type_for,
    render,
)
from awsmount.vfs.stat import Stat, dir_stat, file_stat, link_stat

if TYPE_CHECKING:
    from awsmount.session.context import Context

__all__ = [
    "Content",
    "DirNode",
    "FileNode",
    "JSONValue",
    "Node",
    "NodeType",
    "SymlinkNode",
]

DEFAULT_CONTENT_TYPE = "text/plain"


class NodeType(enum.Enum):
    """Kind of a node."""

    DIR = "dir"
    FILE = "file"
    LINK = "link"


class Node(abc.ABC):
    """Base node; immutable identity (name, parent)."""

    type: ClassVar[NodeType]

    def __init__(self, name: str, parent: DirNode | None,
                 ctx: Context) -> None:
        if parent is not None and (
                not name or "/" in name or name in (".", "..")):
            raise ValueError(f"invalid node name {name!r}")
        self.name = name
        self.parent = parent
        self.ctx = ctx
        self._path = "/" if parent is None else join(parent.path, name)

    @property
    def path(self) -> str:
        """Absolute path made of escaped components."""
        return self._path

    @abc.abstractmethod
    def stat(self) -> Stat:
        """Return the stat record of this node."""

    def mtime(self) -> float:
        """Wall-clock time of the backing data."""
        if self.parent is not None:
            return self.parent.mtime()
        return float(self.ctx.started_at)

    def invalidate(self) -> None:
        """Forget memoised state (no-op for stateless nodes)."""

    def _ttl(self) -> float:
        return float(self.ctx.config.ttl)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self._path!r})"


class DirNode(Node):
    """Directory whose children come from a loader, memoised per TTL."""

    type = NodeType.DIR

    def __init__(self, name: str, parent: DirNode | None, ctx: Context,
                 loader: Callable[[DirNode], Iterable[Node]],
                 *, static: bool = False,
                 fetched_at: float | None = None) -> None:
        super().__init__(name, parent, ctx)
        self._loader = loader
        self._static = static
        self._fetched_at = fetched_at
        self._lock = threading.Lock()
        self._state: tuple[float, float, Mapping[str, Node]] | None = None

    @property
    def static(self) -> bool:
        """True when the children never expire."""
        return self._static

    @property
    def is_loaded(self) -> bool:
        """True when fresh children are memoised."""
        return self.peek_children() is not None

    def _fresh(self, state: tuple[float, float, Mapping[str, Node]]
               ) -> bool:
        return self._static or time.monotonic() < state[0]

    def children(self) -> Mapping[str, Node]:
        """Return the children sorted by name, loading them if needed."""
        state = self._state
        if state is not None and self._fresh(state):
            return state[2]
        with self._lock:
            state = self._state
            if state is not None and self._fresh(state):
                return state[2]
            built: dict[str, Node] = {}
            for node in self._loader(self):
                if node.name in built:
                    raise ValueError(
                        f"duplicate child name {node.name!r} in {self.path}")
                built[node.name] = node
            children = MappingProxyType(dict(sorted(built.items())))
            self._state = (time.monotonic() + self._ttl(), time.time(),
                           children)
            return children

    def child(self, name: str) -> Node | None:
        """Return the child called ``name`` or None."""
        return self.children().get(name)

    def peek_children(self) -> Mapping[str, Node] | None:
        """Non-blocking; None if not loaded or expired."""
        state = self._state
        if state is not None and self._fresh(state):
            return state[2]
        return None

    def invalidate(self) -> None:
        """Forget memoised children and, recursively, their state.

        Loaders may hand back node objects that outlive one listing
        (static roots, account dirs). Invalidating recursively makes
        sure no descendant keeps serving memoised content afterwards.
        """
        with self._lock:
            state = self._state
            self._state = None
        if state is None:
            return
        for node in state[2].values():
            node.invalidate()

    def mtime(self) -> float:
        """Fetch time of the backing data (session start if static)."""
        if self._fetched_at is not None:
            return self._fetched_at
        if self._static:
            return float(self.ctx.started_at)
        state = self._state
        if state is not None:
            return state[1]
        return super().mtime()

    def stat(self) -> Stat:
        """Directory stat; never triggers a load."""
        return dir_stat(self.path, self.mtime())


class FileNode(Node):
    """Regular file rendered once per TTL."""

    type = NodeType.FILE

    def __init__(self, name: str, parent: DirNode, ctx: Context,
                 render: Callable[[], Content], *, lazy: bool,
                 content_type: str = DEFAULT_CONTENT_TYPE,
                 volatile: bool = False) -> None:
        super().__init__(name, parent, ctx)
        self._render = render
        self.lazy = lazy
        self.volatile = volatile
        self._content_type = content_type
        self._lock = threading.Lock()
        self._state: tuple[float, float, bytes] | None = None
        self._volatile_at: float | None = None

    @property
    def content_type(self) -> str:
        """MIME type; ``.json`` files are ``application/json``."""
        if self._content_type == DEFAULT_CONTENT_TYPE:
            return content_type_for(self.name)
        return self._content_type

    def _fresh_state(self) -> tuple[float, float, bytes] | None:
        state = self._state
        if state is not None and time.monotonic() < state[0]:
            return state
        return None

    @property
    def is_rendered(self) -> bool:
        """True when fresh rendered content is cached."""
        return self._fresh_state() is not None

    def invalidate(self) -> None:
        """Forget the cached render so the next read re-renders."""
        with self._lock:
            self._state = None
            self._volatile_at = None

    def content(self) -> bytes:
        """Rendered bytes; cached for the TTL and single-flight."""
        if not self.volatile:
            state = self._fresh_state()
            if state is not None:
                return state[2]
        with self._lock:
            if not self.volatile:
                state = self._fresh_state()
                if state is not None:
                    return state[2]
            data = render(self._render())
            if self.volatile:
                self._volatile_at = time.time()
            else:
                self._state = (time.monotonic() + self._ttl(), time.time(),
                               data)
            return data

    def known_size(self) -> int | None:
        """Size without triggering a render (None if unknown)."""
        state = self._fresh_state()
        return len(state[2]) if state is not None else None

    def read(self, offset: int, length: int) -> bytes:
        """Return ``length`` bytes from ``offset`` (-1 = to the end)."""
        data = self.content()
        offset = max(0, offset)
        if length < 0:
            return data[offset:]
        return data[offset:offset + length]

    def mtime(self) -> float:
        """Render time for lazy/volatile files, else the parent's time."""
        if self.volatile and self._volatile_at is not None:
            return self._volatile_at
        if self.lazy:
            state = self._state
            if state is not None:
                return state[1]
        return super().mtime()

    def stat(self, *, render: bool = True) -> Stat:
        """File stat; ``render=False`` reports 0 for unrendered lazy files."""
        if render or not self.lazy:
            size = len(self.content())
        else:
            size = self.known_size() or 0
        return file_stat(self.path, size, self.mtime())


class SymlinkNode(Node):
    """Symbolic link with a relative POSIX target."""

    type = NodeType.LINK

    def __init__(self, name: str, parent: DirNode, ctx: Context,
                 target: str) -> None:
        super().__init__(name, parent, ctx)
        self.target = target

    def readlink(self) -> str:
        """Return the link target."""
        return self.target

    def stat(self) -> Stat:
        """Symlink stat (lstat semantics)."""
        return link_stat(self.path, self.target, self.mtime())
