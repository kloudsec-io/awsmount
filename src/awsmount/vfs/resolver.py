"""Path resolution with POSIX physical semantics.

See ARCHITECTURE: Path resolution.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterator

from awsmount.errors import (
    AwsMountError,
    IsADirectory,
    NotADirectory,
    NotALink,
    NotFound,
    SymlinkLoop,
)
from awsmount.vfs.node import DirNode, FileNode, Node, SymlinkNode
from awsmount.vfs.path import join, normpath, split
from awsmount.vfs.stat import Stat

__all__ = ["MAX_SYMLINKS", "VFS", "WalkErrorHandler"]

MAX_SYMLINKS = 40

WalkErrorHandler = Callable[[str, AwsMountError], None]


class VFS:
    """Read-only virtual filesystem rooted at one DirNode."""

    def __init__(self, root: DirNode) -> None:
        self.root = root

    def resolve(self, path: str, *, follow: bool = True) -> Node:
        """Resolve ``path`` to a node, following intermediate symlinks."""
        trailing = len(path) > 1 and path.endswith("/")
        if trailing:
            follow = True
        queue = deque(split(path))
        cur: Node = self.root
        hops = 0
        while queue:
            comp = queue.popleft()
            if not isinstance(cur, DirNode):
                raise NotADirectory(path)
            if comp == ".":
                continue
            if comp == "..":
                cur = cur.parent if cur.parent is not None else self.root
                continue
            child = cur.child(comp)
            if child is None:
                raise NotFound(path)
            if isinstance(child, SymlinkNode) and (queue or follow):
                hops += 1
                if hops > MAX_SYMLINKS:
                    raise SymlinkLoop(path)
                target = child.readlink()
                parts = [p for p in target.split("/") if p]
                queue.extendleft(reversed(parts))
                if target.startswith("/") or child.parent is None:
                    cur = self.root
                else:
                    cur = child.parent
                continue
            cur = child
        if trailing and not isinstance(cur, DirNode):
            raise NotADirectory(path)
        return cur

    def stat(self, path: str) -> Stat:
        """Stat following symlinks."""
        return self.resolve(path, follow=True).stat()

    def lstat(self, path: str) -> Stat:
        """Stat without following a final symlink."""
        return self.resolve(path, follow=False).stat()

    def listdir(self, path: str) -> list[str]:
        """Sorted escaped names in a directory."""
        node = self.resolve(path, follow=True)
        if not isinstance(node, DirNode):
            raise NotADirectory(path)
        return list(node.children().keys())

    def read(self, path: str, offset: int = 0, length: int = -1) -> bytes:
        """Read file content."""
        node = self.resolve(path, follow=True)
        if isinstance(node, DirNode):
            raise IsADirectory(path)
        if not isinstance(node, FileNode):
            raise NotFound(path)
        return node.read(offset, length)

    def readlink(self, path: str) -> str:
        """Return a symlink's target."""
        node = self.resolve(path, follow=False)
        if not isinstance(node, SymlinkNode):
            raise NotALink(path)
        return node.readlink()

    def realpath(self, path: str) -> str:
        """Physical path with every symlink resolved."""
        return self.resolve(path, follow=True).path

    def walk(self, path: str, *, follow_links: bool = False,
             max_depth: int | None = None,
             on_error: WalkErrorHandler | None = None
             ) -> Iterator[tuple[str, Node]]:
        """Pre-order, sorted traversal yielding ``(path, node)``.

        Symlinked directories are not descended unless ``follow_links``;
        then already-visited real paths are skipped. ``on_error``
        receives listing errors and the walk continues; without it the
        error propagates.
        """
        start = normpath(path)
        node = self.resolve(start, follow=True)
        visited: set[str] = set()
        yield from self._walk(start, node, 0, follow_links, max_depth,
                              on_error, visited)

    def _walk(self, path: str, node: Node, depth: int, follow: bool,
              max_depth: int | None, on_error: WalkErrorHandler | None,
              visited: set[str]) -> Iterator[tuple[str, Node]]:
        yield path, node
        target: Node = node
        if isinstance(node, SymlinkNode):
            if not follow:
                return
            try:
                target = self.resolve(path, follow=True)
            except AwsMountError as exc:
                if on_error is None:
                    raise
                on_error(path, exc)
                return
        if not isinstance(target, DirNode):
            return
        if follow:
            if target.path in visited:
                return
            visited.add(target.path)
        if max_depth is not None and depth >= max_depth:
            return
        try:
            items = list(target.children().items())
        except AwsMountError as exc:
            if on_error is None:
                raise
            on_error(path, exc)
            return
        for name, child in items:
            yield from self._walk(join(path, name), child, depth + 1,
                                  follow, max_depth, on_error, visited)
