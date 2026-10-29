"""find/grep/tree traversal shared by the shell and export."""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass

from awsmount.errors import AwsMountError, IsADirectory
from awsmount.vfs.node import DirNode, FileNode, Node, NodeType
from awsmount.vfs.path import basename, join, normpath, unescape_name
from awsmount.vfs.resolver import VFS, WalkErrorHandler

__all__ = [
    "GrepMatch",
    "TYPE_CHARS",
    "TreeEntry",
    "find",
    "grep",
    "tree",
]

TYPE_CHARS: dict[NodeType, str] = {
    NodeType.FILE: "f",
    NodeType.DIR: "d",
    NodeType.LINK: "l",
}


@dataclass(frozen=True)
class GrepMatch:
    """One grep hit; ``binary`` hits carry no line."""

    path: str
    lineno: int | None
    line: str | None
    binary: bool = False


@dataclass(frozen=True)
class TreeEntry:
    """One row of a tree listing.

    ``lasts`` holds, for every level from depth 1 to this entry, whether
    the node at that level is the last of its siblings.
    """

    path: str
    name: str
    node: Node
    depth: int
    lasts: tuple[bool, ...]


def _report(on_error: WalkErrorHandler | None, path: str,
            exc: AwsMountError) -> None:
    if on_error is None:
        raise exc
    on_error(path, exc)


def find(vfs: VFS, path: str = "/", *, name: str | None = None,
         type_: str | None = None, max_depth: int | None = None,
         on_error: WalkErrorHandler | None = None
         ) -> Iterator[tuple[str, Node]]:
    """Yield ``(path, node)`` matching ``-name``/``-type``; no links."""
    if type_ is not None and type_ not in ("f", "d", "l"):
        raise ValueError(f"invalid -type {type_!r}")
    for found, node in vfs.walk(path, max_depth=max_depth,
                                on_error=on_error):
        if name is not None:
            raw = unescape_name(basename(found))
            if not fnmatch.fnmatchcase(raw, name):
                continue
        if type_ is not None and TYPE_CHARS[node.type] != type_:
            continue
        yield found, node


def _grep_file(path: str, node: FileNode, rx: re.Pattern[str],
               files_only: bool, on_error: WalkErrorHandler | None
               ) -> Iterator[GrepMatch]:
    try:
        data = node.content()
    except AwsMountError as exc:
        _report(on_error, path, exc)
        return
    text = data.decode("utf-8", "replace")
    if b"\x00" in data:
        if rx.search(text):
            yield GrepMatch(path, None, None, binary=True)
        return
    for lineno, line in enumerate(text.splitlines(), 1):
        if rx.search(line):
            yield GrepMatch(path, lineno, line)
            if files_only:
                return


def grep(vfs: VFS, pattern: str, paths: Sequence[str], *,
         recursive: bool = False, ignore_case: bool = False,
         files_only: bool = False,
         on_error: WalkErrorHandler | None = None
         ) -> Iterator[GrepMatch]:
    """Search files for a Python regular expression.

    Recursion never follows symlinks; errors go to ``on_error`` and the
    search continues.
    """
    rx = re.compile(pattern, re.IGNORECASE if ignore_case else 0)
    for start in paths:
        norm = normpath(start)
        try:
            node = vfs.resolve(norm, follow=True)
        except AwsMountError as exc:
            _report(on_error, start, exc)
            continue
        if isinstance(node, FileNode):
            yield from _grep_file(norm, node, rx, files_only, on_error)
            continue
        if not isinstance(node, DirNode):
            continue
        if not recursive:
            _report(on_error, start, IsADirectory(start))
            continue
        for found, child in vfs.walk(norm, on_error=on_error):
            if isinstance(child, FileNode):
                yield from _grep_file(found, child, rx, files_only,
                                      on_error)


def tree(vfs: VFS, path: str = "/", *, max_depth: int | None = None,
         on_error: WalkErrorHandler | None = None
         ) -> Iterator[TreeEntry]:
    """Yield tree entries in pre-order; links are not followed."""
    start = normpath(path)
    node = vfs.resolve(start, follow=True)
    yield TreeEntry(start, basename(start), node, 0, ())
    yield from _tree_children(start, node, 0, (), max_depth, on_error)


def _tree_children(path: str, node: Node, depth: int,
                   lasts: tuple[bool, ...], max_depth: int | None,
                   on_error: WalkErrorHandler | None
                   ) -> Iterator[TreeEntry]:
    if not isinstance(node, DirNode):
        return
    if max_depth is not None and depth >= max_depth:
        return
    try:
        items = list(node.children().items())
    except AwsMountError as exc:
        _report(on_error, path, exc)
        return
    for index, (name, child) in enumerate(items):
        flags = lasts + (index == len(items) - 1,)
        child_path = join(path, name)
        yield TreeEntry(child_path, name, child, depth + 1, flags)
        yield from _tree_children(child_path, child, depth + 1, flags,
                                  max_depth, on_error)
