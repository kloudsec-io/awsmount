"""Pure-python virtual filesystem core shared by every adapter."""

from __future__ import annotations

from awsmount.vfs.node import (
    Content,
    DirNode,
    FileNode,
    JSONValue,
    Node,
    NodeType,
    SymlinkNode,
)
from awsmount.vfs.resolver import MAX_SYMLINKS, VFS
from awsmount.vfs.stat import Stat

__all__ = [
    "Content",
    "DirNode",
    "FileNode",
    "JSONValue",
    "MAX_SYMLINKS",
    "Node",
    "NodeType",
    "Stat",
    "SymlinkNode",
    "VFS",
]
