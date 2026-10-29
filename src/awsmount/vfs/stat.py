"""Stat records and inode hashing (ARCHITECTURE: File metadata)."""

from __future__ import annotations

import hashlib
import os
import stat as _stat
from dataclasses import dataclass

__all__ = [
    "BLOCK_SIZE",
    "DIR_MODE",
    "FILE_MODE",
    "LINK_MODE",
    "Stat",
    "dir_stat",
    "file_stat",
    "inode_for",
    "link_stat",
]

DIR_MODE = _stat.S_IFDIR | 0o555
FILE_MODE = _stat.S_IFREG | 0o444
LINK_MODE = _stat.S_IFLNK | 0o777
BLOCK_SIZE = 4096


def _uid() -> int:
    getuid = getattr(os, "getuid", None)
    return int(getuid()) if getuid is not None else 0


def _gid() -> int:
    getgid = getattr(os, "getgid", None)
    return int(getgid()) if getgid is not None else 0


@dataclass(frozen=True)
class Stat:
    """POSIX-like stat information for one node."""

    mode: int
    size: int
    mtime: float
    nlink: int
    uid: int
    gid: int
    ino: int

    @property
    def is_dir(self) -> bool:
        """True for directories."""
        return _stat.S_ISDIR(self.mode)

    @property
    def is_file(self) -> bool:
        """True for regular files."""
        return _stat.S_ISREG(self.mode)

    @property
    def is_link(self) -> bool:
        """True for symlinks."""
        return _stat.S_ISLNK(self.mode)

    @property
    def blocks(self) -> int:
        """Number of 512-byte blocks."""
        return (self.size + 511) // 512

    def to_fuse(self) -> dict[str, int | float]:
        """Return the dict expected by FUSE ``getattr``."""
        return {
            "st_mode": self.mode,
            "st_size": self.size,
            "st_mtime": self.mtime,
            "st_atime": self.mtime,
            "st_ctime": self.mtime,
            "st_nlink": self.nlink,
            "st_uid": self.uid,
            "st_gid": self.gid,
            "st_ino": self.ino,
            "st_blocks": self.blocks,
            "st_blksize": BLOCK_SIZE,
        }


def inode_for(path: str) -> int:
    """Return a stable 63-bit inode number for ``path``."""
    digest = hashlib.blake2b(path.encode("utf-8", "surrogatepass"),
                             digest_size=8).digest()
    return int.from_bytes(digest, "big") & (2 ** 63 - 1)


def dir_stat(path: str, mtime: float) -> Stat:
    """Stat for a directory."""
    return Stat(DIR_MODE, 0, mtime, 1, _uid(), _gid(), inode_for(path))


def file_stat(path: str, size: int, mtime: float) -> Stat:
    """Stat for a regular file."""
    return Stat(FILE_MODE, size, mtime, 1, _uid(), _gid(), inode_for(path))


def link_stat(path: str, target: str, mtime: float) -> Stat:
    """Stat for a symlink."""
    size = len(target.encode("utf-8", "surrogatepass"))
    return Stat(LINK_MODE, size, mtime, 1, _uid(), _gid(), inode_for(path))
