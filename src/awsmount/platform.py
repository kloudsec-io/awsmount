"""OS detection, unmount helpers and mountpoint checks."""

from __future__ import annotations

import ctypes.util
import os
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

__all__ = [
    "MountpointCheck",
    "OSName",
    "cleanup_mountpoint",
    "is_linux",
    "is_macos",
    "is_mounted",
    "os_name",
    "prefer_libfuse3",
    "prepare_mountpoint",
    "unmount",
    "unmount_commands",
]

OSName = Literal["linux", "macos", "other"]


def os_name() -> OSName:
    """Return the host operating system family."""
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "macos"
    return "other"


def is_linux() -> bool:
    """True on Linux."""
    return os_name() == "linux"


def is_macos() -> bool:
    """True on macOS."""
    return os_name() == "macos"


def prefer_libfuse3() -> None:
    """Make mfusepy load libfuse 3 on Linux when it is installed.

    mfusepy tries libfuse 2 first. A machine can have the libfuse 2 library
    without its ``fusermount`` helper (Amazon Linux 2023 installs
    ``fuse-libs`` next to ``fuse3``, which only ships ``fusermount3``), and
    the mount then fails with "failed to exec fusermount". Call this before
    importing mfusepy. A ``FUSE_LIBRARY_PATH`` or ``FUSE_LIBRARY_NAME`` set
    by the user wins.
    """
    if not is_linux():
        return
    if os.environ.get("FUSE_LIBRARY_PATH") or \
            os.environ.get("FUSE_LIBRARY_NAME"):
        return
    if ctypes.util.find_library("fuse3"):
        os.environ["FUSE_LIBRARY_NAME"] = "fuse3"


def is_mounted(path: str | os.PathLike[str]) -> bool:
    """True when ``path`` is a mount point."""
    try:
        return os.path.ismount(os.fspath(path))
    except OSError:
        return False


def unmount_commands(mountpoint: str) -> list[list[str]]:
    """Return the unmount commands to try, in order, for this OS."""
    if is_linux():
        candidates = [["fusermount3", "-u", mountpoint],
                      ["fusermount", "-u", mountpoint],
                      ["umount", mountpoint]]
    elif is_macos():
        candidates = [["umount", mountpoint],
                      ["diskutil", "unmount", "force", mountpoint]]
    else:
        candidates = [["umount", mountpoint]]
    return [c for c in candidates if shutil.which(c[0]) is not None]


def unmount(mountpoint: str | os.PathLike[str],
            timeout: float = 30.0) -> bool:
    """Unmount ``mountpoint``; return True when it is no longer mounted.

    Returns False without running any command when ``mountpoint`` is
    not a mount point, so callers never report a phantom unmount.
    """
    target = os.fspath(mountpoint)
    if not is_mounted(target):
        return False
    for cmd in unmount_commands(target):
        try:
            result = subprocess.run(cmd, capture_output=True,
                                    timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0 or not is_mounted(target):
            return True
    return not is_mounted(target)


@dataclass
class MountpointCheck:
    """Result of :func:`prepare_mountpoint`."""

    path: Path
    created: bool
    warnings: list[str] = field(default_factory=list)


def prepare_mountpoint(path: str | os.PathLike[str]) -> MountpointCheck:
    """Validate (and create if needed) an empty mountpoint directory.

    Raises ``ValueError`` when the path cannot be used.
    """
    target = Path(path).expanduser().absolute()
    created = False
    if target.exists():
        if not target.is_dir():
            raise ValueError(f"{target}: not a directory")
        if is_mounted(target):
            raise ValueError(f"{target}: already a mount point")
        if any(target.iterdir()):
            raise ValueError(f"{target}: directory is not empty")
    else:
        if not target.parent.is_dir():
            raise ValueError(f"{target.parent}: parent does not exist")
        target.mkdir(mode=0o700)
        created = True
    check = MountpointCheck(path=target, created=created)
    check.warnings.extend(_parent_warnings(target))
    return check


def _inside_home(path: Path) -> bool:
    """True when ``path`` is the user's home directory or below it."""
    try:
        return path.resolve().is_relative_to(Path.home().resolve())
    except (OSError, RuntimeError):
        return False


def _parent_warnings(target: Path) -> list[str]:
    """Why the parent of ``target`` is a poor place for a mountpoint.

    The mount itself is owner-only, so a directory that others can merely
    walk through is fine inside the user's home (a default macOS home is
    0755). What matters is whether another user could replace the
    mountpoint (a parent they can write to, unless it is sticky like
    ``/tmp``), or reach it from outside a private home directory.
    """
    parent = target.parent
    try:
        mode = parent.stat().st_mode
    except OSError:
        return []
    others_write = mode & (stat.S_IWGRP | stat.S_IWOTH)
    if others_write and not mode & stat.S_ISVTX:
        return [f"{parent} can be modified by other users, who could "
                f"replace {target.name}; use a private parent directory"]
    if mode & (stat.S_IXGRP | stat.S_IXOTH) and not _inside_home(parent):
        return [f"{parent} is traversable by other users; mounted "
                "account data is protected by the mount itself, but "
                "prefer a mountpoint inside your home directory"]
    return []


def cleanup_mountpoint(check: MountpointCheck) -> None:
    """Remove a mountpoint directory created by :func:`prepare_mountpoint`."""
    if not check.created:
        return
    try:
        check.path.rmdir()
    except OSError:
        pass
