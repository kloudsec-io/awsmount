"""mfusepy mount lifecycle (ARCHITECTURE: FUSE).

mfusepy is imported only inside :func:`load_mfusepy`. Importing it loads
libfuse and raises ``OSError`` when libfuse is absent, so this module
itself always imports. The operations class
(:class:`~awsmount.adapters.fuse.operations.AwsFuse`) already subclasses
``mfusepy.Operations`` when libfuse is present, so the mount simply
instantiates it.
"""

from __future__ import annotations

import importlib
import os
import sys
from collections.abc import Callable
from types import ModuleType
from typing import TYPE_CHECKING, Any, Literal

from awsmount import platform as _platform
from awsmount.adapters.fuse.operations import AwsFuse
from awsmount.doctor import FUSE_T_LIB, MACFUSE_FS
from awsmount.session.progress import clear_line
from awsmount.vfs.resolver import VFS

if TYPE_CHECKING:
    from awsmount.session.context import Context

__all__ = [
    "FSNAME",
    "fuse_options",
    "load_mfusepy",
    "mount",
    "os_options",
]

LazySizeMode = Literal["render", "zero"]

FSNAME = "awsmount"
LINUX_HINT = ("install libfuse (apt install fuse3) and mfusepy "
              "(pip install mfusepy); see 'awsmount doctor'")
MACOS_HINT = ("FUSE on macOS needs a third-party layer (FUSE-T or "
              "macFUSE) plus mfusepy. You do not need it: use "
              "'--method webdav' (built in); see 'awsmount doctor'")


def load_mfusepy() -> ModuleType:
    """Import mfusepy (raises ImportError/OSError without libfuse)."""
    _platform.prefer_libfuse3()
    return importlib.import_module("mfusepy")


def _log(message: str) -> None:
    try:
        clear_line()
        sys.stderr.write(f"[awsmount] {message}\n")
        sys.stderr.flush()
    except (OSError, ValueError):
        pass


def os_options(osn: str | None = None) -> dict[str, Any]:
    """Per-OS mount options (Linux, macFUSE or FUSE-T)."""
    name = osn if osn is not None else _platform.os_name()
    if name == "linux":
        return {"subtype": FSNAME}
    if name == "macos":
        if os.path.exists(MACFUSE_FS) and not os.path.exists(FUSE_T_LIB):
            return {"volname": FSNAME, "noappledouble": True,
                    "noapplexattr": True}
        return {"volname": FSNAME}
    return {}


def fuse_options(ttl: float, osn: str | None = None) -> dict[str, Any]:
    """Keyword arguments for ``mfusepy.FUSE`` (never ``allow_other``)."""
    opts: dict[str, Any] = {
        "foreground": True,
        "nothreads": False,
        "ro": True,
        "raw_fi": True,
        "use_ino": True,
        "fsname": FSNAME,
        "attr_timeout": ttl,
        "entry_timeout": ttl,
        "negative_timeout": min(ttl, 10.0),
    }
    opts.update(os_options(osn))
    return opts


def _stderr_echo(line: str) -> None:
    clear_line()
    sys.stderr.write(line + "\n")
    sys.stderr.flush()


def mount(vfs: VFS, ctx: Context, mountpoint: str, *,
          lazy_size: LazySizeMode | None = None,
          echo: Callable[[str], Any] | None = None) -> int:
    """Mount the VFS read-only at ``mountpoint`` and block.

    Returns 0 after a clean unmount (Ctrl-C, SIGTERM or
    ``awsmount umount``) and 1 on error.
    """
    say = echo if echo is not None else _stderr_echo
    osn = _platform.os_name()
    if osn not in ("linux", "macos"):
        say("awsmount: FUSE mounting is supported on Linux and macOS only")
        return 1
    hint = LINUX_HINT if osn == "linux" else MACOS_HINT
    try:
        fusepy = load_mfusepy()
    except (ImportError, OSError) as exc:
        say(f"awsmount: FUSE is not available: {exc}")
        say(f"awsmount: {hint}")
        return 1
    try:
        check = _platform.prepare_mountpoint(mountpoint)
    except (ValueError, OSError) as exc:
        say(f"awsmount: cannot use mountpoint: {exc}")
        return 1
    for warning in check.warnings:
        say(f"awsmount: warning: {warning}")
    target = str(check.path)
    mode: LazySizeMode = lazy_size or ctx.config.lazy_size
    ttl = float(ctx.config.ttl)

    state = {"mounted": False}

    class ReadyFuse(AwsFuse):
        """AwsFuse that announces the mount once libfuse is up."""

        def init(self, *args: Any) -> None:
            """Called by libfuse once the filesystem is mounted."""
            state["mounted"] = True
            say(f"awsmount: mounted read-only at {target} (FUSE). Press "
                f"Ctrl-C or run 'awsmount umount {target}' to unmount.")

    ops = ReadyFuse(vfs, lazy_size=mode)
    status = 0
    try:
        fusepy.FUSE(ops, target, **fuse_options(ttl, osn))
    except KeyboardInterrupt:
        pass
    except (RuntimeError, OSError) as exc:
        if state["mounted"]:
            # libfuse returns a non-zero code when SIGTERM or SIGHUP ends
            # a mount that was up (libfuse 3 does; mfusepy raises it).
            # That is a normal shutdown, not a failed mount.
            pass
        else:
            say(f"awsmount: FUSE mount failed: {exc}")
            say(f"awsmount: {hint}")
            status = 1
    finally:
        if _platform.is_mounted(target):
            if not _platform.unmount(target):
                say(f"awsmount: cannot unmount {target}; try "
                    f"'fusermount3 -u {target}' or 'umount {target}'")
                status = 1
        _platform.cleanup_mountpoint(check)
    return status
