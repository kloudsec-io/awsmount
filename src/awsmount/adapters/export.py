"""Materialise a VFS subtree into a real directory (ARCHITECTURE: Export)."""

from __future__ import annotations

import json
import os
import posixpath
import shutil
import sys
import threading
from collections.abc import Mapping
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from awsmount import __version__
from awsmount.errors import AwsMountError
from awsmount.session.progress import clear_line
from awsmount.tree.collection import LinkDir
from awsmount.vfs.node import DirNode, FileNode, Node, SymlinkNode
from awsmount.vfs.resolver import VFS

__all__ = [
    "MARKER",
    "ExportError",
    "ExportReport",
    "export",
]

MARKER = ".awsmount-export"
LinkMode = Literal["keep", "skip", "file"]
_LINK_MODES = ("keep", "skip", "file")
_FILE_MODE = 0o644
_DIR_MODE = 0o755


class ExportError(AwsMountError):
    """The destination cannot be used for an export."""


@dataclass
class ExportReport:
    """Counts of written entries and per-path errors."""

    dirs: int
    files: int
    links: int
    errors: list[tuple[str, str]] = field(default_factory=list)
    external: int = 0


class _State:
    """Thread-safe counters and error list of one export run."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.dirs = 0
        self.files = 0
        self.links = 0
        self.external = 0
        self.errors: list[tuple[str, str]] = []

    def add_file(self) -> None:
        """Count one written file."""
        with self.lock:
            self.files += 1

    def fail(self, path: str, exc: BaseException) -> None:
        """Record and report a per-path error."""
        message = _message(exc)
        with self.lock:
            self.errors.append((path, message))
        clear_line()
        print(f"export: {path}: {message}", file=sys.stderr)


def _message(exc: BaseException) -> str:
    """Human-readable strerror-like message for ``exc``."""
    if isinstance(exc, OSError) and exc.strerror:
        return str(exc.strerror)
    code = getattr(exc, "errno", None)
    if isinstance(code, int) and code > 0:
        return os.strerror(code)
    return str(exc) or type(exc).__name__


def _clear(path: Path) -> None:
    """Remove whatever is at ``path`` without following symlinks."""
    if path.is_symlink():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)
    elif os.path.lexists(path):
        path.unlink()


def _write_bytes(path: Path, data: bytes) -> None:
    """Write ``data`` to a fresh 0644 file, never through a symlink."""
    _clear(path)
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
             | getattr(os, "O_NOFOLLOW", 0))
    fd = os.open(path, flags, _FILE_MODE)
    try:
        os.fchmod(fd, _FILE_MODE)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
    finally:
        os.close(fd)


def _make_dir(path: Path) -> None:
    """Create (or reuse) a real 0755 directory at ``path``."""
    if path.is_symlink() or (os.path.lexists(path) and not path.is_dir()):
        path.unlink()
    if not path.is_dir():
        path.mkdir(mode=_DIR_MODE)
    os.chmod(path, _DIR_MODE)


def _make_link(path: Path, target: str) -> None:
    """Create a symlink at ``path`` pointing at ``target`` verbatim."""
    _clear(path)
    os.symlink(target, path)


def _prepare(dest: Path, *, clean: bool, force: bool) -> None:
    """Validate and prepare the destination directory."""
    if dest.is_symlink():
        raise ExportError(f"destination {dest} is a symlink")
    if not dest.exists():
        dest.mkdir(parents=True, mode=_DIR_MODE)
        return
    if not dest.is_dir():
        raise ExportError(f"destination {dest} is not a directory")
    entries = list(dest.iterdir())
    if not entries:
        return
    if clean:
        marker = dest / MARKER
        if marker.is_symlink() or not marker.is_file():
            raise ExportError(
                f"destination {dest} has no {MARKER} marker; "
                "refusing to --clean it")
        for entry in entries:
            _clear(entry)
        return
    if not force:
        raise ExportError(
            f"destination {dest} is not empty "
            "(use --force to overwrite or --clean to replace)")


def _reveal_flag(vfs: VFS) -> bool:
    """The session's --reveal flag, read from the root context."""
    config = getattr(vfs.root.ctx, "config", None)
    return bool(getattr(config, "reveal", False))


def _write_marker(dest: Path, source: str, reveal: bool) -> None:
    """Write the ``.awsmount-export`` marker file."""
    payload = {
        "reveal": reveal,
        "source": source,
        "time": datetime.now(timezone.utc).isoformat(),
        "version": __version__,
    }
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    _write_bytes(dest / MARKER, text.encode("utf-8"))


def _export_file(node: FileNode, path: Path, state: _State) -> None:
    """Render and write one file, recording any error."""
    try:
        data = node.content()
        _write_bytes(path, data)
    except Exception as exc:  # noqa: BLE001 - reported per file
        state.fail(node.path, exc)
        return
    state.add_file()


def _inside(root: str, target: str) -> bool:
    """True when the absolute VFS path ``target`` is within ``root``."""
    root = root.rstrip("/") or "/"
    return (target == root or root == "/"
            or target.startswith(root + "/"))


def _export_link(node: SymlinkNode, path: Path, links: LinkMode,
                 state: _State, src_root: str) -> None:
    """Recreate, skip or textualise one symlink.

    In ``keep`` mode a symlink is recreated only when its target stays
    inside the exported subtree. A link that points outside would be
    dangling (or worse, resolve to an unrelated host path of the same
    name), so it is written as a text file holding the target instead
    and counted in ``external``.
    """
    if links == "skip":
        return
    external = False
    try:
        target = node.readlink()
        if links == "keep":
            resolved = target if target.startswith("/") else \
                posixpath.normpath(
                    posixpath.join(posixpath.dirname(node.path), target))
            if _inside(src_root, resolved):
                _make_link(path, target)
            else:
                external = True
                _write_bytes(path, (target + "\n").encode("utf-8"))
        else:
            _write_bytes(path, (target + "\n").encode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - reported per link
        state.fail(node.path, exc)
        return
    with state.lock:
        state.links += 1
        if external:
            state.external += 1


def _children(node: DirNode, state: _State) -> Mapping[str, Node]:
    """Children of ``node``; listing errors are recorded, not raised."""
    try:
        return node.children()
    except Exception as exc:  # noqa: BLE001 - reported per directory
        state.fail(node.path, exc)
        return {}


def _walk(root: DirNode, dest: Path, links: LinkMode, state: _State,
          pool: ThreadPoolExecutor, futures: list[Future[None]],
          src_root: str) -> None:
    """Create dirs and links in pre-order; queue files on the pool.

    With ``links == "skip"`` the directories that hold only links
    (``links/``, ``referenced-by/``) are not created at all.
    """
    stack: list[tuple[DirNode, Path]] = [(root, dest)]
    while stack:
        directory, target = stack.pop()
        for name, child in _children(directory, state).items():
            path = target / name
            if isinstance(child, SymlinkNode):
                _export_link(child, path, links, state, src_root)
            elif isinstance(child, LinkDir) and links == "skip":
                continue
            elif isinstance(child, DirNode):
                try:
                    _make_dir(path)
                except OSError as exc:
                    state.fail(child.path, exc)
                    continue
                state.dirs += 1
                stack.append((child, path))
            elif isinstance(child, FileNode):
                futures.append(
                    pool.submit(_export_file, child, path, state))


def export(vfs: VFS, src: str, dest: Path, *,
           links: LinkMode = "keep",
           jobs: int = 8, clean: bool = False,
           force: bool = False) -> ExportReport:
    """Write the subtree at ``src`` into the real directory ``dest``.

    The source is resolved (following symlinks) before the destination
    is touched. Content equals the served content, so redaction follows
    the session's ``--reveal`` flag. Symlinks are recreated with their
    exact relative targets (``keep``), omitted (``skip``) or written as
    files holding the target text (``file``).
    """
    if links not in _LINK_MODES:
        raise ValueError(f"invalid links mode {links!r}")
    if jobs < 1:
        raise ValueError("jobs must be >= 1")
    dest = Path(dest)
    start = vfs.realpath(src)
    root = vfs.resolve(start, follow=False)
    _prepare(dest, clean=clean, force=force)
    state = _State()
    futures: list[Future[None]] = []
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        if isinstance(root, DirNode):
            _walk(root, dest, links, state, pool, futures, start)
        elif isinstance(root, FileNode):
            futures.append(
                pool.submit(_export_file, root, dest / root.name, state))
        elif isinstance(root, SymlinkNode):
            _export_link(root, dest / root.name, links, state,
                         posixpath.dirname(start))
        for future in futures:
            future.result()
    _write_marker(dest, start, _reveal_flag(vfs))
    return ExportReport(dirs=state.dirs, files=state.files,
                        links=state.links, errors=sorted(state.errors),
                        external=state.external)
