"""macOS WebDAV mount through ``/sbin/mount_webdav`` (ARCHITECTURE: WebDAV).

This method was verified on macOS 26. ``mount_webdav`` has no ``-r``,
``-a <fd>`` fails, and credentials in the URL fail. The working
authenticated method is interactive mode (``-i``) driven through a
pseudo-terminal: the ``username`` prompt is answered first, then, after
0.2 s, the ``password`` prompt. The user name and password never appear
in argv, the URL or the environment.

The share URL, including the per-session token, *is* passed in argv. It
is visible to every local user through ``ps`` during the handshake, and
afterwards in ``mount``/``df`` output.
The token is therefore not a secret: it only scopes the share path.
The password is the secret, and the server always requires HTTP
authentication. Read-only access comes from ``-o rdonly``, and the
server refuses write methods anyway.
"""

from __future__ import annotations

import os
import pty
import select
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from awsmount import platform as _platform
from awsmount.adapters.webdav.auth import Credentials
from awsmount.adapters.webdav.server import ShutdownSignals, WebDavServer
from awsmount.session.progress import clear_line
from awsmount.vfs.resolver import VFS

if TYPE_CHECKING:
    from awsmount.session.context import Context

__all__ = [
    "FALLBACK_HELP",
    "HANDSHAKE_TIMEOUT",
    "HandshakeResult",
    "MOUNT_WEBDAV",
    "MOUNT_OPTIONS",
    "PASSWORD_DELAY",
    "WATCH_INTERVAL",
    "disable_spotlight",
    "mount",
    "mount_command",
    "run_mount_webdav",
]

MOUNT_WEBDAV = "/sbin/mount_webdav"
# mount_webdav shows HTTP 403 as "Operation not permitted" (EPERM) and
# 401 as "Permission denied" (EACCES, what FUSE reports for an AWS
# AccessDenied). Only this mount uses 401: Finder and davfs2, which can
# connect to `awsmount serve`, would ask for credentials again.
ACCESS_DENIED_STATUS = 401
MOUNT_OPTIONS = "rdonly,nobrowse"
VOLUME_NAME = "awsmount"
HANDSHAKE_TIMEOUT = 25.0
PASSWORD_DELAY = 0.2
MOUNT_SETTLE = 3.0
WATCH_INTERVAL = 0.2
"""Seconds between looks at the mount table while the mount is up, so that
``umount`` is noticed (and the server stopped) within a fraction of a
second."""

FALLBACK_HELP = (
    "awsmount: alternatives: run 'awsmount serve' and connect from "
    "Finder (Go > Connect to Server, Cmd-K) with the printed "
    "credentials, or use the interactive shell: 'awsmount shell'.")


def mount_command(url: str, mountpoint: str) -> list[str]:
    """argv of the interactive, read-only ``mount_webdav`` call.

    The URL (and so the non-secret token) is visible to other local
    users through ``ps``; the user name and password are never part of
    argv, they are typed into the pseudo-terminal.
    """
    return [MOUNT_WEBDAV, "-i", "-S", "-o", MOUNT_OPTIONS, "-v",
            VOLUME_NAME, url, mountpoint]


@dataclass
class HandshakeResult:
    """Outcome of one ``mount_webdav`` pty session."""

    returncode: int | None
    output: str
    asked_user: bool
    asked_password: bool
    timed_out: bool = False
    cancelled: bool = False

    @property
    def ok(self) -> bool:
        """True when ``mount_webdav`` exited 0 in time."""
        return (self.returncode == 0 and not self.timed_out
                and not self.cancelled)

    def describe(self) -> str:
        """Short reason for a failure."""
        if self.cancelled:
            return "interrupted"
        if self.timed_out:
            if not self.asked_user:
                return "no username prompt within the timeout"
            if not self.asked_password:
                return "no password prompt within the timeout"
            return "mount_webdav did not finish within the timeout"
        return f"mount_webdav exited with status {self.returncode}"


def _read(fd: int) -> bytes:
    try:
        return os.read(fd, 4096)
    except OSError:
        return b""


def _write(fd: int, data: bytes) -> None:
    try:
        os.write(fd, data)
    except OSError:
        pass


def _reap(pid: int) -> int | None:
    """Exit code of ``pid`` if it has exited, else None."""
    try:
        done, status = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return -1
    if not done:
        return None
    return os.waitstatus_to_exitcode(status)


def _kill(pid: int) -> int:
    """Terminate ``pid`` (SIGTERM, then SIGKILL) and reap it."""
    for sig, grace in ((signal.SIGTERM, 2.0), (signal.SIGKILL, 5.0)):
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            code = _reap(pid)
            if code is not None:
                return code
            time.sleep(0.05)
    try:
        _done, status = os.waitpid(pid, 0)
    except ChildProcessError:
        return -1
    return os.waitstatus_to_exitcode(status)


def _drain(fd: int, buf: bytearray) -> None:
    while True:
        try:
            ready, _w, _x = select.select([fd], [], [], 0)
        except (OSError, ValueError):
            return
        if not ready:
            return
        chunk = _read(fd)
        if not chunk:
            return
        buf += chunk


def run_mount_webdav(argv: Sequence[str], user: str, password: str, *,
                     timeout: float = HANDSHAKE_TIMEOUT,
                     cancel: threading.Event | None = None,
                     password_delay: float = PASSWORD_DELAY
                     ) -> HandshakeResult:
    """Run ``argv`` on a pty, answering the username/password prompts.

    The password is never echoed by ``mount_webdav``. It is also
    scrubbed from the returned output.
    """
    args = list(argv)
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.execv(args[0], args)
        except BaseException:
            pass
        os._exit(127)
    buf = bytearray()
    user_at = 0
    asked_user = False
    asked_password = False
    timed_out = False
    cancelled = False
    eof = False
    code: int | None = None
    deadline = time.monotonic() + timeout
    try:
        while code is None:
            if cancel is not None and cancel.is_set():
                cancelled = True
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            if eof:
                time.sleep(min(remaining, 0.05))
            else:
                ready, _w, _x = select.select([fd], [], [],
                                              min(remaining, 0.25))
                if ready:
                    chunk = _read(fd)
                    if not chunk:
                        eof = True
                    else:
                        buf += chunk
                        lowered = bytes(buf).lower()
                        if not asked_user and b"username" in lowered:
                            _write(fd, user.encode("utf-8") + b"\n")
                            asked_user = True
                            user_at = len(buf)
                        elif (asked_user and not asked_password
                              and b"password" in lowered[user_at:]):
                            time.sleep(password_delay)
                            _write(fd, password.encode("utf-8") + b"\n")
                            asked_password = True
            code = _reap(pid)
    finally:
        _drain(fd, buf)
        if code is None:
            code = _kill(pid)
        try:
            os.close(fd)
        except OSError:
            pass
    text = bytes(buf).decode("utf-8", "replace")
    if password:
        text = text.replace(password, "<hidden>")
    return HandshakeResult(returncode=code, output=text,
                           asked_user=asked_user,
                           asked_password=asked_password,
                           timed_out=timed_out, cancelled=cancelled)


def disable_spotlight(mountpoint: str) -> None:
    """Best-effort ``mdutil -i off <mountpoint>``."""
    tool = shutil.which("mdutil") or "/usr/bin/mdutil"
    try:
        subprocess.run([tool, "-i", "off", mountpoint],
                       capture_output=True, timeout=15, check=False)
    except (OSError, subprocess.SubprocessError):
        pass


def _wait_mounted(path: str, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        if _platform.is_mounted(path):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.1)


def _stderr_echo(line: str) -> None:
    clear_line()
    sys.stderr.write(line + "\n")
    sys.stderr.flush()


def _tail(text: str, limit: int = 600) -> str:
    flat = " ".join(text.split())
    return flat[-limit:]


def _handshake(server: WebDavServer, target: str,
               cancel: threading.Event) -> HandshakeResult:
    creds: Credentials = server.credentials
    return run_mount_webdav(mount_command(server.url, target),
                            creds.user, creds.password, cancel=cancel)


def mount(vfs: VFS, ctx: Context, mountpoint: str, *, port: int = 0,
          links_mode: str = "file",
          echo: Callable[[str], Any] | None = None) -> int:
    """Serve the VFS and mount it read-only at ``mountpoint``.

    The call blocks until SIGINT/SIGTERM, or until the volume is
    unmounted externally (``awsmount umount``). It returns an exit
    status: 0 ok, 1 error.
    """
    say = echo if echo is not None else _stderr_echo
    if not _platform.is_macos():
        say("awsmount: WebDAV mounting is automated on macOS only")
        return 1
    if not os.access(MOUNT_WEBDAV, os.X_OK):
        say(f"awsmount: {MOUNT_WEBDAV} not found")
        say(FALLBACK_HELP)
        return 1
    try:
        check = _platform.prepare_mountpoint(mountpoint)
    except (ValueError, OSError) as exc:
        say(f"awsmount: cannot use mountpoint: {exc}")
        return 1
    for warning in check.warnings:
        say(f"awsmount: warning: {warning}")
    target = str(check.path)
    server = WebDavServer(vfs, port=port, links_mode=links_mode,
                          verbose=bool(ctx.config.verbose),
                          denied_status=ACCESS_DENIED_STATUS)
    try:
        server.start()
    except OSError as exc:
        say(f"awsmount: cannot start WebDAV server: {exc}")
        _platform.cleanup_mountpoint(check)
        return 1
    status = 0
    try:
        with ShutdownSignals() as stop:
            try:
                result = _handshake(server, target, stop.event)
            except OSError as exc:
                result = HandshakeResult(None, str(exc), False, False)
            if result.ok and not _wait_mounted(target, MOUNT_SETTLE):
                result.returncode = None
            if not result.ok:
                if result.cancelled:
                    say("awsmount: mount interrupted")
                else:
                    say(f"awsmount: mount_webdav failed: "
                        f"{result.describe()}")
                    detail = _tail(result.output)
                    if detail:
                        say(f"awsmount: mount_webdav output: {detail}")
                    say(FALLBACK_HELP)
                status = 1
            else:
                disable_spotlight(target)
                say(f"awsmount: mounted read-only at {target} "
                    f"(WebDAV on 127.0.0.1:{server.port}). Press Ctrl-C "
                    f"or run 'awsmount umount {target}' to unmount.")
                while not stop.wait(WATCH_INTERVAL):
                    if not _platform.is_mounted(target):
                        break
                    if not server.running:
                        say("awsmount: WebDAV server stopped "
                            "unexpectedly")
                        status = 1
                        break
    finally:
        if _platform.is_mounted(target):
            if not _platform.unmount(target):
                say(f"awsmount: cannot unmount {target}; try "
                    f"'diskutil unmount force {target}'")
                status = 1
        server.stop()
        _platform.cleanup_mountpoint(check)
    return status
