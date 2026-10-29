"""External pipes: ``builtin | !cmd`` and ``!cmd`` (ARCHITECTURE: Shell).

The builtin's output is captured to bytes and fed to
``/bin/sh -c PIPELINE``. Host commands get ``AWSMOUNT_CWD`` exported but
cannot see the VFS itself.
"""

from __future__ import annotations

import os
import subprocess
from typing import BinaryIO, TextIO

__all__ = ["SHELL", "run_host", "split_pipe"]

SHELL = "/bin/sh"


def split_pipe(line: str) -> tuple[str, str | None]:
    """Split ``line`` at its first unquoted ``|``.

    Returns ``(left, right)``; ``right`` is None when there is no pipe.
    """
    quote: str | None = None
    index = 0
    while index < len(line):
        char = line[index]
        if quote is not None:
            if char == quote:
                quote = None
            elif char == "\\" and quote == '"':
                index += 1
        elif char == "\\":
            index += 1
        elif char in "'\"":
            quote = char
        elif char == "|":
            return line[:index], line[index + 1:]
        index += 1
    return line, None


def _fileno(stream: object) -> int | None:
    """OS file descriptor of a stream, or None (e.g. BytesIO)."""
    fileno = getattr(stream, "fileno", None)
    if fileno is None:
        return None
    try:
        return int(fileno())
    except (OSError, ValueError):
        return None


def _flush(stream: object) -> None:
    flush = getattr(stream, "flush", None)
    if flush is None:
        return
    try:
        flush()
    except (OSError, ValueError):
        pass


def run_host(command: str, *, cwd: str, out: BinaryIO, err: TextIO,
             stdin_data: bytes | None = None) -> int:
    """Run ``command`` with ``/bin/sh -c``; return its exit status.

    ``stdin_data`` (captured builtin output) is fed on stdin; without it
    stdin is inherited. Output goes straight to ``out``/``err`` when they
    are real files, otherwise it is captured and copied.
    """
    if not command.strip():
        err.write("awsmount: empty host command\n")
        return 2
    env = dict(os.environ)
    env["AWSMOUNT_CWD"] = cwd
    _flush(out)
    _flush(err)
    out_fd = _fileno(out)
    err_fd = _fileno(err)
    try:
        proc = subprocess.run(
            [SHELL, "-c", command],
            input=stdin_data,
            stdout=out_fd if out_fd is not None else subprocess.PIPE,
            stderr=err_fd if err_fd is not None else subprocess.PIPE,
            env=env,
            check=False)
    except OSError as exc:
        err.write(f"awsmount: cannot run {SHELL}: {exc}\n")
        return 127
    if out_fd is None and proc.stdout:
        out.write(proc.stdout)
    if err_fd is None and proc.stderr:
        err.write(proc.stderr.decode("utf-8", "replace"))
    code = int(proc.returncode)
    return 128 - code if code < 0 else code
