"""prompt_toolkit REPL around :class:`Shell` (ARCHITECTURE: Shell)."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TextIO

from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import ANSI
from prompt_toolkit.history import FileHistory, History, InMemoryHistory

from awsmount.adapters.shell import formatting as fmt
from awsmount.adapters.shell.commands import COMMANDS, Shell
from awsmount.adapters.shell.completer import VFSCompleter

__all__ = [
    "BANNER",
    "history_path",
    "open_history",
    "prompt_text",
    "run_repl",
    "run_stream",
]

BANNER = ("awsmount shell (read-only). Type 'help' for commands, "
          "'exit' or Ctrl-D to leave.\n")


def history_path() -> Path:
    """``$XDG_STATE_HOME/awsmount/history`` (default ~/.local/state)."""
    base = os.environ.get("XDG_STATE_HOME")
    root = Path(base) if base else Path.home() / ".local" / "state"
    return root / "awsmount" / "history"


def open_history(path: Path) -> History:
    """File history with mode 0600; in-memory if the file is unusable."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        os.close(fd)
        os.chmod(path, 0o600)
    except OSError:
        return InMemoryHistory()
    return FileHistory(str(path))


def prompt_text(shell: Shell) -> str:
    """``awsmount:<logical cwd>$ `` (colored when enabled)."""
    if shell.color:
        return (f"{fmt.PROMPT_COLOR}awsmount{fmt.RESET}:"
                f"{fmt.DIR_COLOR}{shell.cwd}{fmt.RESET}$ ")
    return f"awsmount:{shell.cwd}$ "


def run_stream(shell: Shell, stream: TextIO) -> int:
    """Run commands read line by line from a non-tty stream."""
    status = 0
    for raw in stream:
        status = shell.run_line(raw.rstrip("\n"))
        shell.flush()
        if shell.should_exit:
            return shell.exit_status
    return status


def _isatty(stream: TextIO) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, OSError, ValueError):
        return False


def run_repl(shell: Shell, *, stdin: TextIO | None = None) -> int:
    """Interactive loop; returns the session exit status."""
    stream = stdin if stdin is not None else sys.stdin
    if not _isatty(stream):
        return run_stream(shell, stream)
    session: PromptSession[str] = PromptSession(
        history=open_history(history_path()),
        completer=VFSCompleter(shell, COMMANDS),
        complete_while_typing=False)
    shell.write(BANNER)
    shell.flush()
    status = 0
    while not shell.should_exit:
        try:
            line = session.prompt(ANSI(prompt_text(shell)))
        except KeyboardInterrupt:
            continue
        except EOFError:
            break
        try:
            status = shell.run_line(line)
        except KeyboardInterrupt:
            shell.error("interrupted")
            status = 130
        shell.flush()
    if shell.should_exit:
        return shell.exit_status
    return status
