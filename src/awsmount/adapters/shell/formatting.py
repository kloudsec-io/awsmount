"""Output formatting: colors, ``ls -l`` rows, columns, tree prefixes."""

from __future__ import annotations

import os
import stat as _stat
import time
from collections.abc import Sequence
from dataclasses import dataclass

from awsmount.vfs.node import NodeType
from awsmount.vfs.stat import Stat

__all__ = [
    "DIR_COLOR",
    "ERROR_COLOR",
    "LINK_COLOR",
    "LongEntry",
    "PROMPT_COLOR",
    "RESET",
    "color_enabled",
    "color_for",
    "colorize",
    "columns",
    "format_mtime",
    "long_lines",
    "mode_string",
    "owner_names",
    "paint",
    "tree_prefix",
]

RESET = "\x1b[0m"
DIR_COLOR = "\x1b[1;34m"
LINK_COLOR = "\x1b[36m"
ERROR_COLOR = "\x1b[31m"
PROMPT_COLOR = "\x1b[1;32m"


def color_enabled(setting: bool | None, stream: object) -> bool:
    """Decide whether ANSI colors are written to ``stream``.

    ``setting`` False (``--no-color``) or a non-empty ``NO_COLOR``
    disables colors; True forces them; None means "only on a tty".
    """
    if setting is False:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if setting is True:
        return True
    isatty = getattr(stream, "isatty", None)
    if isatty is None:
        return False
    try:
        return bool(isatty())
    except (OSError, ValueError):
        return False


def paint(text: str, code: str, enabled: bool) -> str:
    """Wrap ``text`` in the ANSI ``code`` when enabled."""
    if not enabled or not code:
        return text
    return f"{code}{text}{RESET}"


def color_for(kind: NodeType) -> str:
    """ANSI color of a node type: dirs bold blue, links cyan."""
    if kind is NodeType.DIR:
        return DIR_COLOR
    if kind is NodeType.LINK:
        return LINK_COLOR
    return ""


def colorize(name: str, kind: NodeType, enabled: bool) -> str:
    """Color a file name according to its node type."""
    return paint(name, color_for(kind), enabled)


def mode_string(mode: int) -> str:
    """``ls``-style mode string, e.g. ``dr-xr-xr-x``."""
    return _stat.filemode(mode)


def owner_names(uid: int, gid: int) -> tuple[str, str]:
    """User and group names for ids (numbers when unknown)."""
    user = str(uid)
    group = str(gid)
    try:
        import pwd

        user = pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError):
        pass
    try:
        import grp

        group = grp.getgrgid(gid).gr_name
    except (ImportError, KeyError):
        pass
    return user, group


def format_mtime(mtime: float) -> str:
    """``MMM DD HH:MM`` in local time."""
    return time.strftime("%b %d %H:%M", time.localtime(mtime))


@dataclass(frozen=True)
class LongEntry:
    """One ``ls -l`` row: (possibly colored) name, stat, link target."""

    name: str
    stat: Stat
    target: str | None = None


def long_lines(entries: Sequence[LongEntry]) -> list[str]:
    """Render ``ls -l`` rows with aligned columns."""
    if not entries:
        return []
    owners: dict[tuple[int, int], tuple[str, str]] = {}
    resolved: list[tuple[LongEntry, str, str]] = []
    for entry in entries:
        ids = (entry.stat.uid, entry.stat.gid)
        if ids not in owners:
            owners[ids] = owner_names(*ids)
        user, group = owners[ids]
        resolved.append((entry, user, group))
    link_w = max(len(str(e.stat.nlink)) for e, _, _ in resolved)
    user_w = max(len(u) for _, u, _ in resolved)
    group_w = max(len(g) for _, _, g in resolved)
    size_w = max(len(str(e.stat.size)) for e, _, _ in resolved)
    lines: list[str] = []
    for entry, user, group in resolved:
        st = entry.stat
        line = (f"{mode_string(st.mode)} {st.nlink:>{link_w}} "
                f"{user:<{user_w}} {group:<{group_w}} "
                f"{st.size:>{size_w}} {format_mtime(st.mtime)} "
                f"{entry.name}")
        if entry.target is not None:
            line += f" -> {entry.target}"
        lines.append(line)
    return lines


def columns(plain: Sequence[str], painted: Sequence[str],
            width: int) -> list[str]:
    """Lay out names column-major like ``ls`` on a terminal.

    ``plain`` gives the visible widths; ``painted`` is what is printed.
    """
    count = len(plain)
    if count == 0:
        return []
    col_w = max(len(p) for p in plain) + 2
    ncols = max(1, width // col_w)
    nrows = (count + ncols - 1) // ncols
    lines: list[str] = []
    for row in range(nrows):
        cells: list[str] = []
        for col in range(ncols):
            index = col * nrows + row
            if index >= count:
                break
            has_next = (col + 1) * nrows + row < count
            pad = " " * (col_w - len(plain[index])) if has_next else ""
            cells.append(painted[index] + pad)
        lines.append("".join(cells))
    return lines


def tree_prefix(lasts: Sequence[bool]) -> str:
    """Drawing prefix for a tree row from its ``lasts`` flags."""
    if not lasts:
        return ""
    parts = ["    " if last else "\u2502   " for last in lasts[:-1]]
    parts.append("\u2514\u2500\u2500 " if lasts[-1]
                 else "\u251c\u2500\u2500 ")
    return "".join(parts)
