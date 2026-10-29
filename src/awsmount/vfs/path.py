"""Path normalisation, name escaping and collision-free naming."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from urllib.parse import unquote

__all__ = [
    "EMPTY_NAME",
    "MAX_NAME_BYTES",
    "assign_names",
    "basename",
    "dirname",
    "escape_name",
    "join",
    "normpath",
    "split",
    "unescape_name",
]

MAX_NAME_BYTES = 255
TRUNCATE_BYTES = 200
EMPTY_NAME = "%00"


def normpath(path: str) -> str:
    """Return an absolute, '/'-separated path.

    Repeated slashes and '.' components are collapsed; '..' is kept so
    that resolution can apply POSIX physical semantics.
    """
    parts = [p for p in path.split("/") if p not in ("", ".")]
    return "/" + "/".join(parts)


def split(path: str) -> list[str]:
    """Return the components of ``path``; ``[]`` for the root."""
    return [p for p in normpath(path).split("/") if p]


def join(base: str, name: str) -> str:
    """Join one escaped component onto an absolute path."""
    if base.endswith("/"):
        return base + name
    return base + "/" + name


def basename(path: str) -> str:
    """Return the last component of ``path`` ("/" for the root)."""
    stripped = path.rstrip("/")
    if not stripped:
        return "/"
    return stripped.rsplit("/", 1)[-1]


def dirname(path: str) -> str:
    """Return the parent of a normalised absolute path."""
    norm = normpath(path)
    head = norm.rsplit("/", 1)[0]
    return head or "/"


def _escape_char(ch: str) -> str:
    data = ch.encode("utf-8", "surrogatepass")
    return "".join(f"%{b:02X}" for b in data)


def _digest(raw: str) -> str:
    return hashlib.blake2b(raw.encode("utf-8", "surrogatepass"),
                           digest_size=8).hexdigest()


def _shorten(name: str, raw: str) -> str:
    """Fit ``name`` in MAX_NAME_BYTES: cut head + ``~digest(raw)``."""
    data = name.encode("utf-8", "surrogatepass")
    if len(data) <= MAX_NAME_BYTES:
        return name
    head = data[:TRUNCATE_BYTES].decode("utf-8", "ignore")
    return f"{head}~{_digest(raw)}"


def escape_name(raw: str) -> str:
    """Escape ``raw`` into a safe single path component.

    See ARCHITECTURE: Names and escaping.
    """
    if raw == "":
        return EMPTY_NAME
    out: list[str] = []
    for index, ch in enumerate(raw):
        code = ord(ch)
        if ch in "%/" or code < 0x20 or code == 0x7F:
            out.append(_escape_char(ch))
        elif index == 0 and ch == ".":
            out.append("%2E")
        else:
            out.append(ch)
    return _shorten("".join(out), raw)


def unescape_name(name: str) -> str:
    """Invert :func:`escape_name` (except truncation)."""
    if name == EMPTY_NAME:
        return ""
    return unquote(name, encoding="utf-8", errors="surrogatepass")


def assign_names(items: Sequence[tuple[str, str]]) -> dict[str, str]:
    """Map each ``(key, display)`` to a unique, deterministic dirname.

    Escaped display names that collide case-insensitively become
    ``display~key``; any remaining duplicate gets ``~2``, ``~3``, ...
    in sorted-key order. Every composed name is shortened again so it
    never exceeds 255 bytes (``~digest`` of the key keeps it unique).
    """
    first: dict[str, str] = {}
    for key, display in items:
        first[key] = escape_name(display)
    groups: dict[str, list[str]] = {}
    for key, name in first.items():
        groups.setdefault(name.casefold(), []).append(key)
    second: dict[str, str] = {}
    for members in groups.values():
        if len(members) == 1:
            second[members[0]] = first[members[0]]
            continue
        for key in members:
            second[key] = _shorten(first[key] + "~" + escape_name(key),
                                   key)
    by_fold: dict[str, list[str]] = {}
    for key in sorted(second):
        by_fold.setdefault(second[key].casefold(), []).append(key)
    used = set(by_fold)
    result: dict[str, str] = {}
    for keys in by_fold.values():
        result[keys[0]] = second[keys[0]]
        counter = 2
        for key in keys[1:]:
            while True:
                candidate = _shorten(f"{second[key]}~{counter}",
                                     f"{key}\x00{counter}")
                counter += 1
                if candidate.casefold() not in used:
                    break
            used.add(candidate.casefold())
            result[key] = candidate
    return result
