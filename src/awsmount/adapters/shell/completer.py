"""Tab completion for command names and VFS paths (ARCHITECTURE: Shell).

Directory listings are fetched on a worker thread; completion waits at
most two seconds. On timeout nothing is offered but the fetch keeps
running, so the next Tab is instant.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable, Iterator, Mapping
from typing import TYPE_CHECKING

from prompt_toolkit.completion import CompleteEvent, Completer, Completion
from prompt_toolkit.document import Document

from awsmount.adapters.shell.pipes import split_pipe
from awsmount.vfs.node import DirNode, Node, SymlinkNode

if TYPE_CHECKING:
    from awsmount.adapters.shell.commands import Shell

__all__ = [
    "LOOKUP_TIMEOUT",
    "VFSCompleter",
    "shell_escape",
    "split_partial",
]

LOOKUP_TIMEOUT = 2.0
_META = frozenset(" \t\n\\'\"$&|;<>()*?[]#!`{}")

Children = Mapping[str, Node]


def shell_escape(text: str) -> str:
    """Backslash-escape spaces and shell metacharacters."""
    return "".join("\\" + ch if ch in _META else ch for ch in text)


def split_partial(text: str) -> tuple[list[str], str, int]:
    """Split a partial command line.

    Returns ``(complete words, current word unescaped, raw length of the
    current word)``; the current word is empty after whitespace.
    """
    words: list[str] = []
    buf: list[str] = []
    in_word = False
    start = len(text)
    quote: str | None = None
    index = 0
    while index < len(text):
        char = text[index]
        if quote is not None:
            if char == quote:
                quote = None
            elif char == "\\" and quote == '"' and index + 1 < len(text):
                index += 1
                buf.append(text[index])
            else:
                buf.append(char)
        elif char in " \t":
            if in_word:
                words.append("".join(buf))
                buf = []
                in_word = False
        else:
            if not in_word:
                in_word = True
                start = index
            if char == "\\":
                if index + 1 < len(text):
                    index += 1
                    buf.append(text[index])
            elif char in "'\"":
                quote = char
            else:
                buf.append(char)
        index += 1
    if in_word:
        return words, "".join(buf), len(text) - start
    return words, "", 0


class _Lookup:
    """One background directory listing."""

    def __init__(self, fn: Callable[[], Children | None]) -> None:
        self.done = threading.Event()
        self.result: Children | None = None
        self._fn = fn
        self.thread = threading.Thread(target=self._run, daemon=True,
                                       name="awsmount-complete")
        self.thread.start()

    def _run(self) -> None:
        try:
            self.result = self._fn()
        except Exception:
            self.result = None
        finally:
            self.done.set()


class VFSCompleter(Completer):
    """Completes command names (first word) and VFS paths."""

    def __init__(self, shell: Shell, commands: Iterable[str],
                 timeout: float = LOOKUP_TIMEOUT) -> None:
        self._shell = shell
        self._commands = sorted(set(commands))
        self._timeout = timeout
        self._lock = threading.Lock()
        self._inflight: dict[str, _Lookup] = {}

    def _load(self, path: str) -> Children | None:
        node = self._shell.vfs.resolve(path, follow=True)
        if isinstance(node, DirNode):
            return node.children()
        return None

    def children_of(self, path: str) -> Children | None:
        """Children of the directory at ``path``; None on timeout."""
        with self._lock:
            lookup = self._inflight.get(path)
            if lookup is not None and lookup.done.is_set():
                del self._inflight[path]
                return lookup.result
            if lookup is None:
                lookup = _Lookup(lambda: self._load(path))
                self._inflight[path] = lookup
        if not lookup.done.wait(self._timeout):
            return None
        with self._lock:
            if self._inflight.get(path) is lookup:
                del self._inflight[path]
        return lookup.result

    def get_completions(self, document: Document,
                        complete_event: CompleteEvent
                        ) -> Iterator[Completion]:
        """Yield completions for the text before the cursor."""
        text = document.text_before_cursor
        if text.lstrip().startswith("!"):
            return
        _left, right = split_pipe(text)
        if right is not None:
            return
        words, current, raw_len = split_partial(text)
        if not words:
            for name in self._commands:
                if name.startswith(current):
                    yield Completion(name, start_position=-raw_len)
            return
        yield from self._paths(current, raw_len)

    def _paths(self, current: str, raw_len: int) -> Iterator[Completion]:
        if "/" in current:
            head, prefix = current.rsplit("/", 1)
            dir_text = head + "/"
            lookup = head or "/"
        else:
            dir_text = ""
            prefix = current
            lookup = "."
        children = self.children_of(self._shell.abspath(lookup))
        if children is None:
            return
        for name, node in children.items():
            if not name.startswith(prefix):
                continue
            is_dir = isinstance(node, (DirNode, SymlinkNode))
            suffix = "/" if is_dir else ""
            yield Completion(shell_escape(dir_text + name) + suffix,
                             start_position=-raw_len,
                             display=name + suffix)
