"""Tab completion tests (ARCHITECTURE: Shell)."""

from __future__ import annotations

import io
import threading
import time
from collections.abc import Callable
from typing import Any

import pytest
from prompt_toolkit.completion import CompleteEvent, Completion
from prompt_toolkit.document import Document

from awsmount.adapters.shell.commands import COMMANDS, Shell
from awsmount.adapters.shell.completer import (
    LOOKUP_TIMEOUT,
    VFSCompleter,
    shell_escape,
    split_partial,
)
from awsmount.session.context import Context
from awsmount.vfs.node import Content, DirNode, FileNode, Node
from awsmount.vfs.resolver import VFS

TREE: dict[str, Any] = {
    "docs": {
        "a.txt": "a",
        "b.json": ("json", {}),
        "sub": {"deep.txt": "d"},
        "with space": "s",
    },
    "esc": {"%2Ehidden": "h", "team%2Fowner": "o"},
    "lines.txt": "l",
    "links": {"to-docs": ("link", "../docs")},
}


def _const(value: Content) -> Callable[[], Content]:
    def render() -> Content:
        return value
    return render


def complete(completer: VFSCompleter, text: str) -> list[Completion]:
    """All completions for ``text`` with the cursor at the end."""
    return list(completer.get_completions(Document(text), CompleteEvent()))


def texts(completions: list[Completion]) -> list[str]:
    """Completion texts."""
    return [c.text for c in completions]


def _shell(vfs: VFS, ctx: Context, cwd: str = "/") -> Shell:
    return Shell(vfs, ctx, out=io.BytesIO(), err=io.StringIO(),
                 color=False, cwd=cwd)


@pytest.fixture
def shell(make_tree: Callable[..., VFS], ctx: Context) -> Shell:
    """Shell over the completion tree."""
    return _shell(make_tree(TREE), ctx)


@pytest.fixture
def completer(shell: Shell) -> VFSCompleter:
    """Completer with a generous timeout."""
    return VFSCompleter(shell, COMMANDS, timeout=5.0)


# -- helpers -------------------------------------------------------------


def test_default_timeout_is_two_seconds() -> None:
    """Completion waits at most 2 s for a listing."""
    assert LOOKUP_TIMEOUT == 2.0


def test_split_partial() -> None:
    """Words, the unescaped current word and its raw length."""
    assert split_partial("") == ([], "", 0)
    assert split_partial("ls /do") == (["ls"], "/do", 3)
    assert split_partial("ls ") == (["ls"], "", 0)
    assert split_partial("cat with\\ sp") == (["cat"], "with sp", 8)
    assert split_partial('cat "a b') == (["cat"], "a b", 4)
    assert split_partial("cat 'x y' z") == (["cat", "x y"], "z", 1)


def test_shell_escape() -> None:
    """Spaces and metacharacters are backslash-escaped."""
    assert shell_escape("with space") == "with\\ space"
    assert shell_escape("a$b") == "a\\$b"
    assert shell_escape("x|y;z") == "x\\|y\\;z"
    assert shell_escape("plain-name_1.json") == "plain-name_1.json"
    assert shell_escape("%2Ehidden") == "%2Ehidden"


# -- commands ------------------------------------------------------------


def test_first_word_completes_commands(completer: VFSCompleter) -> None:
    """The first word completes command names."""
    assert texts(complete(completer, "c")) == ["cache", "cat", "cd"]
    assert texts(complete(completer, "he")) == ["head", "help"]
    assert texts(complete(completer, "zz")) == []
    every = texts(complete(completer, ""))
    assert every == sorted(COMMANDS)


def test_command_start_position(completer: VFSCompleter) -> None:
    """The partial word is replaced."""
    (only,) = complete(completer, "whoa")
    assert (only.text, only.start_position) == ("whoami", -4)


# -- paths ---------------------------------------------------------------


def test_absolute_path_prefix(completer: VFSCompleter) -> None:
    """Dirs get a trailing slash; the word is replaced."""
    (only,) = complete(completer, "ls /d")
    assert only.text == "/docs/"
    assert only.start_position == -2
    assert only.display_text == "docs/"


def test_directory_contents(completer: VFSCompleter) -> None:
    """Every child, escaped, with display names unescaped."""
    found = complete(completer, "cat /docs/")
    assert texts(found) == ["/docs/a.txt", "/docs/b.json", "/docs/sub/",
                            "/docs/with\\ space"]
    assert {c.start_position for c in found} == {-6}
    assert found[-1].display_text == "with space"


def test_empty_word_completes_cwd(completer: VFSCompleter) -> None:
    """After a space, the cwd children are offered."""
    found = complete(completer, "cd ")
    assert texts(found) == ["docs/", "esc/", "lines.txt", "links/"]
    assert {c.start_position for c in found} == {0}


def test_escaped_partial_word(completer: VFSCompleter) -> None:
    """A backslash-escaped space is part of the prefix."""
    (only,) = complete(completer, "cat /docs/with\\ s")
    assert only.text == "/docs/with\\ space"
    assert only.start_position == -len("/docs/with\\ s")


def test_quoted_partial_word(completer: VFSCompleter) -> None:
    """An open quote is replaced by the escaped completion."""
    (only,) = complete(completer, 'cat "/docs/wi')
    assert only.text == "/docs/with\\ space"
    assert only.start_position == -len('"/docs/wi')


def test_symlinked_directory_gets_slash(completer: VFSCompleter) -> None:
    """Links are completed like directories."""
    assert texts(complete(completer, "ls /links/to-d")) == [
        "/links/to-docs/"]
    assert texts(complete(completer, "ls /links/to-docs/s")) == [
        "/links/to-docs/sub/"]


def test_escaped_names_are_offered_verbatim(
        completer: VFSCompleter) -> None:
    """Escaped VFS names are completed as stored."""
    assert texts(complete(completer, "cat /esc/")) == [
        "/esc/%2Ehidden", "/esc/team%2Fowner"]


def test_relative_paths(make_tree: Callable[..., VFS],
                        ctx: Context) -> None:
    """Relative words resolve against the logical cwd."""
    comp = VFSCompleter(_shell(make_tree(TREE), ctx, cwd="/docs"),
                        COMMANDS, timeout=5.0)
    assert texts(complete(comp, "cat s")) == ["sub/"]
    assert texts(complete(comp, "cat ../l")) == ["../lines.txt",
                                                 "../links/"]


def test_no_completion_for_missing_or_file(
        completer: VFSCompleter) -> None:
    """Missing dirs and files used as dirs complete nothing."""
    assert complete(completer, "ls /nope/x") == []
    assert complete(completer, "cat /lines.txt/x") == []


def test_no_completion_for_host_commands(completer: VFSCompleter) -> None:
    """Nothing after ``!`` or a pipe."""
    assert complete(completer, "!ls /") == []
    assert complete(completer, "  !ls /d") == []
    assert complete(completer, "cat /lines.txt | !w") == []
    assert complete(completer, "cat /lines.txt | gr") == []


def test_loaded_directory_completes_quickly(
        completer: VFSCompleter) -> None:
    """A memoised directory completes immediately."""
    assert len(complete(completer, "cat /docs/")) == 4
    start = time.monotonic()
    assert len(complete(completer, "cat /docs/")) == 4
    assert time.monotonic() - start < 0.5


def test_slow_directory_times_out_then_completes(
        make_tree: Callable[..., VFS], ctx: Context) -> None:
    """Empty on timeout; the fetch continues; next Tab is served."""
    release = threading.Event()
    calls: list[int] = []

    def slow(node: DirNode) -> list[Node]:
        calls.append(1)
        release.wait(10)
        return [FileNode("ready.txt", node, node.ctx, _const("x"),
                         lazy=False)]

    sh = _shell(make_tree({"slow": ("dirfn", slow)}), ctx)
    comp = VFSCompleter(sh, COMMANDS, timeout=0.3)
    try:
        start = time.monotonic()
        assert complete(comp, "cat /slow/") == []
        assert time.monotonic() - start < 2.0
    finally:
        release.set()
    deadline = time.monotonic() + 5.0
    found: list[str] = []
    while not found and time.monotonic() < deadline:
        found = texts(complete(comp, "cat /slow/"))
    assert found == ["/slow/ready.txt"]
    assert calls == [1]
