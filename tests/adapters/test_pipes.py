"""Pipe and host-command tests (``pipes.py``, ARCHITECTURE: Shell)."""

from __future__ import annotations

import io
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from awsmount.adapters.shell import pipes
from awsmount.adapters.shell.commands import STATUS_USAGE, Shell
from awsmount.adapters.shell.pipes import SHELL, run_host, split_pipe
from awsmount.session.context import Context
from awsmount.vfs.resolver import VFS

pytestmark = pytest.mark.skipif(not os.access(SHELL, os.X_OK),
                                reason="/bin/sh is required")

A_TXT = "alpha\nbeta\nGamma\n"
TREE: dict[str, Any] = {
    "docs": {"a.txt": A_TXT, "bin.dat": b"\x00\x01match\x00"},
    "empty": {},
}


class Run:
    """Run shell lines and capture ``(status, stdout, stderr)``."""

    def __init__(self, vfs: VFS, ctx: Context,
                 color: bool = False) -> None:
        self.sh = Shell(vfs, ctx, out=io.BytesIO(), err=io.StringIO(),
                        color=color)

    def __call__(self, line: str) -> tuple[int, str, str]:
        out = io.BytesIO()
        err = io.StringIO()
        self.sh.out = out
        self.sh.err = err
        status = self.sh.run_line(line)
        return status, out.getvalue().decode("utf-8", "replace"), \
            err.getvalue()


@pytest.fixture
def run(make_tree: Callable[..., VFS], ctx: Context) -> Run:
    """Shell over a small tree."""
    return Run(make_tree(TREE), ctx)


def test_split_pipe() -> None:
    """First unquoted, unescaped ``|`` only."""
    assert split_pipe("cat x | !wc -c") == ("cat x ", " !wc -c")
    assert split_pipe("cat x") == ("cat x", None)
    assert split_pipe("grep 'a|b' x") == ("grep 'a|b' x", None)
    assert split_pipe('grep "a|b" x') == ('grep "a|b" x', None)
    assert split_pipe("grep a\\|b x") == ("grep a\\|b x", None)
    assert split_pipe("a | !b | c") == ("a ", " !b | c")


def test_pipe_byte_count_matches_content(run: Run) -> None:
    """``cat x | !wc -c`` equals len(content)."""
    status, out, err = run("cat /docs/a.txt | !wc -c")
    assert (status, err) == (0, "")
    assert int(out.strip()) == len(A_TXT.encode())


def test_pipe_binary_content(run: Run) -> None:
    """Binary bytes reach the host command intact."""
    status, out, _ = run("cat /docs/bin.dat | !wc -c")
    assert status == 0
    assert int(out.strip()) == 8


def test_pipe_transforms_output(run: Run) -> None:
    """Host stdout is copied back to the shell's stdout."""
    assert run("cat /docs/a.txt | !tr a-z A-Z") == (
        0, "ALPHA\nBETA\nGAMMA\n", "")


def test_pipe_status_is_host_status(run: Run) -> None:
    """The line's status is the pipeline's status."""
    assert run("cat /docs/a.txt | !grep -q zzz")[0] == 1
    assert run("cat /docs/a.txt | !exit 7")[0] == 7


def test_pipe_keeps_builtin_stderr(run: Run) -> None:
    """Builtin errors still reach stderr; the host sees no input."""
    status, out, err = run("cat /nope | !wc -c")
    assert status == 0
    assert int(out.strip()) == 0
    assert "cat: /nope: " in err


def test_pipe_output_is_never_colored(make_tree: Callable[..., VFS],
                                      ctx: Context,
                                      monkeypatch: pytest.MonkeyPatch
                                      ) -> None:
    """Captured builtin output carries no ANSI codes."""
    monkeypatch.delenv("NO_COLOR", raising=False)
    r = Run(make_tree(TREE), ctx, color=True)
    assert "\x1b[" in r("ls /")[1]
    assert r("ls / | !cat") == (0, "docs\nempty\n", "")


def test_builtin_to_builtin_pipe_rejected(run: Run) -> None:
    """Only ``| !host`` is supported."""
    status, out, err = run("ls / | cat")
    assert (status, out) == (STATUS_USAGE, "")
    assert "pipes between builtins are not supported" in err
    assert run("ls / |")[0] == STATUS_USAGE


def test_pipe_without_command(run: Run) -> None:
    """A pipe needs a builtin on the left and a command on the right."""
    status, _out, err = run("| !wc -c")
    assert status == STATUS_USAGE
    assert "missing command before '|'" in err
    status, _out, err = run("ls / | !")
    assert status == 2
    assert "empty host command" in err


def test_host_command_sees_cwd(run: Run) -> None:
    """``!cmd`` exports AWSMOUNT_CWD."""
    assert run("cd /docs")[0] == 0
    assert run("!echo $AWSMOUNT_CWD") == (0, "/docs\n", "")


def test_host_command_stderr(run: Run) -> None:
    """Host stderr is captured into the shell's stderr."""
    assert run("!echo oops 1>&2") == (0, "", "oops\n")
    assert run("!")[0] == 2


def test_run_host_real_descriptors(tmp_path: Path) -> None:
    """Real files receive output directly."""
    out_path = tmp_path / "out"
    err_path = tmp_path / "err"
    with open(out_path, "wb") as out, open(err_path, "w") as err:
        status = run_host("printf hi; printf oops >&2", cwd="/x",
                          out=out, err=err)
    assert status == 0
    assert out_path.read_bytes() == b"hi"
    assert err_path.read_text() == "oops"


def test_run_host_env_and_stdin() -> None:
    """stdin_data is fed; AWSMOUNT_CWD is set verbatim."""
    out = io.BytesIO()
    err = io.StringIO()
    status = run_host('printf "%s|" "$AWSMOUNT_CWD"; cat', cwd="/a b",
                      out=out, err=err, stdin_data=b"payload")
    assert status == 0
    assert out.getvalue() == b"/a b|payload"


def test_run_host_signal_status() -> None:
    """Death by signal maps to 128 + signal."""
    status = run_host("kill -TERM $$", cwd="/", out=io.BytesIO(),
                      err=io.StringIO())
    assert status == 143


def test_run_host_missing_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unusable shell gives 127 and a message."""
    monkeypatch.setattr(pipes, "SHELL", "/nonexistent/awsmount-sh")
    err = io.StringIO()
    assert run_host("true", cwd="/", out=io.BytesIO(), err=err) == 127
    assert "cannot run" in err.getvalue()


def test_run_host_blank_command() -> None:
    """Blank commands are refused."""
    err = io.StringIO()
    assert run_host("   ", cwd="/", out=io.BytesIO(), err=err) == 2
    assert "empty host command" in err.getvalue()
