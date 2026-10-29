"""Progress counter: in-place line, line breaks before other messages."""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import pytest

from awsmount.config import Config
from awsmount.session import context as context_module
from awsmount.session import progress as progress_module
from awsmount.session.context import Context
from awsmount.session.progress import LINE_EVERY, TTY_INTERVAL, Progress
from awsmount.session.progress import clear_line

ERASE = "\r\x1b[K"


class Tty(io.StringIO):
    """A stream that claims to be a terminal."""

    def isatty(self) -> bool:
        """Always a terminal."""
        return True


def _ticking() -> Any:
    """A clock that moves past the redraw interval on every call."""
    now = [0.0]

    def clock() -> float:
        now[0] += TTY_INTERVAL + 1.0
        return now[0]

    return clock


@pytest.fixture(autouse=True)
def _no_active_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every test starts with no unfinished counter line."""
    monkeypatch.setattr(progress_module, "_active", None)


def test_terminal_counter_is_rewritten_in_place() -> None:
    """On a terminal the counter is one line redrawn with a carriage return."""
    stream = Tty()
    progress = Progress(True, stream, clock=_ticking())
    progress.tick("ec2:DescribeVpcs")
    progress.tick("ec2:DescribeSubnets")
    out = stream.getvalue()
    assert out.count("\r") == 2
    assert "\n" not in out
    assert out.endswith("api calls 2 ec2:DescribeSubnets\x1b[K")


def test_clear_line_erases_the_counter_before_another_message() -> None:
    """The next message starts on a clean line, not glued to the counter."""
    stream = Tty()
    progress = Progress(True, stream, clock=_ticking())
    progress.tick("iam:ListAccountAliases")
    clear_line()
    assert stream.getvalue().endswith(ERASE)
    before = stream.getvalue()
    progress.finish()
    assert stream.getvalue() == before, "nothing left to terminate"


def test_clear_line_twice_writes_once() -> None:
    """Nothing is erased when the line is already clean."""
    stream = Tty()
    progress = Progress(True, stream, clock=_ticking())
    progress.tick("x")
    clear_line()
    size = len(stream.getvalue())
    clear_line()
    assert len(stream.getvalue()) == size


def test_counter_resumes_after_a_clear() -> None:
    """Ticking again after a clear redraws the counter."""
    stream = Tty()
    progress = Progress(True, stream, clock=_ticking())
    progress.tick("a")
    clear_line()
    progress.tick("b")
    assert stream.getvalue().endswith("api calls 2 b\x1b[K")
    progress.finish()
    assert stream.getvalue().endswith("\n")


def test_clear_line_without_any_counter_is_a_no_op() -> None:
    """Disabled or never-used counters write nothing."""
    clear_line()
    stream = Tty()
    Progress(False, stream).tick("x")
    clear_line()
    assert stream.getvalue() == ""


def test_pipe_output_is_whole_lines_every_hundred_calls() -> None:
    """Off a terminal there is no carriage return and nothing to clear."""
    stream = io.StringIO()
    progress = Progress(True, stream)
    for _ in range(LINE_EVERY):
        progress.tick("x")
    assert stream.getvalue() == f"[awsmount] api calls {LINE_EVERY} x\n"
    clear_line()
    assert "\r" not in stream.getvalue()


def test_verbose_error_echo_starts_on_a_clean_line(
        capsys: pytest.CaptureFixture[str]) -> None:
    """``[awsmount] error ...`` is not appended to the counter."""
    stream = Tty()
    Progress(True, stream, clock=_ticking()).tick("kms:ListResourceTags")
    context_module._stderr_echo("one TSV line")
    assert stream.getvalue().endswith(ERASE)
    assert capsys.readouterr().err == "[awsmount] error one TSV line\n"


def test_failed_profile_line_starts_on_a_clean_line(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]) -> None:
    """The failed-profile message is not appended to the counter."""
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE",
                       str(tmp_path / "credentials"))
    stream = Tty()
    Progress(True, stream, clock=_ticking()).tick("sts:GetCallerIdentity")
    ctx = Context.from_config(Config(profiles=("typo",),
                                     regions=("us-east-1",)))
    ctx.accounts.accounts()
    assert stream.getvalue().endswith(ERASE)
    err = capsys.readouterr().err
    assert err.startswith("awsmount: profile typo: ")
    assert err.endswith("; nothing is shown for it\n")


def test_failed_profile_line_has_no_dot_before_the_semicolon(
        capsys: pytest.CaptureFixture[str]) -> None:
    """An AWS message ends with a period; the line must not say ``.;``."""
    ctx = Context.from_config(Config(profiles=("p",)))
    ctx.accounts._note_failure(  # noqa: SLF001 - the formatting is the unit
        "p", "The security token included in the request is invalid.")
    assert capsys.readouterr().err == (
        "awsmount: profile p: The security token included in the request "
        "is invalid; nothing is shown for it\n")
