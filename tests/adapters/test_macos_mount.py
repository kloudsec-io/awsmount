"""macOS mount lifecycle: how fast the process follows an ``umount``."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("wsgidav")

from awsmount import platform as _platform  # noqa: E402
from awsmount.adapters.webdav import macos  # noqa: E402


class FakeServer:
    """Stands in for the WebDAV server: always up, nothing to serve."""

    instances: list[FakeServer] = []

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        self.credentials = SimpleNamespace(user="u", password="p")
        self.url = "http://127.0.0.1:1/token/"
        self.port = 1
        self.running = True
        self.stopped = False
        FakeServer.instances.append(self)

    def start(self) -> int:
        """Pretend to listen."""
        return self.port

    def stop(self) -> None:
        """Record the shutdown."""
        self.stopped = True


@pytest.fixture
def fake_mount(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Everything ``macos.mount`` touches, replaced; a mount table you set."""
    table: dict[str, Any] = {"mounted": False, "unmount_calls": 0}
    FakeServer.instances.clear()
    monkeypatch.setattr(macos, "WebDavServer", FakeServer)
    monkeypatch.setattr(macos._platform, "is_macos", lambda: True)
    monkeypatch.setattr(macos.os, "access", lambda *_a, **_k: True)

    def handshake(*_a: Any, **_k: Any) -> macos.HandshakeResult:
        table["mounted"] = True
        return macos.HandshakeResult(0, "", True, True)

    monkeypatch.setattr(macos, "_handshake", handshake)
    monkeypatch.setattr(macos._platform, "is_mounted",
                        lambda _path: bool(table["mounted"]))
    monkeypatch.setattr(macos, "disable_spotlight", lambda _path: None)

    def unmount(_path: Any) -> bool:
        table["unmount_calls"] += 1
        table["mounted"] = False
        return True

    monkeypatch.setattr(macos._platform, "unmount", unmount)
    return table


def _run(table: dict[str, Any], mountpoint: Path,
         unmount_after: float) -> tuple[int, float, list[str]]:
    """Run ``macos.mount``; "unmount" the volume ``unmount_after`` s after
    it said it was mounted.

    Returns ``(status, seconds from the unmount to the return, messages)``.
    """
    said: list[str] = []
    flipped: list[float] = []

    def flip() -> None:
        flipped.append(time.monotonic())
        table["mounted"] = False

    def echo(line: str) -> None:
        said.append(line)
        if "mounted read-only" in line:
            threading.Timer(unmount_after, flip).start()

    ctx = SimpleNamespace(config=SimpleNamespace(verbose=False))
    vfs: Any = object()
    status = macos.mount(vfs, ctx, str(mountpoint), echo=echo)
    done = time.monotonic()
    assert flipped, "the volume was never unmounted by the test"
    return status, done - flipped[0], said


def test_the_process_follows_an_unmount_within_half_a_second(
        fake_mount: dict[str, Any], tmp_path: Path) -> None:
    """``awsmount umount`` ends the mount process quickly and cleanly."""
    status, delay, said = _run(fake_mount, tmp_path / "mnt", 0.3)
    assert status == 0
    assert delay < 0.5, f"the process took {delay:.2f}s to notice"
    assert any("mounted read-only" in line for line in said)
    assert FakeServer.instances[0].stopped
    assert fake_mount["unmount_calls"] == 0, "nothing left to unmount"


@pytest.mark.parametrize("offset", [0.0, 0.1, 0.45, 0.7, 0.95])
def test_the_delay_does_not_depend_on_when_the_unmount_happens(
        fake_mount: dict[str, Any], tmp_path: Path, offset: float) -> None:
    """The old once-a-second look took up to a second, depending on timing."""
    _status, delay, _said = _run(fake_mount, tmp_path / "mnt", offset)
    assert delay < 0.5, f"unmount at +{offset}s: {delay:.2f}s to notice"


def test_a_directory_created_for_the_mount_is_removed_again(
        fake_mount: dict[str, Any], tmp_path: Path) -> None:
    """A mountpoint that awsmount made is not left behind."""
    target = tmp_path / "made-by-awsmount"
    _run(fake_mount, target, 0.2)
    assert not target.exists()


def test_a_directory_the_user_made_is_kept(
        fake_mount: dict[str, Any], tmp_path: Path) -> None:
    """A mountpoint the user created stays."""
    target = tmp_path / "mine"
    target.mkdir()
    _run(fake_mount, target, 0.2)
    assert target.is_dir()
    assert _platform.is_mounted(target) is False
