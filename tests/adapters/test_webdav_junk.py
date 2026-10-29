"""macOS junk names are rejected before the VFS is touched.

A real cheroot server serves a small hand-built tree. A spy wraps
``VFS.resolve`` and the root's ``child`` lookup, so the tests can
prove that requests for ``.DS_Store``, ``._*``, Spotlight and similar
names get a 404 without any VFS access. They also prove that this
happens before authentication and the token check. Near-miss names
still reach the VFS, which shows that the spy is wired.
"""

from __future__ import annotations

import http.client
import threading
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import pytest

pytest.importorskip("wsgidav")
pytest.importorskip("cheroot")

from awsmount.adapters.webdav.server import (  # noqa: E402
    JUNK_NAMES,
    WebDavServer,
    is_junk,
)
from awsmount.config import Config  # noqa: E402
from awsmount.session.context import Context  # noqa: E402
from awsmount.vfs.node import Content, DirNode, FileNode, Node  # noqa
from awsmount.vfs.resolver import VFS  # noqa: E402

JUNK = (
    ".DS_Store",
    "._x",
    "._notes.txt",
    "._",
    ".metadata_never_index",
    ".metadata_never_index_unless_rootfs",
    ".Spotlight-V100",
    ".Trashes",
    ".fseventsd",
    ".hidden",
    ".localized",
    ".VolumeIcon.icns",
    ".TemporaryItems",
    ".com.apple.timemachine.donotpresent",
    "Icon\r",
    "desktop.ini",
)
NEAR_MISSES = ("notes._x", "DS_Store", "x.DS_Store", "Icon",
               "Spotlight-V100", "_x")
METHODS = ("GET", "HEAD", "PROPFIND", "PUT", "DELETE", "MKCOL")


def _const(value: Content) -> Callable[[], Content]:
    def render() -> Content:
        return value
    return render


def _build_vfs(ctx: Context) -> VFS:
    """``/notes.txt`` and ``/dir/inner.txt``."""

    def load_dir(node: DirNode) -> list[Node]:
        return [FileNode("inner.txt", node, ctx, _const("inner"),
                         lazy=False)]

    def load_root(node: DirNode) -> list[Node]:
        return [FileNode("notes.txt", node, ctx, _const("notes"),
                         lazy=False),
                DirNode("dir", node, ctx, load_dir)]

    return VFS(DirNode("", None, ctx, load_root, static=True))


class VfsSpy:
    """Records every ``resolve`` and root ``child`` call."""

    def __init__(self, vfs: VFS) -> None:
        self._lock = threading.Lock()
        self.resolves: list[str] = []
        self.lookups: list[str] = []
        self._resolve = vfs.resolve
        self._child = vfs.root.child
        vfs.resolve = self.resolve  # type: ignore[method-assign]
        vfs.root.child = self.child  # type: ignore[method-assign]

    def resolve(self, path: str, *, follow: bool = True) -> Node:
        """Spy for ``VFS.resolve``."""
        with self._lock:
            self.resolves.append(path)
        return self._resolve(path, follow=follow)

    def child(self, name: str) -> Node | None:
        """Spy for the root's ``child``."""
        with self._lock:
            self.lookups.append(name)
        return self._child(name)

    @property
    def touched(self) -> int:
        """Total number of recorded VFS accesses."""
        with self._lock:
            return len(self.resolves) + len(self.lookups)

    def reset(self) -> None:
        """Forget recorded calls."""
        with self._lock:
            self.resolves.clear()
            self.lookups.clear()


@dataclass(frozen=True)
class Reply:
    """One HTTP response."""

    status: int
    headers: dict[str, str]
    body: bytes


@dataclass
class Served:
    """Running server, its spy and a request helper."""

    server: WebDavServer
    spy: VfsSpy

    @property
    def token(self) -> str:
        """Session token."""
        return self.server.credentials.token

    def request(self, method: str, path: str, *, auth: bool = True,
                headers: Mapping[str, str] | None = None) -> Reply:
        """Send one request on a fresh connection."""
        hdrs: dict[str, str] = {}
        if auth:
            hdrs["Authorization"] = self.server.credentials.basic_header()
        if method == "PROPFIND":
            hdrs["Depth"] = "0"
        hdrs.update(headers or {})
        body: bytes | None = b"x" if method == "PUT" else None
        conn = http.client.HTTPConnection("127.0.0.1", self.server.port,
                                          timeout=30)
        try:
            conn.request(method, path, body=body, headers=hdrs)
            resp = conn.getresponse()
            data = resp.read()
            return Reply(resp.status,
                         {k.lower(): v for k, v in resp.getheaders()},
                         data)
        finally:
            conn.close()


@pytest.fixture(scope="module")
def served() -> Iterator[Served]:
    """A real server over a spied, hand-built tree (no AWS)."""
    ctx = Context.from_config(Config(regions=("us-east-1",)))
    vfs = _build_vfs(ctx)
    spy = VfsSpy(vfs)
    server = WebDavServer(vfs, port=0)
    server.start()
    try:
        yield Served(server, spy)
    finally:
        server.stop()


@pytest.fixture
def junk_server(served: Served) -> Served:
    """The module server with a freshly reset spy."""
    served.spy.reset()
    return served


def _paths(token: str, name: str) -> list[str]:
    q = quote(name)
    return [
        f"/{token}/{q}",
        f"/{token}/dir/{q}",
        f"/{token}/{q}/notes.txt",
        f"/{token}/dir/{q}/deeper/x",
        f"/{q}",
        f"/{q}/{token}/notes.txt",
    ]


# ---------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------


@pytest.mark.parametrize("name", JUNK)
def test_is_junk(name: str) -> None:
    """Every documented junk name is recognised."""
    assert is_junk(name)


@pytest.mark.parametrize("name", NEAR_MISSES + ("notes.txt", "dir"))
def test_is_not_junk(name: str) -> None:
    """Near misses and real names are not junk."""
    assert not is_junk(name)


def test_junk_table_matches_design() -> None:
    """Every fixed name of the design table is in JUNK_NAMES."""
    for name in JUNK:
        if not name.startswith("._"):
            assert name in JUNK_NAMES, name


def test_spy_is_wired(junk_server: Served) -> None:
    """A real file request does reach the VFS."""
    reply = junk_server.request("GET", f"/{junk_server.token}/notes.txt")
    assert reply.status == 200
    assert reply.body == b"notes\n"
    assert junk_server.spy.touched > 0


@pytest.mark.parametrize("name", JUNK)
@pytest.mark.parametrize("method", METHODS)
def test_junk_is_404_without_vfs_access(junk_server: Served, name: str,
                                        method: str) -> None:
    """Junk names in any component are 404 before the VFS."""
    for path in _paths(junk_server.token, name):
        reply = junk_server.request(method, path)
        assert reply.status == 404, (method, path)
        if method == "HEAD":
            assert reply.body == b""
    assert junk_server.spy.touched == 0


@pytest.mark.parametrize("name", [".DS_Store", "._x", ".Spotlight-V100",
                                  ".metadata_never_index"])
def test_junk_is_404_before_auth(junk_server: Served, name: str) -> None:
    """No credentials needed to get a quick 404, and no auth challenge."""
    for path in _paths(junk_server.token, name):
        for method in ("GET", "HEAD", "PROPFIND"):
            reply = junk_server.request(method, path, auth=False)
            assert reply.status == 404, (method, path)
            assert "www-authenticate" not in reply.headers
    assert junk_server.spy.touched == 0


def test_junk_with_wrong_password_is_404(junk_server: Served) -> None:
    """Even a bad Authorization header does not reach wsgidav."""
    reply = junk_server.request(
        "GET", f"/{junk_server.token}/._notes.txt",
        headers={"Authorization": "Basic YXdzbW91bnQ6d3Jvbmc="})
    assert reply.status == 404
    assert junk_server.spy.touched == 0


@pytest.mark.parametrize("name", NEAR_MISSES)
def test_near_misses_reach_the_vfs(junk_server: Served,
                                   name: str) -> None:
    """Names that merely resemble junk go through the normal path."""
    reply = junk_server.request("GET",
                                f"/{junk_server.token}/{quote(name)}")
    assert reply.status == 404
    assert junk_server.spy.touched > 0


def test_junk_still_requires_loopback_host(junk_server: Served) -> None:
    """The Host check runs before the junk filter."""
    reply = junk_server.request(
        "GET", f"/{junk_server.token}/.DS_Store",
        headers={"Host": "evil.example"})
    assert reply.status == 421
    assert junk_server.spy.touched == 0


def _unused(_value: Any) -> None:
    """Keep the typing import meaningful for mypy --strict users."""
    return None
