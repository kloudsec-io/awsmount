"""How the WebDAV server reports a file that cannot be rendered.

A real cheroot server serves a small hand-built tree whose lazy files
fail in a chosen way (AWS AccessDenied, a guard refusal, an upstream
error). The tests check three things:

* a PROPFIND on such a file still succeeds, so a client does not take
  the file for missing (macOS reported ENOENT for a direct read);
* the error comes from the GET, with the status the server was given for
  an AccessDenied: 403 by default (``awsmount serve``), 401 for the macOS
  mount, because ``mount_webdav`` shows 401 as "Permission denied" (what
  FUSE reports) and 403 as "Operation not permitted";
* a guard refusal stays 403 and an upstream failure stays 503, so the
  macOS mount can tell them apart.
"""

from __future__ import annotations

import http.client
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

import pytest

pytest.importorskip("wsgidav")
pytest.importorskip("cheroot")

from awsmount.adapters.webdav.macos import (  # noqa: E402
    ACCESS_DENIED_STATUS,
)
from awsmount.adapters.webdav.provider import VFSDavProvider  # noqa: E402
from awsmount.adapters.webdav.server import WebDavServer  # noqa: E402
from awsmount.config import Config  # noqa: E402
from awsmount.errors import (  # noqa: E402
    ForbiddenOperation,
    PermissionDenied,
    UpstreamError,
)
from awsmount.session.context import Context  # noqa: E402
from awsmount.vfs.node import Content, DirNode, FileNode, Node  # noqa
from awsmount.vfs.resolver import VFS  # noqa: E402

PROPFIND_BODY = (b'<?xml version="1.0" encoding="utf-8"?>\n'
                 b'<D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>\n')


def _raises(exc: Exception) -> Callable[[], Content]:
    def render() -> Content:
        raise exc
    return render


def _build_vfs(ctx: Context) -> VFS:
    """``/ok.txt`` plus lazy files that fail in different ways."""

    def load_root(node: DirNode) -> list[Node]:
        return [
            FileNode("ok.txt", node, ctx, lambda: "fine", lazy=True),
            FileNode("denied.json", node, ctx,
                     _raises(PermissionDenied("AccessDenied")), lazy=True),
            FileNode("guard.json", node, ctx,
                     _raises(ForbiddenOperation("blocked")), lazy=True),
            FileNode("upstream.json", node, ctx,
                     _raises(UpstreamError("boom")), lazy=True),
        ]

    return VFS(DirNode("", None, ctx, load_root, static=True))


@dataclass(frozen=True)
class Reply:
    """One HTTP response."""

    status: int
    body: bytes


@dataclass
class Served:
    """A running server and a request helper."""

    server: WebDavServer

    def request(self, method: str, name: str,
                depth: str = "0") -> Reply:
        """One authenticated request for ``/<token>/<name>``."""
        headers = {"Authorization": self.server.credentials.basic_header()}
        body = None
        if method == "PROPFIND":
            headers["Depth"] = depth
            headers["Content-Type"] = "application/xml; charset=utf-8"
            body = PROPFIND_BODY
        conn = http.client.HTTPConnection("127.0.0.1", self.server.port,
                                          timeout=30)
        try:
            conn.request(method, f"/{self.server.credentials.token}/{name}",
                         body=body, headers=headers)
            resp = conn.getresponse()
            return Reply(resp.status, resp.read())
        finally:
            conn.close()


def _serve(denied_status: int | None) -> Iterator[Served]:
    ctx = Context.from_config(Config(regions=("us-east-1",)))
    kwargs: dict[str, Any] = {}
    if denied_status is not None:
        kwargs["denied_status"] = denied_status
    server = WebDavServer(_build_vfs(ctx), port=0, **kwargs)
    server.start()
    try:
        yield Served(server)
    finally:
        server.stop()


@pytest.fixture(scope="module")
def serve_mode() -> Iterator[Served]:
    """Default server, as started by ``awsmount serve``."""
    yield from _serve(None)


@pytest.fixture(scope="module")
def mount_mode() -> Iterator[Served]:
    """Server as started by the macOS mount."""
    yield from _serve(ACCESS_DENIED_STATUS)


def test_macos_mount_uses_401_serve_keeps_403() -> None:
    assert ACCESS_DENIED_STATUS == 401
    ctx = Context.from_config(Config(regions=("us-east-1",)))
    assert WebDavServer(_build_vfs(ctx)).denied_status == 403


def test_provider_rejects_other_statuses() -> None:
    ctx = Context.from_config(Config(regions=("us-east-1",)))
    with pytest.raises(ValueError):
        VFSDavProvider(_build_vfs(ctx), denied_status=404)


@pytest.mark.parametrize("name", ["denied.json", "guard.json",
                                  "upstream.json"])
@pytest.mark.parametrize("mode", ["serve_mode", "mount_mode"])
def test_propfind_on_a_failing_file_still_succeeds(
        request: pytest.FixtureRequest, mode: str, name: str) -> None:
    served: Served = request.getfixturevalue(mode)
    reply = served.request("PROPFIND", name)
    assert reply.status == 207, reply.body[:200]
    assert name.encode() in reply.body


def test_listing_with_failing_files_succeeds(serve_mode: Served) -> None:
    reply = serve_mode.request("PROPFIND", "", depth="1")
    assert reply.status == 207
    for name in (b"denied.json", b"guard.json", b"upstream.json"):
        assert name in reply.body


def test_get_denied_is_403_for_serve(serve_mode: Served) -> None:
    assert serve_mode.request("GET", "denied.json").status == 403


def test_get_denied_is_401_for_the_macos_mount(mount_mode: Served) -> None:
    assert mount_mode.request("GET", "denied.json").status == 401


@pytest.mark.parametrize("mode", ["serve_mode", "mount_mode"])
def test_guard_refusal_stays_403(request: pytest.FixtureRequest,
                                 mode: str) -> None:
    served: Served = request.getfixturevalue(mode)
    assert served.request("GET", "guard.json").status == 403


@pytest.mark.parametrize("mode", ["serve_mode", "mount_mode"])
def test_upstream_error_stays_503(request: pytest.FixtureRequest,
                                  mode: str) -> None:
    served: Served = request.getfixturevalue(mode)
    assert served.request("GET", "upstream.json").status == 503


@pytest.mark.parametrize("mode", ["serve_mode", "mount_mode"])
def test_working_file_unaffected(request: pytest.FixtureRequest,
                                 mode: str) -> None:
    served: Served = request.getfixturevalue(mode)
    reply = served.request("GET", "ok.txt")
    assert reply.status == 200 and reply.body == b"fine\n"
    props = served.request("PROPFIND", "ok.txt")
    assert props.status == 207 and b"getcontentlength" in props.body
