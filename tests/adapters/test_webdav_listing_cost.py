"""A WebDAV directory listing must not fetch lazy files from AWS.

Found on a real mount: ``find . -name s3`` over nine accounts took more
than seven minutes, because every ``PROPFIND`` (one per directory) asked
for the size, ETag and times of each child, and each answer rendered the
file, which for lazy files means AWS API calls. On a small sandbox the same
``find`` made 637 calls; after the fix it makes none for file rendering.
"""

from __future__ import annotations

from typing import Any

from awsmount.adapters.webdav.provider import VFSDavProvider, VFSFile
from awsmount.config import Config
from awsmount.session.context import Context
from awsmount.vfs.node import DirNode, FileNode
from awsmount.vfs.resolver import VFS


class Rig:
    """A one-file VFS whose renderer counts how often it is called."""

    def __init__(self, *, lazy: bool) -> None:
        self.renders = 0
        ctx = Context.from_config(Config(
            regions=("us-east-1",), endpoint_url="http://127.0.0.1:9"))
        root = DirNode("", None, ctx, lambda d: [], static=True)
        self.node = FileNode("policy.json", root, ctx, self._render,
                             lazy=lazy)
        self.provider = VFSDavProvider(VFS(root))

    def _render(self) -> dict[str, Any]:
        self.renders += 1
        return {"Statement": ["x" * 50]}

    def dav(self, method: str = "PROPFIND", depth: str | None = "1"
            ) -> VFSFile:
        """The DAV resource as the server builds it for one request."""
        environ: dict[str, Any] = {"REQUEST_METHOD": method,
                                   "wsgidav.provider": self.provider}
        if depth is not None:
            environ["HTTP_DEPTH"] = depth
        return VFSFile("/policy.json", environ, self.provider, self.node)


def test_listing_does_not_render_an_unrendered_lazy_file() -> None:
    rig = Rig(lazy=True)
    res = rig.dav(depth="1")
    assert res.get_content_length() is None       # property omitted
    res.get_last_modified()
    res.get_creation_date()
    res.get_etag()
    assert rig.renders == 0


def test_asking_about_the_single_file_renders_it_once() -> None:
    rig = Rig(lazy=True)
    length = rig.dav(depth="0").get_content_length()
    assert length is not None and length > 20
    assert rig.renders == 1
    # a following listing now reuses the cached render: size is known
    assert rig.dav(depth="1").get_content_length() == length
    assert rig.renders == 1


def test_reading_the_file_returns_the_full_content() -> None:
    rig = Rig(lazy=True)
    rig.dav(depth="1").get_content_length()       # listing first
    res = rig.dav(method="GET", depth=None)
    body = res.get_content().read()
    assert len(body) == res.get_content_length()
    assert b"xxxxxxxxxx" in body
    assert rig.renders == 1


def test_non_lazy_files_keep_reporting_their_size_in_listings() -> None:
    rig = Rig(lazy=False)
    assert rig.dav(depth="1").get_content_length() is not None


def test_listing_etag_is_stable_and_changes_once_rendered() -> None:
    rig = Rig(lazy=True)
    first = rig.dav(depth="1").get_etag()
    assert rig.dav(depth="1").get_etag() == first
    rig.dav(depth="0").get_content_length()       # render it
    assert rig.dav(depth="1").get_etag() != first
