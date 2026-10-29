"""VFS resolution, listing and reading.

See ARCHITECTURE: Nodes and rendering, Path resolution.
"""

from __future__ import annotations

import errno
import json
from collections.abc import Callable
from typing import Any

import pytest

from awsmount.errors import (
    AwsMountError,
    IsADirectory,
    NotADirectory,
    NotFound,
)
from awsmount.session.context import Context
from awsmount.vfs.node import DirNode, FileNode, Node
from awsmount.vfs.render import render
from awsmount.vfs.resolver import VFS

SPEC = {
    "a": {"b": {"file.txt": "hello"}, "data.json": ("json", {"k": "v"})},
    "top.txt": "x",
    "empty": {},
}

MakeTree = Callable[..., VFS]


@pytest.fixture
def fs(make_tree: MakeTree) -> VFS:
    """A small hand-built tree."""
    return make_tree(SPEC)


def test_root(fs: VFS) -> None:
    """'/' and '' resolve to the root."""
    assert fs.resolve("/") is fs.root
    assert fs.resolve("") is fs.root
    assert fs.root.path == "/"


def test_nested_path(fs: VFS) -> None:
    """Paths are absolute escaped components."""
    node = fs.resolve("/a/b/file.txt")
    assert isinstance(node, FileNode)
    assert node.path == "/a/b/file.txt"


def test_relative_input_is_absolute(fs: VFS) -> None:
    """A path without a leading slash is taken from the root."""
    assert fs.resolve("a/b").path == "/a/b"


def test_dot_is_skipped(fs: VFS) -> None:
    """'.' components are ignored."""
    assert fs.resolve("/a/./b/.").path == "/a/b"


def test_dotdot_at_root_stays(fs: VFS) -> None:
    """'..' at the root stays at the root."""
    assert fs.resolve("/../..") is fs.root
    assert fs.resolve("/../a").path == "/a"
    assert fs.resolve("/a/b/../..") is fs.root
    assert fs.resolve("/a/b/../../top.txt").path == "/top.txt"


def test_missing_is_enoent(fs: VFS) -> None:
    """Missing path -> NotFound (ENOENT)."""
    with pytest.raises(NotFound) as info:
        fs.resolve("/a/nope")
    assert info.value.errno == errno.ENOENT
    assert isinstance(info.value, AwsMountError)


def test_missing_under_missing(fs: VFS) -> None:
    """Missing intermediate dir is also ENOENT."""
    with pytest.raises(NotFound):
        fs.resolve("/nope/deeper/still")


def test_through_file_is_enotdir(fs: VFS) -> None:
    """Traversing through a file -> NotADirectory (ENOTDIR)."""
    with pytest.raises(NotADirectory) as info:
        fs.resolve("/top.txt/x")
    assert info.value.errno == errno.ENOTDIR


def test_file_dotdot_is_enotdir(fs: VFS) -> None:
    """POSIX: 'file/..' is ENOTDIR, not the parent."""
    with pytest.raises(NotADirectory):
        fs.resolve("/top.txt/..")


def test_trailing_slash(fs: VFS) -> None:
    """Trailing slash requires a directory."""
    assert fs.resolve("/a/").path == "/a"
    with pytest.raises(NotADirectory):
        fs.resolve("/top.txt/")


def test_read_directory_is_eisdir(fs: VFS) -> None:
    """Reading a directory -> IsADirectory (EISDIR)."""
    with pytest.raises(IsADirectory) as info:
        fs.read("/a")
    assert info.value.errno == errno.EISDIR


def test_listdir_file_is_enotdir(fs: VFS) -> None:
    """Listing a file -> ENOTDIR."""
    with pytest.raises(NotADirectory):
        fs.listdir("/top.txt")


def test_listdir_sorted_by_name(make_tree: MakeTree) -> None:
    """Children are sorted by (code point) name."""
    vfs = make_tree({"b": "1", "a": "2", "C": "3", "_x": "4"})
    assert vfs.listdir("/") == ["C", "_x", "a", "b"]


def test_listdir_empty_and_nested(fs: VFS) -> None:
    """Empty dirs list as []."""
    assert fs.listdir("/empty") == []
    assert fs.listdir("/a") == ["b", "data.json"]


def test_read_full_and_ranges(fs: VFS) -> None:
    """read() supports offset/length; -1 means to the end."""
    assert fs.read("/a/b/file.txt") == b"hello\n"
    assert fs.read("/a/b/file.txt", 1, 3) == b"ell"
    assert fs.read("/a/b/file.txt", 2) == b"llo\n"
    assert fs.read("/a/b/file.txt", 100, 5) == b""
    assert fs.read("/a/b/file.txt", 0, 0) == b""


def test_read_json_file(fs: VFS) -> None:
    """JSON content is rendered canonically."""
    assert fs.read("/a/data.json") == b'{\n  "k": "v"\n}\n'


def test_duplicate_child_names_raise(ctx: Context) -> None:
    """A loader returning duplicate names is a programming error."""

    def loader(node: DirNode) -> list[Node]:
        return [FileNode("x", node, ctx, lambda: "1", lazy=False),
                FileNode("x", node, ctx, lambda: "2", lazy=False)]

    root = DirNode("", None, ctx, loader)
    with pytest.raises(ValueError):
        root.children()


@pytest.mark.parametrize("bad", ["a/b", ".", "..", ""])
def test_invalid_child_names_rejected(ctx: Context, bad: str) -> None:
    """Node names are single escaped components."""
    root = DirNode("", None, ctx, lambda node: [], static=True)
    with pytest.raises(ValueError):
        FileNode(bad, root, ctx, lambda: "x", lazy=False)


def _counting(ctx: Context, loads: list[int]
              ) -> Callable[[DirNode], list[Node]]:
    def loader(node: DirNode) -> list[Node]:
        loads.append(1)
        return [FileNode("f", node, ctx, lambda: "x", lazy=False)]
    return loader


def test_children_memoised_within_ttl(ctx: Context,
                                      make_tree: MakeTree) -> None:
    """A dir loads once per TTL; invalidate() forces a reload."""
    loads: list[int] = []
    vfs = make_tree({"d": ("dirfn", _counting(ctx, loads))})
    vfs.listdir("/d")
    vfs.listdir("/d")
    vfs.read("/d/f")
    vfs.stat("/d/f")
    assert len(loads) == 1
    node = vfs.resolve("/d")
    assert isinstance(node, DirNode)
    node.invalidate()
    vfs.listdir("/d")
    assert len(loads) == 2


def test_ttl_zero_reloads(make_ctx: Callable[..., Context],
                          make_tree: MakeTree) -> None:
    """With ttl=0 children expire immediately."""
    ctx0 = make_ctx(ttl=0.0)
    loads: list[int] = []
    vfs = make_tree({"d": ("dirfn", _counting(ctx0, loads))}, ctx0)
    vfs.listdir("/d")
    vfs.listdir("/d")
    assert len(loads) == 2


def test_peek_children_and_stat_do_not_load(ctx: Context,
                                            make_tree: MakeTree) -> None:
    """peek is non-blocking; stat on a dir never triggers its load."""
    loads: list[int] = []
    vfs = make_tree({"d": ("dirfn", _counting(ctx, loads))})
    node = vfs.resolve("/d")
    assert isinstance(node, DirNode)
    assert node.peek_children() is None
    vfs.stat("/d")
    assert loads == []
    vfs.listdir("/d")
    peeked = node.peek_children()
    assert peeked is not None
    assert list(peeked) == ["f"]


# ---------------------------------------------------------------------
# full tree over the fake provider
# ---------------------------------------------------------------------


def test_top_levels_cost_no_api_calls(vfs: VFS, backend: Any,
                                      fake: Any) -> None:
    """Root/account/region/service dirs: zero calls beyond identity."""
    acct = f"/{fake.account_id}"
    assert vfs.listdir("/") == [fake.account_id]
    assert vfs.listdir(acct) == ["_meta", "global", fake.region]
    assert vfs.listdir(f"{acct}/{fake.region}") == ["fake"]
    assert vfs.listdir(f"{acct}/global") == []
    assert vfs.listdir(fake.base) == ["gadgets", "widgets"]
    assert vfs.listdir(f"{acct}/_meta") == [
        "account.json", "errors.log", "identity.json", "stats.json"]
    assert backend.api_calls() == 0
    assert backend.count("sts", "get_caller_identity") == 1


def test_meta_account_and_identity(vfs: VFS, fake: Any) -> None:
    """_meta/account.json and identity.json content."""
    meta = f"/{fake.account_id}/_meta"
    account = json.loads(vfs.read(f"{meta}/account.json"))
    assert account["AccountId"] == fake.account_id
    assert account["Aliases"] == []
    assert account["Partition"] == "aws"
    assert account["Regions"] == [fake.region]
    assert account["GlobalRegion"] == "us-east-1"
    identity = json.loads(vfs.read(f"{meta}/identity.json"))
    assert identity["Account"] == fake.account_id
    assert "ResponseMetadata" not in identity


def test_collection_listing_is_one_call(vfs: VFS, backend: Any,
                                        fake: Any) -> None:
    """A collection is listed with one call, cached for the TTL."""
    assert vfs.listdir(f"{fake.base}/widgets") == ["w-1", "w-2", "w-3"]
    assert backend.count("fake", "list_widgets") == 1
    vfs.listdir(f"{fake.base}/widgets")
    vfs.listdir(f"{fake.base}/widgets/w-1")
    assert backend.count("fake", "list_widgets") == 1
    assert backend.api_calls() == 1


def test_resource_dir_entries(vfs: VFS, fake: Any) -> None:
    """describe.json, arn, name, tags, files and links are present."""
    assert vfs.listdir(f"{fake.base}/widgets/w-1") == [
        "arn", "color", "describe.json", "details.json", "links",
        "name", "tags", "tags.json", "user-data"]
    assert "name" not in vfs.listdir(f"{fake.base}/widgets/w-3")
    assert vfs.read(f"{fake.base}/widgets/w-1/name") == b"first\n"
    assert vfs.read(f"{fake.base}/widgets/w-1/arn") == (
        f"arn:aws:fake:{fake.region}:{fake.account_id}:widget/w-1\n"
    ).encode()


def test_describe_json_is_canonical_item(vfs: VFS, backend: Any,
                                         fake: Any) -> None:
    """describe.json equals the canonical render of the listed item."""
    item = next(w for w in backend.widgets if w["Id"] == "w-2")
    assert vfs.read(f"{fake.base}/widgets/w-2/describe.json") == \
        render(item)


def test_display_named_collection(vfs: VFS, fake: Any) -> None:
    """Display-named dirs apply the casefold collision rule."""
    assert vfs.listdir(f"{fake.base}/gadgets") == [
        "Alpha~g-3", "alpha~g-1", "beta"]
    assert vfs.read(f"{fake.base}/gadgets/beta/name") == b"beta\n"


def test_no_n_plus_one(vfs: VFS, backend: Any, ctx: Context,
                       fake: Any) -> None:
    """ls costs one charge per page; describe.json reads cost none."""
    backend.widgets = [{"Id": f"w-{i:03d}", "Color": "red", "Tags": []}
                       for i in range(50)]
    backend.page_size = 20
    vfs.listdir("/")
    used = ctx.budget.used()
    names = vfs.listdir(f"{fake.base}/widgets")
    assert len(names) == 50
    assert ctx.budget.used() - used == 3
    assert backend.count("fake", "list_widgets") == 3
    for name in names:
        vfs.read(f"{fake.base}/widgets/{name}/describe.json")
        vfs.read(f"{fake.base}/widgets/{name}/tags.json")
        vfs.stat(f"{fake.base}/widgets/{name}/color")
    assert ctx.budget.used() - used == 3
    assert backend.api_calls() == 3
