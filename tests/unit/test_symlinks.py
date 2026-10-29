"""Symlinks: resolution, loops, walking and relative targets."""

from __future__ import annotations

import errno
import stat as pystat
from collections.abc import Callable
from typing import Any

import pytest

from awsmount.errors import AwsMountError, NotADirectory, NotFound
from awsmount.errors import SymlinkLoop
from awsmount.tree.links import LinkResolver
from awsmount.vfs.node import DirNode, SymlinkNode
from awsmount.vfs.resolver import MAX_SYMLINKS, VFS

LINKS = "/ec2/instances/i-1/links"
SUBNET = "/vpc/subnets/subnet-1"

SPEC: dict[str, Any] = {
    "vpc": {"subnets": {"subnet-1": {
        "describe.json": ("json", {"SubnetId": "subnet-1"})}}},
    "ec2": {"instances": {"i-1": {"links": {
        "subnet": ("link", "../../../../vpc/subnets/subnet-1"),
        "abs": ("link", "/vpc/subnets/subnet-1"),
        "dangling": ("link", "../../../../vpc/subnets/subnet-404"),
        "file": ("link",
                 "../../../../vpc/subnets/subnet-1/describe.json"),
        "via": ("link", "subnet"),
    }}}},
    "loop": {"a": ("link", "b"), "b": ("link", "a"),
             "self": ("link", "self")},
}

MakeTree = Callable[..., VFS]


@pytest.fixture
def fs(make_tree: MakeTree) -> VFS:
    """Tree with relative/absolute/dangling/looping links."""
    return make_tree(SPEC)


def test_follow_and_nofollow(fs: VFS) -> None:
    """follow=True yields the target, follow=False the link."""
    assert fs.resolve(f"{LINKS}/subnet").path == SUBNET
    node = fs.resolve(f"{LINKS}/subnet", follow=False)
    assert isinstance(node, SymlinkNode)
    assert node.path == f"{LINKS}/subnet"


def test_intermediate_link_followed(fs: VFS) -> None:
    """Links in the middle of a path are always followed."""
    data = fs.read(f"{LINKS}/subnet/describe.json")
    assert b"subnet-1" in data
    node = fs.resolve(f"{LINKS}/subnet/describe.json", follow=False)
    assert node.path == f"{SUBNET}/describe.json"


def test_absolute_target(fs: VFS) -> None:
    """Absolute targets are evaluated from the root."""
    assert fs.realpath(f"{LINKS}/abs") == SUBNET


def test_link_to_link(fs: VFS) -> None:
    """Chained links resolve."""
    assert fs.realpath(f"{LINKS}/via") == SUBNET


def test_dotdot_after_link_is_physical(fs: VFS) -> None:
    """'..' after a followed link goes to the target's parent."""
    assert fs.resolve(f"{LINKS}/subnet/..").path == "/vpc/subnets"


def test_realpath_and_listdir_through_link(fs: VFS) -> None:
    """realpath resolves; listdir follows a link to a dir."""
    assert fs.realpath(f"{LINKS}/subnet") == SUBNET
    assert fs.listdir(f"{LINKS}/subnet") == ["describe.json"]


def test_trailing_slash_forces_follow(fs: VFS) -> None:
    """'link/' resolves to the target even with follow=False."""
    node = fs.resolve(f"{LINKS}/subnet/", follow=False)
    assert isinstance(node, DirNode)
    assert node.path == SUBNET


def test_link_to_file(fs: VFS) -> None:
    """Links to files read the file; can't be traversed."""
    assert b"subnet-1" in fs.read(f"{LINKS}/file")
    with pytest.raises(NotADirectory):
        fs.resolve(f"{LINKS}/file/x")
    with pytest.raises(NotADirectory):
        fs.resolve(f"{LINKS}/file/")


def test_readlink(fs: VFS) -> None:
    """readlink returns the stored relative target."""
    assert fs.readlink(f"{LINKS}/subnet") == \
        "../../../../vpc/subnets/subnet-1"
    with pytest.raises(AwsMountError):
        fs.readlink(SUBNET)


def test_lstat_vs_stat(fs: VFS) -> None:
    """lstat describes the link, stat the target."""
    target = fs.readlink(f"{LINKS}/subnet")
    lst = fs.lstat(f"{LINKS}/subnet")
    assert pystat.S_ISLNK(lst.mode)
    assert lst.size == len(target.encode())
    assert pystat.S_ISDIR(fs.stat(f"{LINKS}/subnet").mode)


def test_dangling_link(fs: VFS) -> None:
    """Dangling: lstat works, following gives ENOENT."""
    assert pystat.S_ISLNK(fs.lstat(f"{LINKS}/dangling").mode)
    with pytest.raises(NotFound):
        fs.stat(f"{LINKS}/dangling")


@pytest.mark.parametrize("path", ["/loop/a", "/loop/b", "/loop/self",
                                  "/loop/a/x"])
def test_loops_are_eloop(fs: VFS, path: str) -> None:
    """Cycles raise SymlinkLoop (ELOOP)."""
    with pytest.raises(SymlinkLoop) as info:
        fs.resolve(path)
    assert info.value.errno == errno.ELOOP


def test_loop_not_followed_with_nofollow(fs: VFS) -> None:
    """A looping final link is fine when not followed."""
    node = fs.resolve("/loop/self", follow=False)
    assert isinstance(node, SymlinkNode)


def _chain(n_links: int) -> dict[str, Any]:
    entries: dict[str, Any] = {"target": "end"}
    for i in range(n_links):
        nxt = f"l{i + 1}" if i + 1 < n_links else "target"
        entries[f"l{i}"] = ("link", nxt)
    return {"chain": entries}


def test_forty_expansions_allowed(make_tree: MakeTree) -> None:
    """Exactly 40 symlink expansions still resolve."""
    assert MAX_SYMLINKS == 40
    vfs = make_tree(_chain(40))
    assert vfs.read("/chain/l0") == b"end\n"


def test_forty_one_expansions_eloop(make_tree: MakeTree) -> None:
    """The 41st expansion raises ELOOP."""
    vfs = make_tree(_chain(41))
    assert vfs.read("/chain/l1") == b"end\n"
    with pytest.raises(SymlinkLoop):
        vfs.read("/chain/l0")


def test_walk_does_not_descend_links(fs: VFS) -> None:
    """Default walk yields links but never enters them."""
    paths = [p for p, _n in fs.walk("/ec2")]
    assert f"{LINKS}/subnet" in paths
    assert not any(p.startswith(f"{LINKS}/subnet/") for p in paths)


def test_walk_preorder_sorted(make_tree: MakeTree) -> None:
    """Pre-order, children sorted."""
    vfs = make_tree({"b": {"y": "1", "x": "2"}, "a": "3"})
    assert [p for p, _n in vfs.walk("/")] == [
        "/", "/a", "/b", "/b/x", "/b/y"]


def test_walk_max_depth(make_tree: MakeTree) -> None:
    """max_depth limits descent."""
    vfs = make_tree({"b": {"y": "1"}, "a": "3"})
    assert [p for p, _n in vfs.walk("/", max_depth=1)] == [
        "/", "/a", "/b"]


def test_walk_follow_links_terminates_on_cycle(
        make_tree: MakeTree) -> None:
    """follow_links=True skips already-visited real paths."""
    vfs = make_tree({"d": {"f": "x", "up": ("link", "..")}})
    paths = [p for p, _n in vfs.walk("/d", follow_links=True)]
    assert "/d/f" in paths
    assert "/d/up" in paths
    assert len(paths) < 10
    assert paths.count("/d/up/d/f") == 0


def test_walk_follow_links_enters_link_dirs(fs: VFS) -> None:
    """follow_links=True descends into symlinked directories."""
    paths = [p for p, _n in fs.walk(LINKS + "/subnet",
                                    follow_links=True)]
    assert f"{LINKS}/subnet/describe.json" in paths


def test_relative_matches_design_example() -> None:
    """Example from ARCHITECTURE: Links and referenced-by."""
    rel = LinkResolver.relative(
        "/a/us-east-1/ec2/instances/i-1/links",
        "/a/us-east-1/vpc/subnets/subnet-0abc")
    assert rel == "../../../../vpc/subnets/subnet-0abc"
    assert LinkResolver.relative(
        "/a/r/vpc/security-groups/sg-0a/referenced-by",
        "/a/r/vpc/security-groups/sg-0b") == "../../sg-0b"


# ---------------------------------------------------------------------
# provider links and referenced-by
# ---------------------------------------------------------------------


def test_provider_link_relative_and_resolves(vfs: VFS,
                                             fake: Any) -> None:
    """links/gadget is a relative link to the display-named dir."""
    link = f"{fake.base}/widgets/w-1/links/gadget"
    assert vfs.readlink(link) == "../../../gadgets/alpha~g-1"
    assert vfs.realpath(link) == f"{fake.base}/gadgets/alpha~g-1"
    assert "describe.json" in vfs.listdir(link)


def test_unresolvable_link_omitted(vfs: VFS, fake: Any) -> None:
    """A link to a missing resource is not emitted."""
    assert vfs.listdir(f"{fake.base}/widgets/w-3/links") == []


def test_referenced_by_entries(vfs: VFS, fake: Any) -> None:
    """referenced-by lists '<svc>-<coll>-<dirname>' relative links."""
    ref = f"{fake.base}/gadgets/alpha~g-1/referenced-by"
    assert vfs.listdir(ref) == ["fake-widgets-w-1"]
    assert vfs.readlink(f"{ref}/fake-widgets-w-1") == \
        "../../../widgets/w-1"
    assert vfs.realpath(f"{ref}/fake-widgets-w-1") == \
        f"{fake.base}/widgets/w-1"
    assert vfs.listdir(f"{fake.base}/gadgets/Alpha~g-3/referenced-by") \
        == []


def test_referenced_by_one_list_call_per_source(vfs: VFS, backend: Any,
                                                fake: Any) -> None:
    """Building the index lists each source collection once."""
    for name in vfs.listdir(f"{fake.base}/gadgets"):
        vfs.listdir(f"{fake.base}/gadgets/{name}/referenced-by")
    assert backend.count("fake", "list_widgets") == 1
    assert backend.count("fake", "list_gadgets") == 1


def test_walk_ignores_referenced_by_links(vfs: VFS, fake: Any) -> None:
    """A recursive walk does not descend through relationship links."""
    paths = [p for p, _n in vfs.walk(f"{fake.base}/gadgets")]
    assert f"{fake.base}/gadgets/alpha~g-1/referenced-by/" \
        "fake-widgets-w-1" in paths
    assert not any("/referenced-by/fake-widgets-w-1/" in p
                   for p in paths)
