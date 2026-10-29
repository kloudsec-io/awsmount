"""Stat records, inodes and the sizing policy (ARCHITECTURE: File metadata)."""

from __future__ import annotations

import hashlib
import os
import stat as pystat
import time
from collections.abc import Callable
from typing import Any

import pytest

from awsmount.config import Config
from awsmount.session.context import Context
from awsmount.vfs.node import FileNode
from awsmount.vfs.resolver import VFS
from awsmount.vfs.stat import Stat, inode_for

MakeTree = Callable[..., VFS]
MASK = 2 ** 63 - 1


@pytest.fixture
def fs(make_tree: MakeTree) -> VFS:
    """Dir, file, JSON file and link."""
    return make_tree({
        "d": {"f.txt": "abc"},
        "j.json": ("json", {"a": 1}),
        "ln": ("link", "d/f.txt"),
    })


def test_modes(fs: VFS) -> None:
    """dir 0555, file 0444, link 0777 with the right type bits."""
    assert fs.lstat("/d").mode == pystat.S_IFDIR | 0o555
    assert fs.lstat("/d/f.txt").mode == pystat.S_IFREG | 0o444
    assert fs.lstat("/ln").mode == pystat.S_IFLNK | 0o777
    assert fs.stat("/ln").mode == pystat.S_IFREG | 0o444


def test_nlink_is_one(fs: VFS) -> None:
    """nlink is 1 for every node type (disables find leaf opt)."""
    for path in ("/", "/d", "/d/f.txt", "/ln"):
        assert fs.lstat(path).nlink == 1


def test_uid_gid_are_process_ids(fs: VFS) -> None:
    """uid/gid belong to the mounting process."""
    for path in ("/", "/d/f.txt", "/ln"):
        st = fs.lstat(path)
        assert st.uid == os.getuid()
        assert st.gid == os.getgid()


def test_sizes(fs: VFS) -> None:
    """dir 0, file len(rendered bytes), link len(target)."""
    assert fs.lstat("/d").size == 0
    assert fs.lstat("/d/f.txt").size == len(b"abc\n")
    assert fs.lstat("/j.json").size == len(fs.read("/j.json"))
    assert fs.lstat("/ln").size == len("d/f.txt")


def test_inode_stable_and_distinct(fs: VFS, make_tree: MakeTree) -> None:
    """Inodes derive from the path: stable, distinct, 63-bit."""
    a = fs.lstat("/d/f.txt").ino
    assert a == fs.lstat("/d/f.txt").ino
    assert a == inode_for("/d/f.txt")
    again = make_tree({"d": {"f.txt": "other"}})
    assert again.lstat("/d/f.txt").ino == a
    assert fs.lstat("/d").ino != a
    for path in ("/", "/d", "/ln"):
        assert 0 <= fs.lstat(path).ino <= MASK


def test_inode_formula() -> None:
    """blake2b(path, digest_size=8) masked to 63 bits."""
    digest = hashlib.blake2b(b"/a/b", digest_size=8).digest()
    candidates = {int.from_bytes(digest, "big") & MASK,
                  int.from_bytes(digest, "little") & MASK}
    assert inode_for("/a/b") in candidates


def test_to_fuse_keys_and_times() -> None:
    """to_fuse exposes every st_* field; atime=ctime=mtime."""
    st = Stat(mode=pystat.S_IFREG | 0o444, size=513, mtime=12.5,
              nlink=1, uid=1, gid=2, ino=3)
    out = st.to_fuse()
    assert set(out) == {"st_mode", "st_size", "st_mtime", "st_atime",
                        "st_ctime", "st_nlink", "st_uid", "st_gid",
                        "st_ino", "st_blocks", "st_blksize"}
    assert out["st_mtime"] == out["st_atime"] == out["st_ctime"] == 12.5
    assert out["st_size"] == 513
    assert out["st_ino"] == 3
    assert out["st_blksize"] == 4096


@pytest.mark.parametrize("size, blocks", [
    (0, 0), (1, 1), (511, 1), (512, 1), (513, 2), (4096, 8)])
def test_blocks(size: int, blocks: int) -> None:
    """st_blocks = ceil(size / 512)."""
    st = Stat(pystat.S_IFREG | 0o444, size, 0.0, 1, 0, 0, 1)
    assert st.to_fuse()["st_blocks"] == blocks


def test_static_root_mtime_is_session_start(fs: VFS, fake: Any) -> None:
    """Static dirs use the session start time."""
    assert fs.lstat("/").mtime == fake.started_at


def test_derived_file_uses_parent_time(fs: VFS) -> None:
    """A derived file shares its directory's time."""
    fs.listdir("/d")
    assert fs.lstat("/d/f.txt").mtime == fs.lstat("/d").mtime


def _lazy_counter(calls: list[int], text: str = "lazy-body"
                  ) -> Callable[[], str]:
    def render() -> str:
        calls.append(1)
        return text
    return render


def test_lazy_rendered_once_per_ttl(make_tree: MakeTree) -> None:
    """stat renders a lazy file once; read reuses it; sizes agree."""
    calls: list[int] = []
    vfs = make_tree({"lz": ("lazy", _lazy_counter(calls))})
    size = vfs.stat("/lz").size
    assert calls == [1]
    assert vfs.stat("/lz").size == size
    assert len(vfs.read("/lz")) == size
    assert calls == [1]


def test_lazy_ttl_zero_rerenders(make_ctx: Callable[..., Context],
                                 make_tree: MakeTree) -> None:
    """With ttl=0 nothing is retained between reads."""
    calls: list[int] = []
    vfs = make_tree({"lz": ("lazy", _lazy_counter(calls))},
                    make_ctx(ttl=0.0))
    vfs.read("/lz")
    vfs.read("/lz")
    assert len(calls) == 2


def test_lazy_size_zero_mode(make_tree: MakeTree) -> None:
    """render=False: unrendered lazy files report 0, no render."""
    calls: list[int] = []
    vfs = make_tree({"lz": ("lazy", _lazy_counter(calls)),
                     "dv": "derived"})
    lazy = vfs.resolve("/lz")
    assert isinstance(lazy, FileNode)
    assert lazy.known_size() is None
    assert lazy.stat(render=False).size == 0
    assert calls == []
    data = vfs.read("/lz")
    assert lazy.known_size() == len(data)
    assert lazy.stat(render=False).size == len(data)
    derived = vfs.resolve("/dv")
    assert isinstance(derived, FileNode)
    assert derived.stat(render=False).size == len(b"derived\n")


def test_lazy_mtime_is_render_time(make_tree: MakeTree) -> None:
    """A lazy file's time is when its data was fetched."""
    calls: list[int] = []
    vfs = make_tree({"lz": ("lazy", _lazy_counter(calls))})
    t0 = time.time()
    vfs.read("/lz")
    t1 = time.time()
    assert t0 <= vfs.stat("/lz").mtime <= t1


def test_lazy_size_config_validation() -> None:
    """lazy_size accepts render/zero only."""
    assert Config(lazy_size="zero").lazy_size == "zero"
    with pytest.raises(ValueError):
        Config(lazy_size="bogus")  # type: ignore[arg-type]


# ---------------------------------------------------------------------
# sizing policy over the fake provider
# ---------------------------------------------------------------------


def test_derived_stat_costs_no_call(vfs: VFS, backend: Any,
                                    fake: Any) -> None:
    """Derived files: stat and read are free after listing."""
    w1 = f"{fake.base}/widgets/w-1"
    vfs.listdir(w1)
    before = backend.api_calls()
    assert vfs.stat(f"{w1}/color").size == len(b"red\n")
    vfs.stat(f"{w1}/describe.json")
    vfs.stat(f"{w1}/tags.json")
    vfs.stat(f"{w1}/arn")
    assert backend.api_calls() == before


def test_lazy_file_stat_then_read(vfs: VFS, backend: Any,
                                  fake: Any) -> None:
    """Lazy file: first stat is one call; size == content length."""
    path = f"{fake.base}/widgets/w-1/details.json"
    vfs.listdir(f"{fake.base}/widgets/w-1")
    before = backend.api_calls()
    size = vfs.stat(path).size
    assert backend.api_calls() == before + 1
    data = vfs.read(path)
    assert len(data) == size
    vfs.stat(path)
    assert backend.api_calls() == before + 1
    assert b"ResponseMetadata" not in data


def test_lazy_file_unrendered_zero(vfs: VFS, backend: Any,
                                   fake: Any) -> None:
    """render=False on an unrendered provider lazy file: 0, no call."""
    path = f"{fake.base}/widgets/w-1/details.json"
    node = vfs.resolve(path, follow=False)
    assert isinstance(node, FileNode)
    before = backend.api_calls()
    assert node.stat(render=False).size == 0
    assert backend.api_calls() == before


def test_resource_times_are_fetch_times(vfs: VFS, fake: Any) -> None:
    """Resource dir/derived file mtime = listing fetch time."""
    t0 = time.time()
    vfs.listdir(f"{fake.base}/widgets")
    t1 = time.time()
    w1 = vfs.stat(f"{fake.base}/widgets/w-1")
    assert t0 <= w1.mtime <= t1
    assert vfs.stat(f"{fake.base}/widgets/w-1/color").mtime == w1.mtime
    assert vfs.stat(f"{fake.base}/widgets/w-1/describe.json").mtime \
        == w1.mtime


def test_provider_link_stat(vfs: VFS, fake: Any) -> None:
    """Link stat: size = len(target); following gives a dir."""
    link = f"{fake.base}/widgets/w-1/links/gadget"
    lst = vfs.lstat(link)
    assert lst.is_link
    assert lst.size == len(vfs.readlink(link))
    assert vfs.stat(link).is_dir
