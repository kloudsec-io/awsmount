"""FUSE operations tested directly over a moto-backed Context.

The ``AwsFuseOps`` (or ``AwsFuse``) ``mfusepy.Operations`` subclass is
called without mounting anything. The tests check getattr, readdir,
readlink, open and read against the VFS. They also check that every
write path is refused with EROFS, that missing paths give ENOENT, that
xattrs give ENODATA, and that ``--lazy-size zero`` behaves as
described in ARCHITECTURE: File metadata, FUSE.

The real Context machinery is used: the client factory and its
read-only guard, the cache, the budget and redaction. AWS itself is
moto in-process (``mock_aws``), seeded by ``fixtures/seed.py``. The
operations module must import even when libfuse is absent (mfusepy is
loaded lazily), so ``FuseOSError`` is taken from it rather
than from mfusepy directly.
"""

from __future__ import annotations

import errno
import importlib
import inspect
import os
import stat
import sys
import types
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import boto3
import pytest
from moto import mock_aws

from awsmount.config import Config
from awsmount.session.context import Context
from awsmount.session.redact import REDACTED
from awsmount.tree.root import build_vfs
from awsmount.vfs.node import DirNode
from awsmount.vfs.resolver import VFS

try:
    _OPS_MODULE = importlib.import_module(
        "awsmount.adapters.fuse.operations")
except ImportError as _exc:
    pytest.skip(f"FUSE operations unavailable: {_exc}",
                allow_module_level=True)
FuseOSError: Any = _OPS_MODULE.FuseOSError

_TESTS_DIR = str(Path(__file__).resolve().parents[1])
if _TESTS_DIR not in sys.path:
    sys.path.insert(0, _TESTS_DIR)
SEED = importlib.import_module("fixtures.seed")

REGION = "us-east-1"
SERVICES = frozenset({"ec2", "vpc"})
MISSING = "does-not-exist"

_ENV = {
    "AWS_ACCESS_KEY_ID": "testing",
    "AWS_SECRET_ACCESS_KEY": "testing",
    "AWS_SECURITY_TOKEN": "testing",
    "AWS_SESSION_TOKEN": "testing",
    "AWS_DEFAULT_REGION": REGION,
    "AWS_CONFIG_FILE": os.devnull,
    "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
}
_UNSET = ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ENDPOINT_URL")

OpsClass: Any = (getattr(_OPS_MODULE, "AwsFuseOps", None)
                 or getattr(_OPS_MODULE, "AwsFuse"))

_XATTR_ERRNOS = {errno.ENODATA,
                 getattr(errno, "ENOATTR", errno.ENODATA)}


# ---------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------


def make_ops(ctx: Context, vfs: VFS) -> Any:
    """Instantiate the operations class from its signature."""
    sig = inspect.signature(OpsClass)
    positional: list[Any] = []
    kwargs: dict[str, Any] = {}
    for name, param in sig.parameters.items():
        if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
            continue
        if name in ("vfs", "fs", "filesystem"):
            value: Any = vfs
        elif name in ("ctx", "context"):
            value = ctx
        elif name == "config":
            value = ctx.config
        elif name == "lazy_size":
            value = ctx.config.lazy_size
        elif param.default is not param.empty:
            continue
        else:
            raise TypeError(f"unexpected required parameter {name!r}")
        if param.kind is param.POSITIONAL_ONLY:
            positional.append(value)
        else:
            kwargs[name] = value
    return OpsClass(*positional, **kwargs)


def call(fn: Callable[..., Any], *args: Any) -> Any:
    """Call ``fn`` with as many of ``args`` as its signature takes."""
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return fn(*args)
    params = list(sig.parameters.values())
    if any(p.kind is p.VAR_POSITIONAL for p in params):
        return fn(*args)
    slots = [p for p in params
             if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
    use = list(args[:len(slots)])
    while len(use) < len(slots) and \
            slots[len(use)].default is inspect.Parameter.empty:
        use.append(None)
    return fn(*use)


def raw_fi(ops: Any) -> bool:
    """True when open() receives a file-info struct (``raw_fi=True``)."""
    params = list(inspect.signature(ops.open).parameters.values())
    if len(params) < 2:
        return False
    return params[1].name != "flags"


def file_info(flags: int = os.O_RDONLY) -> types.SimpleNamespace:
    """Stand-in for ``struct fuse_file_info``."""
    return types.SimpleNamespace(flags=flags, fh=0, direct_io=False,
                                 keep_cache=True, nonseekable=False)


def open_file(ops: Any, path: str, flags: int = os.O_RDONLY
              ) -> tuple[Any, types.SimpleNamespace]:
    """Open ``path``; return (handle argument for read/release, fi)."""
    fi = file_info(flags)
    if raw_fi(ops):
        ret = ops.open(path, fi)
        if isinstance(ret, int) and ret and not fi.fh:
            fi.fh = ret
        return fi, fi
    ret = ops.open(path, flags)
    fi.fh = ret
    return ret, fi


def expect_errno(code: int | set[int], fn: Callable[..., Any],
                 *args: Any) -> None:
    """Assert that ``fn(*args)`` raises FuseOSError with ``code``."""
    with pytest.raises(FuseOSError) as info:
        call(fn, *args)
    codes = code if isinstance(code, set) else {code}
    assert info.value.errno in codes, (
        f"{getattr(fn, '__name__', fn)}: errno {info.value.errno} "
        f"({os.strerror(info.value.errno)}), expected {sorted(codes)}")


def names_of(entries: Any) -> list[str]:
    """readdir entries may be names or (name, attrs, offset) tuples."""
    return [e if isinstance(e, str) else e[0] for e in entries]


# ---------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------


@pytest.fixture(scope="module")
def seeded() -> Iterator[Any]:
    """moto in-process with the EC2/VPC estate seeded once per module."""
    saved = {k: os.environ.get(k) for k in (*_ENV, *_UNSET)}
    for key in _UNSET:
        os.environ.pop(key, None)
    os.environ.update(_ENV)
    try:
        with mock_aws():
            session = boto3.Session(region_name=REGION)
            yield SEED.seed_ec2_vpc(session, region=REGION)
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@pytest.fixture
def make_mount(seeded: Any
               ) -> Callable[..., tuple[Context, VFS, Any]]:
    """Factory: fresh (ctx, vfs, ops) for config overrides."""

    def factory(**overrides: Any) -> tuple[Context, VFS, Any]:
        overrides.setdefault("regions", (REGION,))
        overrides.setdefault("services", SERVICES)
        ctx = Context.from_config(Config(**overrides))
        vfs = build_vfs(ctx)
        return ctx, vfs, make_ops(ctx, vfs)

    return factory


@pytest.fixture
def mount(make_mount: Callable[..., tuple[Context, VFS, Any]]
          ) -> tuple[Context, VFS, Any]:
    """Default (redacting, render-size) mount."""
    return make_mount()


@pytest.fixture
def paths(seeded: Any) -> types.SimpleNamespace:
    """Interesting VFS paths of the seeded account."""
    base = f"/{seeded.account_id}/{REGION}"
    inst = f"{base}/ec2/instances/{seeded.instance_web}"
    return types.SimpleNamespace(
        account=f"/{seeded.account_id}",
        base=base,
        instances=f"{base}/ec2/instances",
        inst=inst,
        describe=f"{inst}/describe.json",
        user_data=f"{inst}/user-data",
        state=f"{inst}/state",
        links=f"{inst}/links",
        subnet_link=f"{inst}/links/subnet",
        subnet_dir=f"{base}/vpc/subnets/{seeded.subnet_public}",
        missing=f"{inst}/{MISSING}",
        new=f"{inst}/new-entry",
    )


# ---------------------------------------------------------------------
# getattr
# ---------------------------------------------------------------------


def test_getattr_root_and_directory(mount: Any, paths: Any) -> None:
    _ctx, vfs, ops = mount
    for path in ("/", paths.account, paths.inst):
        attrs = call(ops.getattr, path)
        assert stat.S_ISDIR(attrs["st_mode"]), path
        assert stat.S_IMODE(attrs["st_mode"]) == 0o555
        assert attrs["st_nlink"] == 1
        assert attrs["st_size"] == 0
        assert attrs["st_ino"] == vfs.lstat(path).ino
        assert attrs["st_uid"] == os.getuid()
        assert attrs["st_gid"] == os.getgid()


def test_getattr_file_size_matches_content(mount: Any,
                                           paths: Any) -> None:
    _ctx, vfs, ops = mount
    attrs = call(ops.getattr, paths.describe)
    data = vfs.read(paths.describe)
    assert stat.S_ISREG(attrs["st_mode"])
    assert stat.S_IMODE(attrs["st_mode"]) == 0o444
    assert attrs["st_size"] == len(data) > 0
    assert attrs["st_nlink"] == 1
    assert attrs["st_mtime"] == attrs["st_atime"] == attrs["st_ctime"]


def test_getattr_symlink_is_not_followed(mount: Any, paths: Any) -> None:
    _ctx, vfs, ops = mount
    attrs = call(ops.getattr, paths.subnet_link)
    target = vfs.readlink(paths.subnet_link)
    assert stat.S_ISLNK(attrs["st_mode"])
    assert stat.S_IMODE(attrs["st_mode"]) == 0o777
    assert attrs["st_size"] == len(target.encode("utf-8"))


def test_getattr_through_intermediate_symlink(mount: Any,
                                              paths: Any) -> None:
    _ctx, vfs, ops = mount
    path = f"{paths.subnet_link}/cidr"
    attrs = call(ops.getattr, path)
    assert stat.S_ISREG(attrs["st_mode"])
    handle, _fi = open_file(ops, path)
    data = ops.read(path, 4096, 0, handle)
    call(ops.release, path, handle)
    assert data == (SEED.PUBLIC_SUBNET_CIDR + "\n").encode()
    assert attrs["st_size"] == len(data)


# ---------------------------------------------------------------------
# readdir / readlink
# ---------------------------------------------------------------------


def test_readdir_resource_dir(mount: Any, paths: Any) -> None:
    _ctx, vfs, ops = mount
    names = names_of(call(ops.readdir, paths.inst, 0))
    assert names[:2] == [".", ".."]
    assert names[2:] == vfs.listdir(paths.inst)
    for expected in ("describe.json", "arn", "state", "user-data",
                     "tags.json", "tags", "links"):
        assert expected in names


def test_readdir_collection_lists_every_instance(mount: Any, paths: Any,
                                                 seeded: Any) -> None:
    _ctx, _vfs, ops = mount
    names = set(names_of(call(ops.readdir, paths.instances, 0)))
    assert set(seeded.instances) <= names
    assert {".", ".."} <= names


@pytest.mark.parametrize("which", ["account", "inst", "links", "instances"])
def test_readdir_entries_carry_inode_and_type(mount: Any, paths: Any,
                                              which: str) -> None:
    """Every entry has a non-zero inode and the type getattr reports.

    A bare name reaches the kernel with d_ino 0, and bash's glob drops
    such entries, so ``*/describe.json`` matched nothing on Linux.
    """
    _ctx, _vfs, ops = mount
    directory = getattr(paths, which)
    entries = call(ops.readdir, directory, 0)
    assert entries[0][0] == "." and entries[1][0] == ".."
    seen = 0
    for entry in entries:
        assert not isinstance(entry, str), (
            f"{entry!r}: a bare name gives d_ino 0 and bash drops it")
        name, attrs, offset = entry
        assert offset == 0
        assert attrs["st_ino"] != 0, name
        if name in (".", ".."):
            assert stat.S_ISDIR(attrs["st_mode"])
            continue
        child = call(ops.getattr, f"{directory.rstrip('/')}/{name}")
        assert attrs["st_ino"] == child["st_ino"], name
        assert stat.S_IFMT(attrs["st_mode"]) == stat.S_IFMT(
            child["st_mode"]), name
        seen += 1
    assert seen > 0


def test_readdir_links_dir_reports_symlink_type(mount: Any,
                                                paths: Any) -> None:
    _ctx, _vfs, ops = mount
    entries = {e[0]: e[1] for e in call(ops.readdir, paths.links, 0)}
    assert stat.S_ISLNK(entries["subnet"]["st_mode"])


def test_readdir_does_not_render_lazy_files(mount: Any, paths: Any) -> None:
    """Listing must stay free: no API call to type or number a child."""
    ctx, _vfs, ops = mount
    call(ops.readdir, paths.instances, 0)  # the collection listing
    before = ctx.budget.used()
    entries = call(ops.readdir, paths.inst, 0)
    assert any(e[0] == "user-data" for e in entries)  # a lazy file
    assert ctx.budget.used() == before


def test_readlink_relative_and_resolvable(mount: Any, paths: Any,
                                          seeded: Any) -> None:
    _ctx, vfs, ops = mount
    target = ops.readlink(paths.subnet_link)
    assert target == vfs.readlink(paths.subnet_link)
    assert not target.startswith("/")
    assert target.endswith(f"vpc/subnets/{seeded.subnet_public}")
    assert vfs.realpath(paths.subnet_link) == paths.subnet_dir


# ---------------------------------------------------------------------
# open / read / release
# ---------------------------------------------------------------------


def test_open_read_with_offsets(mount: Any, paths: Any) -> None:
    _ctx, vfs, ops = mount
    content = vfs.read(paths.describe)
    assert len(content) > 40
    handle, _fi = open_file(ops, paths.describe)
    try:
        assert ops.read(paths.describe, len(content), 0,
                        handle) == content
        assert ops.read(paths.describe, 10, 5, handle) == content[5:15]
        assert ops.read(paths.describe, 1 << 20, 7,
                        handle) == content[7:]
        tail = len(content) - 3
        assert ops.read(paths.describe, 100, tail,
                        handle) == content[tail:]
        assert ops.read(paths.describe, 10, len(content), handle) == b""
        assert ops.read(paths.describe, 10, len(content) + 50,
                        handle) == b""
        assert ops.read(paths.describe, 0, 0, handle) == b""
    finally:
        call(ops.release, paths.describe, handle)


def test_concurrent_handles_are_independent(mount: Any,
                                            paths: Any) -> None:
    _ctx, vfs, ops = mount
    first, _fi1 = open_file(ops, paths.describe)
    second, _fi2 = open_file(ops, paths.state)
    try:
        assert ops.read(paths.describe, 1 << 16, 0,
                        first) == vfs.read(paths.describe)
        assert ops.read(paths.state, 1 << 16, 0,
                        second) == vfs.read(paths.state)
    finally:
        call(ops.release, paths.describe, first)
        call(ops.release, paths.state, second)


def test_snapshot_survives_cache_invalidation(mount: Any,
                                              paths: Any) -> None:
    ctx, vfs, ops = mount
    content = vfs.read(paths.describe)
    handle, _fi = open_file(ops, paths.describe)
    try:
        ctx.cache.invalidate()
        vfs.root.invalidate()
        assert ops.read(paths.describe, 1 << 20, 0, handle) == content
    finally:
        call(ops.release, paths.describe, handle)


def test_redacted_user_data_never_leaks(mount: Any, paths: Any) -> None:
    ctx, _vfs, ops = mount
    used = ctx.budget.used()
    handle, _fi = open_file(ops, paths.user_data)
    try:
        data = ops.read(paths.user_data, 1 << 16, 0, handle)
    finally:
        call(ops.release, paths.user_data, handle)
    assert data == (REDACTED + "\n").encode()
    assert SEED.FAKE_SECRET.encode() not in data
    attrs = call(ops.getattr, paths.user_data)
    assert attrs["st_size"] == len(data)
    # The first access pays for account bootstrap and the instance
    # listing. Once resolved, reading the redacted file again must not
    # reach the API at all (no DescribeInstanceAttribute).
    settled = ctx.budget.used()
    assert settled > used
    for _ in range(3):
        handle, _fi = open_file(ops, paths.user_data)
        try:
            again = ops.read(paths.user_data, 1 << 16, 0, handle)
        finally:
            call(ops.release, paths.user_data, handle)
        assert again == data
        call(ops.getattr, paths.user_data)
    assert ctx.budget.used() == settled


@pytest.mark.parametrize("flags", [
    os.O_WRONLY,
    os.O_RDWR,
    os.O_RDONLY | os.O_APPEND,
    os.O_RDONLY | os.O_CREAT,
    os.O_RDONLY | os.O_TRUNC,
    os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
], ids=["wronly", "rdwr", "append", "creat", "trunc", "creat-trunc"])
def test_open_with_write_intent_is_erofs(mount: Any, paths: Any,
                                         flags: int) -> None:
    _ctx, _vfs, ops = mount
    arg: Any = file_info(flags) if raw_fi(ops) else flags
    expect_errno(errno.EROFS, ops.open, paths.describe, arg)


# ---------------------------------------------------------------------
# write operations
# ---------------------------------------------------------------------


WRITE_OPS: dict[str, Callable[[types.SimpleNamespace], tuple[Any, ...]]]
WRITE_OPS = {
    "write": lambda p: (p.file, b"x", 0, p.fh),
    "create": lambda p: (p.new, 0o644, p.fi),
    "mkdir": lambda p: (p.new, 0o755),
    "rmdir": lambda p: (p.dir,),
    "unlink": lambda p: (p.file,),
    "rename": lambda p: (p.file, p.new),
    "symlink": lambda p: (p.new, p.file),
    "link": lambda p: (p.new, p.file),
    "chmod": lambda p: (p.file, 0o777),
    "chown": lambda p: (p.file, 0, 0),
    "truncate": lambda p: (p.file, 0, p.fh),
    "utimens": lambda p: (p.file, (0.0, 0.0)),
    "setxattr": lambda p: (p.file, "user.awsmount", b"v", 0, 0),
    "removexattr": lambda p: (p.file, "user.awsmount"),
    "mknod": lambda p: (p.new, stat.S_IFREG | 0o644, 0),
    "fallocate": lambda p: (p.file, 0, 0, 16, p.fh),
}


@pytest.mark.parametrize("op", sorted(WRITE_OPS))
def test_write_operations_are_erofs(mount: Any, paths: Any,
                                    op: str) -> None:
    ctx, vfs, ops = mount
    vfs.resolve(paths.describe)
    used = ctx.budget.used()
    raw = raw_fi(ops)
    fi = file_info(os.O_WRONLY)
    args = WRITE_OPS[op](types.SimpleNamespace(
        file=paths.describe, dir=paths.links, new=paths.new,
        fi=fi if raw else None, fh=fi if raw else 0))
    expect_errno(errno.EROFS, getattr(ops, op), *args)
    assert ctx.budget.used() == used, f"{op} made API calls"
    assert MISSING not in vfs.listdir(paths.inst)
    assert "new-entry" not in vfs.listdir(paths.inst)


# ---------------------------------------------------------------------
# access, ENOENT, ENOTDIR, xattrs, statfs
# ---------------------------------------------------------------------


@pytest.mark.parametrize("amode", [os.W_OK, os.R_OK | os.W_OK,
                                   os.W_OK | os.X_OK],
                         ids=["w", "rw", "wx"])
def test_access_write_is_erofs(mount: Any, paths: Any,
                               amode: int) -> None:
    _ctx, _vfs, ops = mount
    expect_errno(errno.EROFS, ops.access, paths.describe, amode)
    expect_errno(errno.EROFS, ops.access, paths.inst, amode)


def test_access_read_succeeds(mount: Any, paths: Any) -> None:
    _ctx, _vfs, ops = mount
    for path in ("/", paths.inst, paths.describe):
        assert ops.access(path, os.R_OK) in (None, 0)
        assert ops.access(path, os.F_OK) in (None, 0)


def test_access_missing_is_enoent(mount: Any, paths: Any) -> None:
    _ctx, _vfs, ops = mount
    expect_errno(errno.ENOENT, ops.access, paths.missing, os.R_OK)


def test_missing_paths_are_enoent(mount: Any, paths: Any) -> None:
    _ctx, _vfs, ops = mount
    missing_dir = f"{paths.base}/ec2/instances/i-{MISSING}"
    expect_errno(errno.ENOENT, ops.getattr, paths.missing)
    expect_errno(errno.ENOENT, ops.getattr, f"/{MISSING}")
    expect_errno(errno.ENOENT, ops.getattr, f"{missing_dir}/describe.json")
    expect_errno(errno.ENOENT, ops.readdir, missing_dir, 0)
    expect_errno(errno.ENOENT, ops.readlink, f"{paths.links}/{MISSING}")
    arg: Any = file_info() if raw_fi(ops) else os.O_RDONLY
    expect_errno(errno.ENOENT, ops.open, paths.missing, arg)


def test_traversal_through_file_is_enotdir(mount: Any,
                                           paths: Any) -> None:
    _ctx, _vfs, ops = mount
    expect_errno(errno.ENOTDIR, ops.readdir, paths.describe, 0)
    expect_errno(errno.ENOTDIR, ops.getattr, f"{paths.describe}/x")


def test_readlink_on_non_link_is_einval(mount: Any, paths: Any) -> None:
    _ctx, _vfs, ops = mount
    expect_errno(errno.EINVAL, ops.readlink, paths.describe)
    expect_errno(errno.EINVAL, ops.readlink, paths.inst)


def test_getxattr_is_enodata(mount: Any, paths: Any) -> None:
    _ctx, _vfs, ops = mount
    for path in (paths.describe, paths.inst, "/"):
        expect_errno(_XATTR_ERRNOS, ops.getxattr, path,
                     "com.apple.FinderInfo", 0)
        expect_errno(_XATTR_ERRNOS, ops.getxattr, path,
                     "security.selinux", 0)


def test_listxattr_is_empty(mount: Any, paths: Any) -> None:
    _ctx, _vfs, ops = mount
    assert list(ops.listxattr(paths.describe)) == []


def test_statfs(mount: Any) -> None:
    _ctx, _vfs, ops = mount
    info = ops.statfs("/")
    assert info["f_bsize"] == 4096
    assert info["f_frsize"] == 4096
    assert info["f_namemax"] == 255
    for key, value in info.items():
        if key not in ("f_bsize", "f_frsize", "f_namemax"):
            assert value == 0, key


def test_opendir_releasedir_are_harmless(mount: Any, paths: Any) -> None:
    _ctx, vfs, ops = mount
    handle = call(ops.opendir, paths.inst)
    call(ops.releasedir, paths.inst, handle if handle else 0)
    assert vfs.listdir(paths.inst)


# ---------------------------------------------------------------------
# --lazy-size
# ---------------------------------------------------------------------


def test_lazy_size_render_reports_full_size(
        make_mount: Callable[..., tuple[Context, VFS, Any]],
        paths: Any) -> None:
    _ctx, _vfs, ops = make_mount(reveal=True, lazy_size="render")
    attrs = call(ops.getattr, paths.user_data)
    assert attrs["st_size"] == len(SEED.USER_DATA.encode())


def test_lazy_size_zero_reports_zero_until_rendered(
        make_mount: Callable[..., tuple[Context, VFS, Any]],
        paths: Any) -> None:
    ctx, _vfs, ops = make_mount(reveal=True, lazy_size="zero")
    used = ctx.budget.used()
    attrs = call(ops.getattr, paths.user_data)
    assert stat.S_ISREG(attrs["st_mode"])
    assert attrs["st_size"] == 0
    assert attrs["st_blocks"] == 0
    calls_for_listing = ctx.budget.used() - used
    again = call(ops.getattr, paths.user_data)
    assert again["st_size"] == 0
    assert ctx.budget.used() - used == calls_for_listing
    handle, _fi = open_file(ops, paths.user_data)
    try:
        data = ops.read(paths.user_data, 1 << 16, 0, handle)
    finally:
        call(ops.release, paths.user_data, handle)
    assert data == SEED.USER_DATA.encode()
    assert SEED.FAKE_SECRET.encode() in data
    after = call(ops.getattr, paths.user_data)
    assert after["st_size"] == len(data)


def test_lazy_size_zero_keeps_derived_sizes(
        make_mount: Callable[..., tuple[Context, VFS, Any]],
        paths: Any) -> None:
    _ctx, vfs, ops = make_mount(lazy_size="zero")
    describe = call(ops.getattr, paths.describe)
    assert describe["st_size"] == len(vfs.read(paths.describe)) > 0
    redacted = call(ops.getattr, paths.user_data)
    assert redacted["st_size"] == len((REDACTED + "\n").encode())


def test_lazy_size_zero_sets_direct_io(
        make_mount: Callable[..., tuple[Context, VFS, Any]],
        paths: Any) -> None:
    _ctx, _vfs, ops = make_mount(reveal=True, lazy_size="zero")
    if not raw_fi(ops):
        pytest.skip("operations do not use raw file-info structs")
    handle, fi = open_file(ops, paths.user_data)
    call(ops.release, paths.user_data, handle)
    assert fi.direct_io is True or fi.direct_io == 1
    assert not fi.keep_cache
    handle, fi = open_file(ops, paths.describe)
    call(ops.release, paths.describe, handle)
    assert not fi.direct_io
    assert not fi.keep_cache


def test_render_mode_never_sets_direct_io(
        make_mount: Callable[..., tuple[Context, VFS, Any]],
        paths: Any) -> None:
    _ctx, _vfs, ops = make_mount(reveal=True, lazy_size="render")
    if not raw_fi(ops):
        pytest.skip("operations do not use raw file-info structs")
    handle, fi = open_file(ops, paths.user_data)
    call(ops.release, paths.user_data, handle)
    assert not fi.direct_io


# ---------------------------------------------------------------------
# libfuse selection
# ---------------------------------------------------------------------


@pytest.mark.parametrize("env, found, expected", [
    ({}, "libfuse3.so.3", "fuse3"),
    ({}, None, None),
    ({"FUSE_LIBRARY_NAME": "fuse"}, "libfuse3.so.3", "fuse"),
    ({"FUSE_LIBRARY_PATH": "/x/libfuse.so.2"}, "libfuse3.so.3", None),
])
def test_prefer_libfuse3_only_when_the_user_chose_nothing(
        monkeypatch: pytest.MonkeyPatch, env: dict[str, str],
        found: str | None, expected: str | None) -> None:
    """mfusepy tries libfuse 2 first; Amazon Linux 2023 has libfuse 2
    without ``fusermount``, so libfuse 3 is selected when it is there."""
    from awsmount import platform as plat
    monkeypatch.delenv("FUSE_LIBRARY_NAME", raising=False)
    monkeypatch.delenv("FUSE_LIBRARY_PATH", raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(plat, "is_linux", lambda: True)
    monkeypatch.setattr(plat.ctypes.util, "find_library",
                        lambda name: found if name == "fuse3" else None)
    plat.prefer_libfuse3()
    assert os.environ.get("FUSE_LIBRARY_NAME") == expected


def test_prefer_libfuse3_does_nothing_off_linux(
        monkeypatch: pytest.MonkeyPatch) -> None:
    from awsmount import platform as plat
    monkeypatch.delenv("FUSE_LIBRARY_NAME", raising=False)
    monkeypatch.delenv("FUSE_LIBRARY_PATH", raising=False)
    monkeypatch.setattr(plat, "is_linux", lambda: False)
    monkeypatch.setattr(plat.ctypes.util, "find_library",
                        lambda name: "libfuse3.so.3")
    plat.prefer_libfuse3()
    assert "FUSE_LIBRARY_NAME" not in os.environ


# ---------------------------------------------------------------------
# mount lifecycle
# ---------------------------------------------------------------------


class _FakeFuseModule:
    """Stands in for mfusepy: runs ``init`` and then ends like libfuse."""

    def __init__(self, *, up: bool, error: Exception | None) -> None:
        self.up, self.error = up, error

    def FUSE(self, ops: Any, target: str, **_opts: Any) -> None:  # noqa
        if self.up:
            ops.init()
        if self.error is not None:
            raise self.error


@pytest.mark.parametrize("up, error, status", [
    (True, None, 0),
    (True, RuntimeError(7), 0),     # SIGTERM on a mount that was up
    (False, RuntimeError(1), 1),    # fusermount failed: never mounted
    (False, OSError("no libfuse"), 1),
])
def test_signal_shutdown_of_a_mounted_filesystem_is_not_an_error(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path, up: bool,
        error: Exception | None, status: int) -> None:
    from awsmount.adapters.fuse import mount as fmount
    monkeypatch.setattr(fmount._platform, "os_name", lambda: "linux")
    monkeypatch.setattr(fmount, "load_mfusepy",
                        lambda: _FakeFuseModule(up=up, error=error))
    ctx = Context.from_config(Config(regions=("us-east-1",)))
    said: list[str] = []
    got = fmount.mount(VFS(DirNode("", None, ctx, lambda d: [],
                                   static=True)),
                       ctx, str(tmp_path / "mnt"), echo=said.append)
    assert got == status, said
    assert any("FUSE mount failed" in s for s in said) is (status == 1)
