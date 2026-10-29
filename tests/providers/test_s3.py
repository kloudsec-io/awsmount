"""S3 provider against moto: buckets, lazy configuration files, the
object listing limit, region filtering and AccessDenied degradation."""

from __future__ import annotations

import errno
import importlib.util
import json
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from awsmount.config import Config
from awsmount.errors import AwsMountError, PermissionDenied
from awsmount.session.context import Context
from awsmount.tree.root import build_vfs
from awsmount.vfs.node import FileNode, SymlinkNode
from awsmount.vfs.render import to_json_text
from awsmount.vfs.resolver import VFS

SEED_FILE = Path(__file__).resolve().parents[1] / "fixtures" / "seed.py"
SEED_MODULE = "awsmount_test_fixtures_seed"


def _load_seed() -> ModuleType:
    module = sys.modules.get(SEED_MODULE)
    if module is not None:
        return module
    spec = importlib.util.spec_from_file_location(SEED_MODULE, SEED_FILE)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {SEED_FILE}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[SEED_MODULE] = module
    spec.loader.exec_module(module)
    return module


seed = _load_seed()
REGION: str = seed.REGION
Mount = Callable[..., "tuple[Context, VFS]"]

BUCKET_ENTRIES = {
    "describe.json", "arn", "tags.json", "tags", "region", "policy.json",
    "encryption.json", "public-access-block.json", "versioning.json",
    "objects-listing.json", "objects",
}


# -- harness ----------------------------------------------------------


@pytest.fixture
def aws_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Fake credentials; no user AWS configuration leaks in."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE",
                       str(tmp_path / "credentials"))
    for name in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_REGION",
                 "AWS_ENDPOINT_URL"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def data(aws_env: None) -> Iterator[Any]:
    """The seeded data estate inside an active moto mock."""
    with mock_aws():
        yield seed.seed_data(boto3.Session(region_name=REGION))


@pytest.fixture
def mount(data: Any) -> Mount:
    """Factory: ``mount(**config)`` -> (ctx, vfs) over the moto account."""

    def factory(**overrides: Any) -> tuple[Context, VFS]:
        overrides.setdefault("regions", (REGION,))
        ctx = Context.from_config(Config(**overrides))
        return ctx, build_vfs(ctx)

    return factory


def read_text(vfs: VFS, path: str) -> str:
    """File content as text."""
    return vfs.read(path).decode("utf-8")


def read_json(vfs: VFS, path: str) -> Any:
    """File content parsed as JSON."""
    return json.loads(vfs.read(path))


def deny(ctx: Context, service: str, op: str,
         code: str = "AccessDenied", region: str = REGION) -> None:
    """Make every ``op`` call of the mount's client fail with ``code``."""

    def handler(**_kwargs: Any) -> None:
        raise ClientError({"Error": {"Code": code,
                                     "Message": "denied by test"}}, op)

    client = ctx.clients.get(None, region, service)
    client.meta.events.register(f"before-call.*.{op}", handler)


def count_calls(ctx: Context, service: str, op: str,
                region: str = REGION) -> list[str]:
    """List that grows by one entry per ``op`` call actually sent."""
    hits: list[str] = []

    def record(**_kwargs: Any) -> None:
        hits.append(op)

    client = ctx.clients.get(None, region, service)
    client.meta.events.register(f"before-call.*.{op}", record)
    return hits


def error_lines(vfs: VFS, account_id: str) -> list[list[str]]:
    """TSV fields of every ``_meta/errors.log`` line."""
    raw = read_text(vfs, f"/{account_id}/_meta/errors.log")
    return [line.split("\t") for line in raw.splitlines() if line]


def all_contents(vfs: VFS, path: str) -> bytes:
    """Every readable file and link target under ``path``."""
    chunks: list[bytes] = []
    for _found, node in vfs.walk(path, on_error=lambda _p, _e: None):
        if isinstance(node, FileNode):
            try:
                chunks.append(node.content())
            except AwsMountError:
                continue
        elif isinstance(node, SymlinkNode):
            chunks.append(node.readlink().encode("utf-8"))
    return b"\n".join(chunks)


# -- helpers ----------------------------------------------------------


def _buckets(data: Any, region: str = REGION) -> str:
    return f"/{data.account_id}/{region}/s3/buckets"


def _bucket(data: Any, name: str | None = None) -> str:
    return f"{_buckets(data)}/{name or data.bucket}"


# -- tests ------------------------------------------------------------


def test_buckets_are_filtered_by_region(mount: Mount, data: Any) -> None:
    """Only buckets located in the mounted region are listed."""
    _ctx, vfs = mount()
    names = vfs.listdir(_buckets(data))
    assert data.bucket in names
    assert data.bucket_plain in names
    assert data.bucket_eu not in names


def test_bucket_lives_under_its_own_region_with_one_list_call(
        mount: Mount, data: Any) -> None:
    """ListBuckets is made once for the account, whatever the regions."""
    eu = seed.BUCKET_EU_REGION
    ctx, vfs = mount(regions=(REGION, eu))
    hits = count_calls(ctx, "s3", "ListBuckets")
    us_names = vfs.listdir(_buckets(data))
    eu_names = vfs.listdir(_buckets(data, eu))
    assert eu_names == [data.bucket_eu]
    assert data.bucket_eu not in us_names
    region = read_text(vfs, f"{_buckets(data, eu)}/{data.bucket_eu}/region")
    assert region == f"{eu}\n"
    vfs.listdir(_buckets(data))
    vfs.listdir(_buckets(data, eu))
    assert len(hits) == 1


def test_bucket_directory_layout(mount: Mount, data: Any) -> None:
    """Every bucket dir has exactly the documented entries."""
    _ctx, vfs = mount()
    assert set(vfs.listdir(_bucket(data))) == BUCKET_ENTRIES
    assert set(vfs.listdir(_bucket(data, data.bucket_plain))) == \
        BUCKET_ENTRIES


def test_describe_json_is_the_listed_item(mount: Mount, data: Any) -> None:
    """describe.json is the canonical render of the ListBuckets item."""
    _ctx, vfs = mount()
    client = boto3.client("s3", region_name=REGION)
    item = next(b for b in client.list_buckets()["Buckets"]
                if b["Name"] == data.bucket)
    raw = vfs.read(f"{_bucket(data)}/describe.json")
    assert raw == to_json_text(item).encode("utf-8")
    assert json.loads(raw)["Name"] == data.bucket
    assert b"ResponseMetadata" not in raw


def test_configuration_files(mount: Mount, data: Any) -> None:
    """Policy, encryption, public access block, versioning and arn."""
    _ctx, vfs = mount()
    d = _bucket(data)
    assert read_text(vfs, f"{d}/arn") == f"arn:aws:s3:::{data.bucket}\n"
    assert read_text(vfs, f"{d}/region") == f"{REGION}\n"
    assert read_json(vfs, f"{d}/policy.json") == \
        seed.bucket_policy(data.account_id)
    encryption = read_json(vfs, f"{d}/encryption.json")
    default = encryption["Rules"][0]["ApplyServerSideEncryptionByDefault"]
    assert default["SSEAlgorithm"] == "aws:kms"
    assert default["KMSMasterKeyID"] == data.kms_key_arn
    pab = read_json(vfs, f"{d}/public-access-block.json")
    assert pab == seed.PUBLIC_ACCESS_BLOCK
    assert read_json(vfs, f"{d}/versioning.json")["Status"] == "Enabled"


def test_tags_are_not_redacted(mount: Mount, data: Any) -> None:
    """Tag values are served verbatim, even secret-looking keys."""
    _ctx, vfs = mount()
    d = _bucket(data)
    assert read_json(vfs, f"{d}/tags.json") == \
        dict(sorted(seed.BUCKET_TAGS.items()))
    assert read_text(vfs, f"{d}/tags/DbPassword") == \
        f"{seed.TAG_SECRET_VALUE}\n"
    assert sorted(vfs.listdir(f"{d}/tags")) == sorted(seed.BUCKET_TAGS)


def test_unconfigured_bucket_gives_null_without_noise(
        mount: Mount, data: Any) -> None:
    """NoSuchBucketPolicy -> null, NoSuchTagSet -> {}; nothing logged."""
    _ctx, vfs = mount()
    d = _bucket(data, data.bucket_plain)
    assert read_text(vfs, f"{d}/policy.json") == "null\n"
    assert read_json(vfs, f"{d}/tags.json") == {}
    assert vfs.listdir(f"{d}/tags") == []
    assert error_lines(vfs, data.account_id) == []


def test_lazy_files_cost_nothing_until_read(mount: Mount,
                                            data: Any) -> None:
    """Derived files are free; a lazy file costs one call per TTL."""
    ctx, vfs = mount()
    vfs.listdir("/")
    d = _bucket(data)
    vfs.listdir(_buckets(data))
    vfs.listdir(d)
    before = ctx.budget.used()
    for name in ("describe.json", "arn", "region"):
        vfs.read(f"{d}/{name}")
    assert ctx.budget.used() == before
    vfs.read(f"{d}/policy.json")
    assert ctx.budget.used() == before + 1
    vfs.read(f"{d}/policy.json")
    assert ctx.budget.used() == before + 1


def test_object_listing_is_off_by_default(mount: Mount, data: Any) -> None:
    """Without --s3-objects no object is listed and no call is made."""
    ctx, vfs = mount()
    hits = count_calls(ctx, "s3", "ListObjectsV2")
    d = _bucket(data)
    assert read_text(vfs, f"{d}/objects-listing.json") == "null\n"
    assert vfs.listdir(f"{d}/objects") == []
    assert hits == []
    assert seed.FAKE_SECRET.encode("utf-8") not in all_contents(vfs, d)


def test_object_listing_stops_at_n_keys(mount: Mount, data: Any) -> None:
    """--s3-objects N lists the first N keys, metadata only, one call."""
    ctx, vfs = mount(s3_objects=2)
    hits = count_calls(ctx, "s3", "ListObjectsV2")
    d = _bucket(data)
    listing = read_json(vfs, f"{d}/objects-listing.json")
    assert [o["Key"] for o in listing] == ["a.txt", "dir/b.txt"]
    size = len(seed.OBJECT_BODY.encode("utf-8"))
    for obj in listing:
        assert set(obj) == {"ETag", "Key", "LastModified", "Size",
                            "StorageClass"}
        assert obj["Size"] == size
    assert vfs.listdir(f"{d}/objects") == ["a.txt.json",
                                           "dir%2Fb.txt.json"]
    entry = read_json(vfs, f"{d}/objects/dir%2Fb.txt.json")
    assert entry["Key"] == "dir/b.txt"
    assert entry["Size"] == size
    assert len(hits) == 1
    assert seed.FAKE_SECRET.encode("utf-8") not in all_contents(vfs, d)


def test_list_buckets_access_denied_degrades(mount: Mount,
                                             data: Any) -> None:
    """AccessDenied on the listing -> empty dir + one errors.log line."""
    ctx, vfs = mount()
    deny(ctx, "s3", "ListBuckets")
    assert vfs.listdir(_buckets(data)) == []
    lines = error_lines(vfs, data.account_id)
    assert len(lines) == 1
    _stamp, account, region, service, op, kind, code, _msg = lines[0]
    assert (account, region, service, op, kind, code) == (
        data.account_id, REGION, "s3", "list_buckets", "access-denied",
        "AccessDenied")
    tables = f"/{data.account_id}/{REGION}/dynamodb/tables"
    assert data.table in vfs.listdir(tables)
    assert vfs.listdir(_buckets(data)) == []
    assert len(error_lines(vfs, data.account_id)) == 1


def test_bucket_policy_access_denied_is_eacces(mount: Mount,
                                               data: Any) -> None:
    """AccessDenied on a lazy file -> EACCES + log; siblings still work."""
    ctx, vfs = mount()
    deny(ctx, "s3", "GetBucketPolicy")
    d = _bucket(data)
    with pytest.raises(PermissionDenied) as info:
        vfs.read(f"{d}/policy.json")
    assert info.value.errno == errno.EACCES
    lines = error_lines(vfs, data.account_id)
    assert [(f[3], f[4], f[5]) for f in lines] == [
        ("s3", "get_bucket_policy", "access-denied")]
    assert read_json(vfs, f"{d}/versioning.json")["Status"] == "Enabled"
