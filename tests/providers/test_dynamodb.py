"""DynamoDB provider against moto: lazy describe, detail files, tags,
the KMS link, item data never read, AccessDenied and the API budget."""

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
from awsmount.errors import AwsMountError, BudgetExceeded, PermissionDenied
from awsmount.session.context import Context
from awsmount.tree.root import build_vfs
from awsmount.vfs.node import FileNode, SymlinkNode
from awsmount.vfs.render import strip_metadata, to_json_text
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

TABLE_ENTRIES = {"describe.json", "arn", "tags.json", "tags", "ttl.json",
                 "continuous-backups.json", "links"}


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


def _tables(data: Any) -> str:
    return f"/{data.account_id}/{REGION}/dynamodb/tables"


def _table(data: Any) -> str:
    return f"{_tables(data)}/{data.table}"


# -- tests ------------------------------------------------------------


def test_listing_costs_one_call_and_describe_is_lazy(
        mount: Mount, data: Any) -> None:
    """ListTables is the only listing call; DescribeTable waits for a
    read and is then cached."""
    ctx, vfs = mount()
    vfs.listdir("/")
    base = ctx.budget.used()
    assert data.table in vfs.listdir(_tables(data))
    assert ctx.budget.used() == base + 1
    vfs.listdir(_table(data))
    vfs.read(f"{_table(data)}/arn")
    assert ctx.budget.used() == base + 1
    vfs.read(f"{_table(data)}/describe.json")
    assert ctx.budget.used() == base + 2
    vfs.read(f"{_table(data)}/describe.json")
    vfs.listdir(f"{_table(data)}/links")
    # links/ confirms its targets against cached target listings
    # (AWSM-009): one list call per target collection, once per TTL.
    assert ctx.budget.used() == base + 3
    vfs.listdir(f"{_table(data)}/links")
    assert ctx.budget.used() == base + 3


def test_table_directory_layout(mount: Mount, data: Any) -> None:
    """A table dir has exactly the documented entries."""
    _ctx, vfs = mount()
    assert set(vfs.listdir(_table(data))) == TABLE_ENTRIES


def test_describe_json_matches_describe_table(mount: Mount,
                                              data: Any) -> None:
    """describe.json is the canonical render of DescribeTable."""
    _ctx, vfs = mount()
    client = boto3.client("dynamodb", region_name=REGION)
    expected = strip_metadata(client.describe_table(TableName=data.table))
    raw = vfs.read(f"{_table(data)}/describe.json")
    assert raw == to_json_text(expected).encode("utf-8")
    table = json.loads(raw)["Table"]
    assert table["TableName"] == data.table
    assert table["KeySchema"] == [{"AttributeName": "pk",
                                   "KeyType": "HASH"}]
    assert b"ResponseMetadata" not in raw


def test_detail_files(mount: Mount, data: Any) -> None:
    """arn, ttl.json and continuous-backups.json."""
    _ctx, vfs = mount()
    d = _table(data)
    assert read_text(vfs, f"{d}/arn") == (
        f"arn:aws:dynamodb:{REGION}:{data.account_id}:table/{data.table}\n")
    assert read_text(vfs, f"{d}/arn").strip() == data.table_arn
    ttl = read_json(vfs, f"{d}/ttl.json")["TimeToLiveDescription"]
    assert ttl["TimeToLiveStatus"] == "ENABLED"
    assert ttl["AttributeName"] == seed.TABLE_TTL_ATTRIBUTE
    backups = read_json(vfs, f"{d}/continuous-backups.json")
    pitr = backups["ContinuousBackupsDescription"][
        "PointInTimeRecoveryDescription"]
    assert pitr["PointInTimeRecoveryStatus"] == "ENABLED"


def test_tags(mount: Mount, data: Any) -> None:
    """tags.json and tags/<Key> come from ListTagsOfResource."""
    _ctx, vfs = mount()
    d = _table(data)
    assert read_json(vfs, f"{d}/tags.json") == \
        dict(sorted(seed.TABLE_TAGS.items()))
    assert read_text(vfs, f"{d}/tags/team") == "orders\n"


def test_kms_key_link_resolves(mount: Mount, data: Any) -> None:
    """links/kms-key is a relative symlink to the table's KMS key."""
    _ctx, vfs = mount()
    link = f"{_table(data)}/links/kms-key"
    assert vfs.readlink(link) == f"../../../../kms/keys/{data.kms_key_id}"
    assert vfs.realpath(link) == (
        f"/{data.account_id}/{REGION}/kms/keys/{data.kms_key_id}")
    assert "describe.json" in vfs.listdir(link)


def test_item_data_is_never_read(mount: Mount, data: Any) -> None:
    """No file under dynamodb/ exposes table items."""
    _ctx, vfs = mount()
    blob = all_contents(vfs, f"/{data.account_id}/{REGION}/dynamodb")
    assert data.table.encode("utf-8") in blob
    assert seed.FAKE_SECRET.encode("utf-8") not in blob
    assert b"order-1" not in blob


def test_list_tables_access_denied_degrades(mount: Mount,
                                            data: Any) -> None:
    """AccessDenied on ListTables -> empty dir + one errors.log line."""
    ctx, vfs = mount()
    deny(ctx, "dynamodb", "ListTables")
    assert vfs.listdir(_tables(data)) == []
    lines = error_lines(vfs, data.account_id)
    assert len(lines) == 1
    assert lines[0][1:7] == [data.account_id, REGION, "dynamodb",
                             "list_tables", "access-denied",
                             "AccessDenied"]
    queues = f"/{data.account_id}/{REGION}/sqs/queues"
    assert seed.QUEUE_NAME in vfs.listdir(queues)


def test_describe_table_access_denied_is_eacces(mount: Mount,
                                                data: Any) -> None:
    """A denied lazy describe.json is EACCES; ttl.json still works."""
    ctx, vfs = mount()
    deny(ctx, "dynamodb", "DescribeTable")
    d = _table(data)
    with pytest.raises(PermissionDenied) as info:
        vfs.read(f"{d}/describe.json")
    assert info.value.errno == errno.EACCES
    ops = [(f[3], f[4]) for f in error_lines(vfs, data.account_id)]
    assert ("dynamodb", "describe_table") in ops
    ttl = read_json(vfs, f"{d}/ttl.json")["TimeToLiveDescription"]
    assert ttl["TimeToLiveStatus"] == "ENABLED"


def test_budget_exhaustion_is_eio_and_cache_still_served(
        mount: Mount, data: Any) -> None:
    """--max-api-calls 3: the listing fits, the next read is EIO."""
    ctx, vfs = mount(max_api_calls=3)
    vfs.listdir("/")
    assert ctx.budget.used() == 2
    assert data.table in vfs.listdir(_tables(data))
    with pytest.raises(BudgetExceeded) as info:
        vfs.read(f"{_table(data)}/describe.json")
    assert info.value.errno == errno.EIO
    assert "budget exhausted" in str(info.value)
    assert data.table in vfs.listdir(_tables(data))
    assert read_text(vfs, f"{_table(data)}/arn").strip() == data.table_arn
    kinds = [line.split("\t")[5]
             for line in ctx.errors.render().decode().splitlines()]
    assert kinds.count("budget") == 1
