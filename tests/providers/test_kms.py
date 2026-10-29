"""KMS provider against moto: keys (lazy describe, policy, rotation,
tags), aliases, the key <-> alias cross links and AccessDenied."""

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
from awsmount.errors import PermissionDenied
from awsmount.session.context import Context
from awsmount.tree.root import build_vfs
from awsmount.vfs.node import DirNode
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
ALIAS_DIR = seed.DATA_KMS_ALIAS[len("alias/"):]

KEY_ENTRIES = {"describe.json", "arn", "tags.json", "tags", "policy.json",
               "rotation.json", "links"}
ALIAS_ENTRIES = {"describe.json", "arn", "links"}


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


# -- helpers ----------------------------------------------------------


def _kms(data: Any) -> str:
    return f"/{data.account_id}/{REGION}/kms"


def _key(data: Any) -> str:
    return f"{_kms(data)}/keys/{data.kms_key_id}"


def _alias(data: Any) -> str:
    return f"{_kms(data)}/aliases/{ALIAS_DIR}"


# -- tests ------------------------------------------------------------


def test_key_listing_layout_and_cost(mount: Mount, data: Any) -> None:
    """One ListKeys call; key dirs are named by key id."""
    ctx, vfs = mount()
    vfs.listdir("/")
    base = ctx.budget.used()
    assert data.kms_key_id in vfs.listdir(f"{_kms(data)}/keys")
    assert ctx.budget.used() == base + 1
    assert set(vfs.listdir(_key(data))) == KEY_ENTRIES
    assert read_text(vfs, f"{_key(data)}/arn") == f"{data.kms_key_arn}\n"
    assert ctx.budget.used() == base + 1
    vfs.read(f"{_key(data)}/describe.json")
    vfs.read(f"{_key(data)}/describe.json")
    assert ctx.budget.used() == base + 2


def test_describe_json_matches_describe_key(mount: Mount,
                                            data: Any) -> None:
    """describe.json is the canonical render of DescribeKey."""
    _ctx, vfs = mount()
    client = boto3.client("kms", region_name=REGION)
    expected = strip_metadata(client.describe_key(KeyId=data.kms_key_id))
    raw = vfs.read(f"{_key(data)}/describe.json")
    assert raw == to_json_text(expected).encode("utf-8")
    meta = json.loads(raw)["KeyMetadata"]
    assert meta["KeyId"] == data.kms_key_id
    assert meta["Arn"] == data.kms_key_arn
    assert meta["Description"] == seed.DATA_KMS_DESCRIPTION
    assert meta["KeyState"] == "Enabled"


def test_policy_and_rotation(mount: Mount, data: Any) -> None:
    """policy.json is the parsed default policy; rotation is enabled."""
    _ctx, vfs = mount()
    assert read_json(vfs, f"{_key(data)}/policy.json") == \
        seed.data_key_policy(data.account_id)
    rotation = read_json(vfs, f"{_key(data)}/rotation.json")
    assert rotation["KeyRotationEnabled"] is True


def test_key_tags(mount: Mount, data: Any) -> None:
    """Tags come from ListResourceTags (TagKey/TagValue shape)."""
    _ctx, vfs = mount()
    assert read_json(vfs, f"{_key(data)}/tags.json") == \
        dict(sorted(seed.DATA_KMS_TAGS.items()))
    assert read_text(vfs, f"{_key(data)}/tags/Environment") == "prod\n"


def test_key_and_alias_cross_links(mount: Mount, data: Any) -> None:
    """key/links/aliases/<a> and alias/links/target-key resolve."""
    _ctx, vfs = mount()
    aliases_dir = f"{_key(data)}/links/aliases"
    assert vfs.listdir(aliases_dir) == [ALIAS_DIR]
    link = f"{aliases_dir}/{ALIAS_DIR}"
    assert vfs.readlink(link) == f"../../../../aliases/{ALIAS_DIR}"
    assert vfs.realpath(link) == _alias(data)
    target = f"{_alias(data)}/links/target-key"
    assert vfs.readlink(target) == f"../../../keys/{data.kms_key_id}"
    node = vfs.resolve(target)
    assert isinstance(node, DirNode)
    assert node.path == _key(data)


def test_alias_directory(mount: Mount, data: Any) -> None:
    """Aliases are derived from ListAliases and carry no tags."""
    _ctx, vfs = mount()
    assert ALIAS_DIR in vfs.listdir(f"{_kms(data)}/aliases")
    assert set(vfs.listdir(_alias(data))) == ALIAS_ENTRIES
    alias = read_json(vfs, f"{_alias(data)}/describe.json")
    assert alias["AliasName"] == seed.DATA_KMS_ALIAS
    assert alias["TargetKeyId"] == data.kms_key_id
    arn = read_text(vfs, f"{_alias(data)}/arn").strip()
    assert arn.endswith(f":{seed.DATA_KMS_ALIAS}")


def test_list_keys_access_denied_degrades(mount: Mount,
                                          data: Any) -> None:
    """Denied ListKeys -> empty keys/, one log line; aliases still list."""
    ctx, vfs = mount()
    deny(ctx, "kms", "ListKeys")
    assert vfs.listdir(f"{_kms(data)}/keys") == []
    assert ALIAS_DIR in vfs.listdir(f"{_kms(data)}/aliases")
    lines = error_lines(vfs, data.account_id)
    assert len(lines) == 1
    assert lines[0][1:7] == [data.account_id, REGION, "kms", "list_keys",
                             "access-denied", "AccessDenied"]


def test_key_policy_access_denied_is_eacces(mount: Mount,
                                            data: Any) -> None:
    """A denied policy.json is EACCES; rotation.json still works."""
    ctx, vfs = mount()
    deny(ctx, "kms", "GetKeyPolicy")
    with pytest.raises(PermissionDenied) as info:
        vfs.read(f"{_key(data)}/policy.json")
    assert info.value.errno == errno.EACCES
    ops = [(f[3], f[4], f[5]) for f in error_lines(vfs, data.account_id)]
    assert ops == [("kms", "get_key_policy", "access-denied")]
    rotation = read_json(vfs, f"{_key(data)}/rotation.json")
    assert rotation["KeyRotationEnabled"] is True
