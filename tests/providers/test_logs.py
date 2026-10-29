"""CloudWatch Logs provider against moto: escaped group names, derived
files (no N+1), lazy filters, tags, the KMS link and AccessDenied."""

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
from awsmount.vfs import walk as vwalk
from awsmount.vfs.path import escape_name, unescape_name
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

APP_DIR = "%2Fawsmount%2Fapp"
AUDIT_DIR = "%2Fawsmount%2Faudit"
GROUP_ENTRIES = {"describe.json", "arn", "tags.json", "tags", "retention",
                 "stored-bytes", "metric-filters.json",
                 "subscription-filters.json", "links"}


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


def _groups(data: Any) -> str:
    return f"/{data.account_id}/{REGION}/logs/log-groups"


def _group(data: Any, dirname: str = APP_DIR) -> str:
    return f"{_groups(data)}/{dirname}"


# -- tests ------------------------------------------------------------


def test_group_names_are_escaped(mount: Mount, data: Any) -> None:
    """``/`` in log group names is escaped and round-trips."""
    _ctx, vfs = mount()
    names = vfs.listdir(_groups(data))
    assert APP_DIR in names
    assert AUDIT_DIR in names
    assert escape_name(data.log_group) == APP_DIR
    assert unescape_name(APP_DIR) == data.log_group
    found = [p for p, _n in vwalk.find(vfs, _groups(data),
                                       name=data.log_group, max_depth=1)]
    assert found == [_group(data)]


def test_group_directory_layout(mount: Mount, data: Any) -> None:
    """A log group dir has exactly the documented entries."""
    _ctx, vfs = mount()
    assert set(vfs.listdir(_group(data))) == GROUP_ENTRIES
    assert set(vfs.listdir(_group(data, AUDIT_DIR))) == GROUP_ENTRIES


def test_derived_files_cost_no_extra_call(mount: Mount,
                                          data: Any) -> None:
    """One DescribeLogGroups; describe/retention/arn are derived."""
    ctx, vfs = mount()
    vfs.listdir("/")
    base = ctx.budget.used()
    vfs.listdir(_groups(data))
    assert ctx.budget.used() == base + 1
    for dirname in (APP_DIR, AUDIT_DIR):
        for name in ("describe.json", "retention", "stored-bytes", "arn"):
            vfs.read(f"{_group(data, dirname)}/{name}")
    assert ctx.budget.used() == base + 1
    assert read_text(vfs, f"{_group(data)}/retention") == \
        f"{seed.LOG_RETENTION}\n"
    assert read_text(vfs, f"{_group(data, AUDIT_DIR)}/retention") == \
        "never\n"
    assert read_text(vfs, f"{_group(data)}/stored-bytes").strip().isdigit()
    assert read_text(vfs, f"{_group(data)}/arn") == (
        f"arn:aws:logs:{REGION}:{data.account_id}:log-group:"
        f"{data.log_group}\n")


def test_describe_json_is_the_listed_item(mount: Mount, data: Any) -> None:
    """describe.json is the canonical render of the listed log group."""
    _ctx, vfs = mount()
    client = boto3.client("logs", region_name=REGION)
    item = next(g for g in client.describe_log_groups(
        logGroupNamePrefix=data.log_group)["logGroups"]
        if g["logGroupName"] == data.log_group)
    raw = vfs.read(f"{_group(data)}/describe.json")
    assert raw == to_json_text(item).encode("utf-8")
    group = json.loads(raw)
    assert group["logGroupName"] == data.log_group
    assert group["retentionInDays"] == seed.LOG_RETENTION
    assert group["kmsKeyId"] == data.kms_key_arn


def test_lazy_filter_files(mount: Mount, data: Any) -> None:
    """metric-filters.json and subscription-filters.json are lazy."""
    ctx, vfs = mount()
    vfs.listdir(_group(data))
    base = ctx.budget.used()
    filters = read_json(vfs, f"{_group(data)}/metric-filters.json")
    assert ctx.budget.used() == base + 1
    assert [f["filterName"] for f in filters] == [seed.METRIC_FILTER]
    assert filters[0]["filterPattern"] == seed.METRIC_PATTERN
    assert read_json(vfs, f"{_group(data)}/subscription-filters.json") \
        == []
    assert read_json(vfs, f"{_group(data, AUDIT_DIR)}/"
                          "metric-filters.json") == []


def test_tags(mount: Mount, data: Any) -> None:
    """Tags come from ListTagsForResource on the ARN without ``:*``."""
    _ctx, vfs = mount()
    assert read_json(vfs, f"{_group(data)}/tags.json") == \
        dict(sorted(seed.LOG_TAGS.items()))
    assert read_text(vfs, f"{_group(data)}/tags/team") == "platform\n"
    assert read_json(vfs, f"{_group(data, AUDIT_DIR)}/tags.json") == {}


def test_kms_key_link(mount: Mount, data: Any) -> None:
    """links/kms-key points at the group's KMS key; none when unset."""
    _ctx, vfs = mount()
    link = f"{_group(data)}/links/kms-key"
    assert vfs.readlink(link) == f"../../../../kms/keys/{data.kms_key_id}"
    assert vfs.realpath(link) == (
        f"/{data.account_id}/{REGION}/kms/keys/{data.kms_key_id}")
    assert vfs.listdir(f"{_group(data, AUDIT_DIR)}/links") == []


def test_describe_log_groups_access_denied_degrades(
        mount: Mount, data: Any) -> None:
    """Denied listing -> empty dir + one errors.log line."""
    ctx, vfs = mount()
    deny(ctx, "logs", "DescribeLogGroups")
    assert vfs.listdir(_groups(data)) == []
    lines = error_lines(vfs, data.account_id)
    assert len(lines) == 1
    assert lines[0][1:7] == [data.account_id, REGION, "logs",
                             "describe_log_groups", "access-denied",
                             "AccessDenied"]
    buckets = f"/{data.account_id}/{REGION}/s3/buckets"
    assert data.bucket in vfs.listdir(buckets)


def test_metric_filters_access_denied_is_eacces(mount: Mount,
                                                data: Any) -> None:
    """A denied lazy file is EACCES; derived files still work."""
    ctx, vfs = mount()
    deny(ctx, "logs", "DescribeMetricFilters")
    with pytest.raises(PermissionDenied) as info:
        vfs.read(f"{_group(data)}/metric-filters.json")
    assert info.value.errno == errno.EACCES
    ops = [(f[3], f[4], f[5]) for f in error_lines(vfs, data.account_id)]
    assert ops == [("logs", "describe_metric_filters", "access-denied")]
    assert read_text(vfs, f"{_group(data)}/retention") == \
        f"{seed.LOG_RETENTION}\n"
