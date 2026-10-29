"""SQS provider against moto: lazy attributes, policy, dead-letter and
KMS links, tags, messages never received, AccessDenied and seed
idempotency."""

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
from awsmount.vfs.node import DirNode, FileNode, SymlinkNode
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

QUEUE_ENTRIES = {"describe.json", "arn", "tags.json", "tags", "url",
                 "policy.json", "links"}


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


def _queues(data: Any) -> str:
    return f"/{data.account_id}/{REGION}/sqs/queues"


def _queue(data: Any, name: str | None = None) -> str:
    return f"{_queues(data)}/{name or seed.QUEUE_NAME}"


# -- tests ------------------------------------------------------------


def test_listing_layout_and_cost(mount: Mount, data: Any) -> None:
    """One ListQueues call; queue dirs are named after the URL."""
    ctx, vfs = mount()
    vfs.listdir("/")
    base = ctx.budget.used()
    assert sorted(vfs.listdir(_queues(data))) == sorted(
        [seed.QUEUE_NAME, seed.DLQ_NAME])
    assert ctx.budget.used() == base + 1
    assert set(vfs.listdir(_queue(data))) == QUEUE_ENTRIES
    assert read_text(vfs, f"{_queue(data)}/url") == f"{data.queue_url}\n"
    assert read_text(vfs, f"{_queue(data)}/arn") == f"{data.queue_arn}\n"
    assert ctx.budget.used() == base + 1


def test_describe_is_lazy_and_shared_by_policy_and_links(
        mount: Mount, data: Any) -> None:
    """GetQueueAttributes runs once; policy and links reuse it."""
    ctx, vfs = mount()
    vfs.listdir(_queues(data))
    base = ctx.budget.used()
    vfs.read(f"{_queue(data)}/describe.json")
    assert ctx.budget.used() == base + 1
    vfs.read(f"{_queue(data)}/policy.json")
    assert ctx.budget.used() == base + 1
    vfs.listdir(f"{_queue(data)}/links")
    # +1: the cached ListKeys that confirms the link target exists
    # (AWSM-009). GetQueueAttributes itself still ran only once.
    assert ctx.budget.used() == base + 2
    vfs.read(f"{_queue(data)}/tags.json")
    assert ctx.budget.used() == base + 3


def test_describe_json_matches_get_queue_attributes(
        mount: Mount, data: Any) -> None:
    """describe.json is the canonical render of GetQueueAttributes."""
    _ctx, vfs = mount()
    client = boto3.client("sqs", region_name=REGION)
    expected = strip_metadata(client.get_queue_attributes(
        QueueUrl=data.queue_url, AttributeNames=["All"]))
    raw = vfs.read(f"{_queue(data)}/describe.json")
    assert raw == to_json_text(expected).encode("utf-8")
    attrs = json.loads(raw)["Attributes"]
    assert attrs["QueueArn"] == data.queue_arn
    assert attrs["VisibilityTimeout"] == seed.QUEUE_VISIBILITY
    assert attrs["KmsMasterKeyId"] == data.kms_key_id


def test_policy_json_is_parsed(mount: Mount, data: Any) -> None:
    """policy.json holds the parsed Policy attribute; DLQ has none."""
    _ctx, vfs = mount()
    assert read_json(vfs, f"{_queue(data)}/policy.json") == \
        seed.queue_policy(data.account_id, REGION)
    assert read_text(vfs, f"{_queue(data, seed.DLQ_NAME)}/policy.json") \
        == "null\n"


def test_dead_letter_queue_link(mount: Mount, data: Any) -> None:
    """links/dead-letter-queue points at the redrive target queue."""
    _ctx, vfs = mount()
    link = f"{_queue(data)}/links/dead-letter-queue"
    assert vfs.readlink(link) == f"../../{seed.DLQ_NAME}"
    node = vfs.resolve(link)
    assert isinstance(node, DirNode)
    assert node.path == _queue(data, seed.DLQ_NAME)
    assert read_text(vfs, f"{link}/arn") == f"{data.dlq_arn}\n"
    dlq_links = vfs.listdir(f"{_queue(data, seed.DLQ_NAME)}/links")
    assert "dead-letter-queue" not in dlq_links
    assert "kms-key" not in dlq_links


def test_kms_key_link(mount: Mount, data: Any) -> None:
    """links/kms-key points at the queue's KMS key."""
    _ctx, vfs = mount()
    link = f"{_queue(data)}/links/kms-key"
    assert vfs.readlink(link) == f"../../../../kms/keys/{data.kms_key_id}"
    assert vfs.realpath(link) == (
        f"/{data.account_id}/{REGION}/kms/keys/{data.kms_key_id}")


def test_tags_are_not_redacted(mount: Mount, data: Any) -> None:
    """Tag values are served verbatim (documented in security.md)."""
    _ctx, vfs = mount()
    assert read_json(vfs, f"{_queue(data)}/tags.json") == \
        dict(sorted(seed.QUEUE_TAGS.items()))
    assert read_text(vfs, f"{_queue(data)}/tags/DbPassword") == \
        f"{seed.TAG_SECRET_VALUE}\n"


def test_messages_are_never_received(mount: Mount, data: Any) -> None:
    """No message body appears anywhere under sqs/."""
    _ctx, vfs = mount()
    blob = all_contents(vfs, f"/{data.account_id}/{REGION}/sqs")
    assert data.queue_arn.encode("utf-8") in blob
    assert seed.FAKE_SECRET.encode("utf-8") not in blob
    attrs = boto3.client("sqs", region_name=REGION).get_queue_attributes(
        QueueUrl=data.queue_url,
        AttributeNames=["ApproximateNumberOfMessages",
                        "ApproximateNumberOfMessagesNotVisible"])
    assert attrs["Attributes"]["ApproximateNumberOfMessages"] == "1"
    assert attrs["Attributes"][
        "ApproximateNumberOfMessagesNotVisible"] == "0"


def test_list_queues_access_denied_degrades(mount: Mount,
                                            data: Any) -> None:
    """AccessDenied on ListQueues -> empty dir + one errors.log line."""
    ctx, vfs = mount()
    deny(ctx, "sqs", "ListQueues")
    assert vfs.listdir(_queues(data)) == []
    lines = error_lines(vfs, data.account_id)
    assert len(lines) == 1
    assert lines[0][3:7] == ["sqs", "list_queues", "access-denied",
                             "AccessDenied"]
    topics = f"/{data.account_id}/{REGION}/sns/topics"
    assert seed.TOPIC_NAME in vfs.listdir(topics)


def test_get_queue_attributes_access_denied_is_eacces(
        mount: Mount, data: Any) -> None:
    """Denied attributes make describe.json and policy.json EACCES."""
    ctx, vfs = mount()
    deny(ctx, "sqs", "GetQueueAttributes")
    for name in ("describe.json", "policy.json"):
        with pytest.raises(PermissionDenied) as info:
            vfs.read(f"{_queue(data)}/{name}")
        assert info.value.errno == errno.EACCES
    ops = {(f[3], f[4], f[5]) for f in error_lines(vfs, data.account_id)}
    assert ops == {("sqs", "get_queue_attributes", "access-denied")}
    assert read_text(vfs, f"{_queue(data)}/url") == f"{data.queue_url}\n"


def test_seed_data_is_idempotent(data: Any) -> None:
    """Seeding twice returns the same ids and creates nothing new."""
    again = seed.seed_data(boto3.Session(region_name=REGION))
    assert again == data
    sqs = boto3.client("sqs", region_name=REGION)
    names = sorted(u.rsplit("/", 1)[-1]
                   for u in sqs.list_queues().get("QueueUrls", []))
    assert names == sorted([seed.QUEUE_NAME, seed.DLQ_NAME])
    attrs = sqs.get_queue_attributes(
        QueueUrl=data.queue_url,
        AttributeNames=["ApproximateNumberOfMessages"])["Attributes"]
    assert attrs["ApproximateNumberOfMessages"] == "1"
    sns = boto3.client("sns", region_name=REGION)
    subs = sns.list_subscriptions_by_topic(
        TopicArn=data.topic_arn)["Subscriptions"]
    assert len(subs) == 3
    kms = boto3.client("kms", region_name=REGION)
    aliases = [a for a in kms.list_aliases()["Aliases"]
               if a["AliasName"] == seed.DATA_KMS_ALIAS]
    assert len(aliases) == 1
    s3 = boto3.client("s3", region_name=REGION)
    keys = [o["Key"] for o in s3.list_objects_v2(
        Bucket=data.bucket).get("Contents", [])]
    assert keys == list(seed.OBJECT_KEYS)
