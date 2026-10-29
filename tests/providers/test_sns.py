"""SNS provider against moto: lazy attributes, policy, subscription
endpoint redaction and --reveal, tags, the KMS link and AccessDenied."""

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
from awsmount.session.redact import REDACTED
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

TOPIC_ENTRIES = {"describe.json", "arn", "name", "tags.json", "tags",
                 "policy.json", "subscriptions.json", "links"}


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


def _topics(data: Any) -> str:
    return f"/{data.account_id}/{REGION}/sns/topics"


def _topic(data: Any) -> str:
    return f"{_topics(data)}/{seed.TOPIC_NAME}"


def _by_protocol(subs: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(s["Protocol"]): s for s in subs}


# -- tests ------------------------------------------------------------


def test_listing_layout_and_cost(mount: Mount, data: Any) -> None:
    """One ListTopics call; dir named after the topic, key is the ARN."""
    ctx, vfs = mount()
    vfs.listdir("/")
    base = ctx.budget.used()
    assert vfs.listdir(_topics(data)) == [seed.TOPIC_NAME]
    assert set(vfs.listdir(_topic(data))) == TOPIC_ENTRIES
    assert read_text(vfs, f"{_topic(data)}/arn") == f"{data.topic_arn}\n"
    assert read_text(vfs, f"{_topic(data)}/name") == f"{seed.TOPIC_NAME}\n"
    assert ctx.budget.used() == base + 1


def test_describe_is_lazy_and_shared(mount: Mount, data: Any) -> None:
    """GetTopicAttributes runs once for describe, policy and links."""
    ctx, vfs = mount()
    vfs.listdir(_topics(data))
    base = ctx.budget.used()
    vfs.read(f"{_topic(data)}/describe.json")
    vfs.read(f"{_topic(data)}/policy.json")
    vfs.listdir(f"{_topic(data)}/links")
    # +1 for GetTopicAttributes (shared by describe, policy and links)
    # and +1 for the cached ListKeys used to confirm the link target
    # exists, so no dangling link is served (AWSM-009).
    assert ctx.budget.used() == base + 2


def test_describe_json_matches_get_topic_attributes(
        mount: Mount, data: Any) -> None:
    """describe.json is the canonical render of GetTopicAttributes."""
    _ctx, vfs = mount()
    client = boto3.client("sns", region_name=REGION)
    expected = strip_metadata(client.get_topic_attributes(
        TopicArn=data.topic_arn))
    raw = vfs.read(f"{_topic(data)}/describe.json")
    assert raw == to_json_text(expected).encode("utf-8")
    attrs = json.loads(raw)["Attributes"]
    assert attrs["TopicArn"] == data.topic_arn
    assert attrs["DisplayName"] == seed.TOPIC_DISPLAY


def test_policy_json_is_parsed(mount: Mount, data: Any) -> None:
    """policy.json is the parsed Policy attribute."""
    _ctx, vfs = mount()
    policy = read_json(vfs, f"{_topic(data)}/policy.json")
    assert isinstance(policy, dict)
    assert isinstance(policy["Statement"], list)
    assert policy["Statement"]


def test_subscription_endpoints_are_redacted(mount: Mount,
                                             data: Any) -> None:
    """HTTP(S) endpoints may embed credentials and are redacted."""
    _ctx, vfs = mount()
    raw = vfs.read(f"{_topic(data)}/subscriptions.json")
    subs = _by_protocol(json.loads(raw))
    assert set(subs) == {"http", "https", "sqs"}
    assert subs["https"]["Endpoint"] == REDACTED
    assert subs["http"]["Endpoint"] == REDACTED
    assert subs["sqs"]["Endpoint"] == data.queue_arn
    assert all(s["TopicArn"] == data.topic_arn for s in subs.values())
    assert seed.FAKE_SECRET.encode("utf-8") not in raw


def test_reveal_shows_subscription_endpoints(mount: Mount,
                                             data: Any) -> None:
    """--reveal disables redaction."""
    _ctx, vfs = mount(reveal=True)
    subs = _by_protocol(read_json(vfs,
                                  f"{_topic(data)}/subscriptions.json"))
    assert subs["https"]["Endpoint"] == seed.HTTPS_ENDPOINT
    assert subs["http"]["Endpoint"] == seed.HTTP_ENDPOINT
    assert subs["sqs"]["Endpoint"] == data.queue_arn


def test_no_secret_anywhere_without_reveal(mount: Mount,
                                           data: Any) -> None:
    """A recursive read of sns/ never exposes the embedded secret."""
    _ctx, vfs = mount()
    blob = all_contents(vfs, f"/{data.account_id}/{REGION}/sns")
    assert data.topic_arn.encode("utf-8") in blob
    assert REDACTED.encode("utf-8") in blob
    assert seed.FAKE_SECRET.encode("utf-8") not in blob


def test_tags(mount: Mount, data: Any) -> None:
    """tags.json and tags/<Key> come from ListTagsForResource."""
    _ctx, vfs = mount()
    assert read_json(vfs, f"{_topic(data)}/tags.json") == \
        dict(sorted(seed.TOPIC_TAGS.items()))
    assert read_text(vfs, f"{_topic(data)}/tags/team") == "events\n"


def test_kms_key_link(mount: Mount, data: Any) -> None:
    """links/kms-key points at the topic's KMS key."""
    _ctx, vfs = mount()
    link = f"{_topic(data)}/links/kms-key"
    assert vfs.readlink(link) == f"../../../../kms/keys/{data.kms_key_id}"
    assert vfs.realpath(link) == (
        f"/{data.account_id}/{REGION}/kms/keys/{data.kms_key_id}")


def test_list_topics_access_denied_degrades(mount: Mount,
                                            data: Any) -> None:
    """AccessDenied on ListTopics -> empty dir + one errors.log line."""
    ctx, vfs = mount()
    deny(ctx, "sns", "ListTopics")
    assert vfs.listdir(_topics(data)) == []
    lines = error_lines(vfs, data.account_id)
    assert len(lines) == 1
    assert lines[0][1:7] == [data.account_id, REGION, "sns",
                             "list_topics", "access-denied",
                             "AccessDenied"]
    keys = f"/{data.account_id}/{REGION}/kms/keys"
    assert data.kms_key_id in vfs.listdir(keys)


def test_subscriptions_access_denied_is_eacces(mount: Mount,
                                               data: Any) -> None:
    """A denied subscriptions.json is EACCES; describe.json works."""
    ctx, vfs = mount()
    deny(ctx, "sns", "ListSubscriptionsByTopic")
    with pytest.raises(PermissionDenied) as info:
        vfs.read(f"{_topic(data)}/subscriptions.json")
    assert info.value.errno == errno.EACCES
    ops = [(f[3], f[4], f[5]) for f in error_lines(vfs, data.account_id)]
    assert ops == [("sns", "list_subscriptions_by_topic",
                    "access-denied")]
    attrs = read_json(vfs, f"{_topic(data)}/describe.json")["Attributes"]
    assert attrs["TopicArn"] == data.topic_arn
