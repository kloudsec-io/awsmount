"""SQS provider (docs/coverage.md).

Collection: queues. ``ListQueues`` returns URLs only, so the listing is
one paginated call and ``describe.json`` (GetQueueAttributes All) is
lazy. policy.json, the dead-letter-queue and kms-key links and the tags
are derived from lazy calls. Messages are never received.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from awsmount.providers import refs
from awsmount.providers.base import (
    CollectionSpec,
    FileSpec,
    LinkSpec,
    ListCtx,
    ResourceCtx,
    ServiceSpec,
    TagSpec,
)
from awsmount.providers.common import (
    kms_ref,
    make_arn,
    name_from_arn,
    parse_json_text,
)
from awsmount.providers.ec2 import field_text
from awsmount.vfs.render import Content

if TYPE_CHECKING:
    from awsmount.session.context import Scope

__all__ = ["QUEUES", "SERVICE", "queue_name"]


def queue_name(url: str) -> str:
    """Queue name: the last segment of the queue URL."""
    return url.rstrip("/").rsplit("/", 1)[-1]


def _list_queues(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated ListQueues call (URLs only)."""
    urls = lc.paginate("list_queues", "QueueUrls", MaxResults=1000)
    return [{"QueueUrl": u} for u in urls if isinstance(u, str) and u]


def _queue_arn(item: dict[str, Any], scope: Scope) -> str | None:
    """Queue ARN built from the URL (account taken from the URL)."""
    url = item.get("QueueUrl")
    if not url:
        return None
    parts = str(url).rstrip("/").split("/")
    account: str | None = None
    if len(parts) >= 2 and parts[-2].isdigit():
        account = parts[-2]
    return make_arn(scope, "sqs", queue_name(str(url)), account=account)


def _describe_queue(rc: ResourceCtx) -> dict[str, Any]:
    """describe.json (lazy GetQueueAttributes AttributeNames=[All])."""
    return rc.call("get_queue_attributes", QueueUrl=rc.item["QueueUrl"],
                   AttributeNames=["All"])


def _attributes(rc: ResourceCtx) -> dict[str, Any]:
    """Queue attributes from the (cached) describe call."""
    attrs = rc.detail().get("Attributes") or {}
    return attrs if isinstance(attrs, dict) else {}


def _policy(rc: ResourceCtx) -> Content:
    """policy.json: the parsed Policy attribute (null if none)."""
    policy = _attributes(rc).get("Policy")
    return parse_json_text(policy)  # type: ignore[no-any-return]


def _dead_letter(rc: ResourceCtx) -> str | None:
    """ARN of the redrive target queue, if any."""
    redrive = parse_json_text(_attributes(rc).get("RedrivePolicy"))
    if not isinstance(redrive, dict):
        return None
    target = redrive.get("deadLetterTargetArn")
    return str(target) if target else None


def _kms_key(rc: ResourceCtx) -> str | None:
    """KMS key of the queue (aliases give no link)."""
    return kms_ref(_attributes(rc).get("KmsMasterKeyId"))


def _tags(rc: ResourceCtx) -> dict[str, str]:
    """Tags from ListQueueTags."""
    resp = rc.call("list_queue_tags", QueueUrl=rc.item["QueueUrl"])
    tags = resp.get("Tags") or {}
    return {str(k): str(v) for k, v in tags.items()}


QUEUES = CollectionSpec(
    name="queues",
    client="sqs",
    lister=_list_queues,
    key=lambda i: queue_name(str(i["QueueUrl"])),
    ops=frozenset({"ListQueues", "GetQueueAttributes", "ListQueueTags"}),
    arn=_queue_arn,
    describe=_describe_queue,
    tags=TagSpec(fetch=_tags),
    files=(
        FileSpec("url", field_text("QueueUrl")),
        FileSpec("policy.json", _policy, lazy=True),
    ),
    links=(
        LinkSpec("dead-letter-queue", refs.SQS_QUEUES, _dead_letter,
                 by="arn"),
        LinkSpec("kms-key", refs.KMS_KEYS, _kms_key),
    ),
    lookup={"name": lambda i: queue_name(str(i.get("QueueUrl", "")))},
    key_from_arn=name_from_arn,
)


SERVICE = ServiceSpec(
    dirname="sqs",
    scope="region",
    collections=(
        QUEUES,
    ),
)
