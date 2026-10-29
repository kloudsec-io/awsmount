"""SNS provider (docs/coverage.md).

Collection: topics. ``ListTopics`` returns ARNs only, so the listing is
one paginated call and ``describe.json`` (GetTopicAttributes) is lazy.
The directory name is the topic name taken from the ARN; the key is the
ARN itself. ``subscriptions.json`` redacts HTTP(S) endpoints (they may
embed credentials) unless ``--reveal``.
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
from awsmount.providers.common import kms_ref, name_from_arn
from awsmount.providers.common import parse_json_text
from awsmount.vfs.render import Content

if TYPE_CHECKING:
    from awsmount.session.context import Scope

__all__ = ["SERVICE", "TOPICS"]


def _list_topics(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated ListTopics call (ARNs only)."""
    return [t for t in lc.paginate("list_topics", "Topics")
            if isinstance(t, dict) and t.get("TopicArn")]


def _topic_arn(item: dict[str, Any], scope: Scope) -> str | None:
    """ARN of the topic as listed."""
    arn = item.get("TopicArn")
    return str(arn) if arn else None


def _describe_topic(rc: ResourceCtx) -> dict[str, Any]:
    """describe.json (lazy GetTopicAttributes)."""
    return rc.call("get_topic_attributes", TopicArn=rc.key)


def _attributes(rc: ResourceCtx) -> dict[str, Any]:
    """Topic attributes from the (cached) describe call."""
    attrs = rc.detail().get("Attributes") or {}
    return attrs if isinstance(attrs, dict) else {}


def _policy(rc: ResourceCtx) -> Content:
    """policy.json: the parsed Policy attribute (null if none)."""
    policy = _attributes(rc).get("Policy")
    return parse_json_text(policy)  # type: ignore[no-any-return]


def _subscriptions(rc: ResourceCtx) -> Content:
    """subscriptions.json (lazy ListSubscriptionsByTopic)."""
    return rc.paginate("list_subscriptions_by_topic", "Subscriptions",
                       TopicArn=rc.key)


def _kms_key(rc: ResourceCtx) -> str | None:
    """KMS key of the topic (aliases give no link)."""
    return kms_ref(_attributes(rc).get("KmsMasterKeyId"))


def _tags(rc: ResourceCtx) -> dict[str, str]:
    """Tags from ListTagsForResource."""
    resp = rc.call("list_tags_for_resource", ResourceArn=rc.key)
    return {str(t["Key"]): str(t.get("Value", ""))
            for t in resp.get("Tags", []) or []
            if isinstance(t, dict) and "Key" in t}


TOPICS = CollectionSpec(
    name="topics",
    client="sns",
    lister=_list_topics,
    key=lambda i: str(i["TopicArn"]),
    ops=frozenset({"ListTopics", "GetTopicAttributes",
                   "ListSubscriptionsByTopic", "ListTagsForResource"}),
    display=lambda i: name_from_arn(str(i["TopicArn"])),
    arn=_topic_arn,
    name_of=lambda i: name_from_arn(str(i.get("TopicArn", ""))) or None,
    describe=_describe_topic,
    tags=TagSpec(fetch=_tags),
    files=(
        FileSpec("policy.json", _policy, lazy=True),
        FileSpec("subscriptions.json", _subscriptions, lazy=True,
                 redact="sns"),
    ),
    links=(
        LinkSpec("kms-key", refs.KMS_KEYS, _kms_key),
    ),
    lookup={"arn": lambda i: str(i.get("TopicArn", "")),
            "name": lambda i: name_from_arn(str(i.get("TopicArn", "")))},
    key_from_arn=lambda arn: arn,
)


SERVICE = ServiceSpec(
    dirname="sns",
    scope="region",
    collections=(
        TOPICS,
    ),
)
