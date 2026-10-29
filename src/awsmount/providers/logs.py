"""CloudWatch Logs provider (docs/coverage.md).

Collection: log-groups. One paginated ``DescribeLogGroups`` call lists
the region; ``describe.json``, retention and stored-bytes are derived
from it. Metric filters, subscription filters and tags are lazy. Log
events are never read (``GetLogEvents``/``FilterLogEvents`` are denied).
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
from awsmount.providers.common import kms_ref
from awsmount.vfs.render import Content

if TYPE_CHECKING:
    from awsmount.session.context import Scope

__all__ = ["LOG_GROUPS", "SERVICE"]

GROUP_MARKER = ":log-group:"


def _strip_star(arn: str) -> str:
    """Remove the trailing ``:*`` of a log group ARN."""
    return arn[:-2] if arn.endswith(":*") else arn


def _group_arn(item: dict[str, Any]) -> str | None:
    """Log group ARN without ``:*``."""
    arn = item.get("logGroupArn") or item.get("arn")
    if not arn:
        return None
    return _strip_star(str(arn))


def _key_from_arn(arn: str) -> str:
    """Log group name from its ARN."""
    if GROUP_MARKER in arn:
        return _strip_star(arn.split(GROUP_MARKER, 1)[1])
    return arn


def _list_log_groups(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated DescribeLogGroups call for the region."""
    return [g for g in lc.paginate("describe_log_groups", "logGroups")
            if isinstance(g, dict) and g.get("logGroupName")]


def _retention(rc: ResourceCtx) -> Content:
    """retention: days, or ``never``."""
    days = rc.item.get("retentionInDays")
    return "never" if days is None else str(days)


def _stored_bytes(rc: ResourceCtx) -> Content:
    """stored-bytes as listed."""
    return str(rc.item.get("storedBytes", 0))


def _metric_filters(rc: ResourceCtx) -> Content:
    """metric-filters.json (lazy)."""
    return rc.paginate("describe_metric_filters", "metricFilters",
                       logGroupName=rc.key)


def _subscription_filters(rc: ResourceCtx) -> Content:
    """subscription-filters.json (lazy)."""
    return rc.paginate("describe_subscription_filters",
                       "subscriptionFilters", logGroupName=rc.key)


def _tags(rc: ResourceCtx) -> dict[str, str]:
    """Tags from ListTagsForResource (ARN without ``:*``)."""
    arn = _group_arn(rc.item)
    if arn is None:
        return {}
    resp = rc.call("list_tags_for_resource", resourceArn=arn)
    tags = resp.get("tags") or {}
    return {str(k): str(v) for k, v in tags.items()}


def _arn(item: dict[str, Any], scope: Scope) -> str | None:
    """ARN of the log group (without ``:*``)."""
    return _group_arn(item)


LOG_GROUPS = CollectionSpec(
    name="log-groups",
    client="logs",
    lister=_list_log_groups,
    key=lambda i: str(i["logGroupName"]),
    ops=frozenset({"DescribeLogGroups", "DescribeMetricFilters",
                   "DescribeSubscriptionFilters",
                   "ListTagsForResource"}),
    arn=_arn,
    tags=TagSpec(fetch=_tags),
    files=(
        FileSpec("retention", _retention),
        FileSpec("stored-bytes", _stored_bytes),
        FileSpec("metric-filters.json", _metric_filters, lazy=True),
        FileSpec("subscription-filters.json", _subscription_filters,
                 lazy=True),
    ),
    links=(
        LinkSpec("kms-key", refs.KMS_KEYS,
                 lambda rc: kms_ref(rc.item.get("kmsKeyId"))),
    ),
    lookup={"arn": lambda i: _group_arn(i) or "",
            "name": lambda i: str(i.get("logGroupName", ""))},
    key_from_arn=_key_from_arn,
)


SERVICE = ServiceSpec(
    dirname="logs",
    scope="region",
    collections=(
        LOG_GROUPS,
    ),
)
