"""Amazon CloudWatch provider: alarms (metric and composite).

One paginated DescribeAlarms call lists both kinds, so ``describe.json``
and the small files are derived from the listing. Tags are lazy
(ListTagsForResource). Metric data, dashboards and log events are not
covered.
"""

from __future__ import annotations

from typing import Any

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
from awsmount.providers.common import parse_arn
from awsmount.providers.ec2 import field_text

__all__ = ["ALARMS", "SERVICE"]


def _list_alarms(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated DescribeAlarms call (metric and composite alarms)."""
    return [a for a in lc.paginate(
        "describe_alarms", ["MetricAlarms", "CompositeAlarms"],
        AlarmTypes=["MetricAlarm", "CompositeAlarm"])
        if isinstance(a, dict)]


def _tags(rc: ResourceCtx) -> dict[str, str]:
    """Lazy tags (ListTagsForResource on the alarm ARN)."""
    arn = rc.item.get("AlarmArn")
    if not arn:
        return {}
    resp = rc.call("list_tags_for_resource", ResourceARN=str(arn))
    out: dict[str, str] = {}
    for tag in resp.get("Tags", []) or []:
        if isinstance(tag, dict) and "Key" in tag:
            out[str(tag["Key"])] = str(tag.get("Value", ""))
    return out


def _sns_topics(rc: ResourceCtx) -> list[str]:
    """SNS topic ARNs among the alarm, OK and insufficient-data actions."""
    out: list[str] = []
    for field in ("AlarmActions", "OKActions", "InsufficientDataActions"):
        for action in rc.item.get(field) or []:
            parsed = parse_arn(str(action))
            if parsed is not None and parsed.service == "sns" \
                    and str(action) not in out:
                out.append(str(action))
    return out


def _instances(rc: ResourceCtx) -> list[str]:
    """EC2 instance ids among the metric dimensions."""
    dims = rc.item.get("Dimensions")
    if not isinstance(dims, list):
        return []
    return [str(d["Value"]) for d in dims
            if isinstance(d, dict) and d.get("Name") == "InstanceId"
            and d.get("Value")]


ALARMS = CollectionSpec(
    name="alarms",
    client="cloudwatch",
    lister=_list_alarms,
    key=lambda i: str(i["AlarmName"]),
    ops=frozenset({"DescribeAlarms", "ListTagsForResource"}),
    arn=lambda i, _scope: str(i["AlarmArn"]) if i.get("AlarmArn") else None,
    tags=TagSpec(fetch=_tags),
    files=(
        FileSpec("state", field_text("StateValue")),
        FileSpec("metric", field_text("MetricName")),
    ),
    links=(
        LinkSpec("sns-topics", refs.SNS_TOPICS, _sns_topics, by="arn",
                 many=True),
        LinkSpec("instances", refs.INSTANCES, _instances, many=True),
    ),
    lookup={"arn": lambda i: str(i.get("AlarmArn", "")),
            "name": lambda i: str(i.get("AlarmName", ""))},
)


SERVICE = ServiceSpec(
    dirname="cloudwatch",
    scope="region",
    collections=(ALARMS,),
)
