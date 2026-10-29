"""Amazon EC2 Auto Scaling provider: groups.

One paginated DescribeAutoScalingGroups call lists the groups with all
their fields, so every file and link is derived from the listing (no lazy
files). Tags are inline. Launch configurations, the legacy kind, are not
covered; ``links/launch-template`` points to the launch template of a
group (or of its mixed instances policy).
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
from awsmount.providers.ec2 import field_text, pluck

__all__ = ["GROUPS", "SERVICE", "group_from_arn"]


def group_from_arn(arn: str) -> str:
    """Group name from ``...:autoScalingGroupName/<name>``."""
    marker = "autoScalingGroupName/"
    if marker in arn:
        return arn.split(marker, 1)[1]
    return arn


def _list_groups(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated DescribeAutoScalingGroups call."""
    return [g for g in lc.paginate("describe_auto_scaling_groups",
                                   "AutoScalingGroups")
            if isinstance(g, dict)]


def _launch_template(rc: ResourceCtx) -> str | None:
    """Launch template id, from the group or its mixed instances policy."""
    item = rc.item
    spec = item.get("LaunchTemplate")
    if not isinstance(spec, dict):
        policy = item.get("MixedInstancesPolicy")
        inner = policy.get("LaunchTemplate") if isinstance(
            policy, dict) else None
        spec = inner.get("LaunchTemplateSpecification") if isinstance(
            inner, dict) else None
    if not isinstance(spec, dict):
        return None
    value = spec.get("LaunchTemplateId")
    return str(value) if value else None


def _subnets(rc: ResourceCtx) -> list[str]:
    """Subnet ids of ``VPCZoneIdentifier`` (comma separated)."""
    raw = rc.item.get("VPCZoneIdentifier")
    if not isinstance(raw, str):
        return []
    return [s.strip() for s in raw.split(",") if s.strip()]


def _target_groups(rc: ResourceCtx) -> list[str]:
    value = rc.item.get("TargetGroupARNs")
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, str) and v]


GROUPS = CollectionSpec(
    name="groups",
    client="autoscaling",
    lister=_list_groups,
    key=lambda i: str(i["AutoScalingGroupName"]),
    ops=frozenset({"DescribeAutoScalingGroups"}),
    arn=lambda i, _scope: (str(i["AutoScalingGroupARN"])
                           if i.get("AutoScalingGroupARN") else None),
    tags=TagSpec(inline="Tags", style="list"),
    files=(
        FileSpec("min-size", field_text("MinSize")),
        FileSpec("max-size", field_text("MaxSize")),
        FileSpec("desired-capacity", field_text("DesiredCapacity")),
    ),
    links=(
        LinkSpec("launch-template", refs.LAUNCH_TEMPLATES,
                 _launch_template),
        LinkSpec("subnets", refs.SUBNETS, _subnets, many=True),
        LinkSpec("target-groups", refs.TARGET_GROUPS, _target_groups,
                 by="arn", many=True),
        LinkSpec("instances", refs.INSTANCES,
                 lambda rc: pluck(rc.item.get("Instances"), "InstanceId"),
                 many=True),
    ),
    lookup={"arn": lambda i: str(i.get("AutoScalingGroupARN", "")),
            "name": lambda i: str(i.get("AutoScalingGroupName", ""))},
    key_from_arn=group_from_arn,
)


SERVICE = ServiceSpec(
    dirname="autoscaling",
    scope="region",
    collections=(GROUPS,),
)
