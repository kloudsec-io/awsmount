"""Elastic Load Balancing v2 provider (docs/coverage.md).

Collections: load-balancers (with nested ``listeners``, which have nested
``rules``) and target-groups. Each collection is listed with one paginated
describe call; the nested ones cost one call per parent when opened.
``describe.json`` and the small text files are derived from that listing.
``listeners.json``, attributes, target health and tags are lazy files. The
``target-groups/`` links of a load balancer come from the cached target
group listing, so they cost at most one extra call per region.
"""

from __future__ import annotations

from collections.abc import Callable
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
from awsmount.providers.common import resource_from_arn
from awsmount.providers.ec2 import field_text, pluck
from awsmount.vfs.render import Content

if TYPE_CHECKING:
    from awsmount.session.context import Scope

__all__ = [
    "LISTENERS",
    "LOAD_BALANCERS",
    "RULES",
    "SERVICE",
    "TARGET_GROUPS",
    "lb_key_from_arn",
    "tg_key_from_arn",
]

ArnFn = Callable[[dict[str, Any], "Scope"], "str | None"]


def lb_key_from_arn(arn: str) -> str:
    """Load balancer name from ``...:loadbalancer/<type>/<name>/<id>``."""
    parts = resource_from_arn(arn).split("/")
    if len(parts) >= 4 and parts[0] == "loadbalancer":
        return parts[2]
    if len(parts) >= 2:
        return parts[1]
    return arn


def tg_key_from_arn(arn: str) -> str:
    """Target group name from ``...:targetgroup/<name>/<id>``."""
    parts = resource_from_arn(arn).split("/")
    if len(parts) >= 2:
        return parts[1]
    return arn


def _arn_field(field: str) -> ArnFn:
    """ARN function returning the item field ``field``."""

    def build(item: dict[str, Any], scope: Scope) -> str | None:
        value = item.get(field)
        return str(value) if value else None

    return build


def _strings(value: Any) -> list[str]:
    """Non-empty strings of a list field."""
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, str) and v]


def _tags_from(field: str) -> Callable[[ResourceCtx], dict[str, str]]:
    """Lazy tag fetcher using DescribeTags on the ARN in ``field``."""

    def fetch(rc: ResourceCtx) -> dict[str, str]:
        arn = rc.item.get(field)
        if not arn:
            return {}
        resp = rc.call("describe_tags", ResourceArns=[str(arn)])
        out: dict[str, str] = {}
        for desc in resp.get("TagDescriptions", []) or []:
            if not isinstance(desc, dict):
                continue
            for tag in desc.get("Tags", []) or []:
                if isinstance(tag, dict) and "Key" in tag:
                    out[str(tag["Key"])] = str(tag.get("Value", ""))
        return out

    return fetch


# -- rules (nested under a listener) --


def _id_of(arn: Any) -> str:
    """Last ``/`` segment of an ARN (the id of a listener or rule)."""
    return str(arn).rsplit("/", 1)[-1]


def _list_rules(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated DescribeRules call for the parent listener."""
    parent = lc.parent
    if parent is None:
        return []
    arn = parent.item.get("ListenerArn")
    if not arn:
        return []
    return [r for r in lc.paginate("describe_rules", "Rules",
                                   ListenerArn=str(arn))
            if isinstance(r, dict)]


def _rule_name(item: dict[str, Any]) -> str:
    """Priority of the rule (``default`` for the default rule)."""
    if item.get("IsDefault"):
        return "default"
    return str(item.get("Priority") or _id_of(item.get("RuleArn")))


def _action_target_groups(actions: Any) -> list[str]:
    """Target group ARNs of forward actions (plain or weighted)."""
    out: list[str] = []
    if not isinstance(actions, list):
        return out
    for action in actions:
        if not isinstance(action, dict):
            continue
        direct = action.get("TargetGroupArn")
        if isinstance(direct, str) and direct and direct not in out:
            out.append(direct)
        forward = action.get("ForwardConfig")
        groups = forward.get("TargetGroups") if isinstance(
            forward, dict) else None
        for group in groups or []:
            arn = group.get("TargetGroupArn") if isinstance(
                group, dict) else None
            if isinstance(arn, str) and arn and arn not in out:
                out.append(arn)
    return out


RULES = CollectionSpec(
    name="rules",
    client="elbv2",
    lister=_list_rules,
    key=lambda i: _id_of(i["RuleArn"]),
    ops=frozenset({"DescribeRules"}),
    display=_rule_name,
    arn=_arn_field("RuleArn"),
    redact="elbv2-rule",
    files=(
        FileSpec("priority", field_text("Priority")),
    ),
    links=(
        LinkSpec("target-groups", refs.TARGET_GROUPS,
                 lambda rc: _action_target_groups(rc.item.get("Actions")),
                 by="arn", many=True),
    ),
    lookup={"arn": lambda i: str(i.get("RuleArn", ""))},
    key_from_arn=_id_of,
)


# -- listeners (nested under a load balancer) --


def _list_listeners(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated DescribeListeners call for the parent load balancer."""
    parent = lc.parent
    if parent is None:
        return []
    arn = parent.item.get("LoadBalancerArn")
    if not arn:
        return []
    return [i for i in lc.paginate("describe_listeners", "Listeners",
                                   LoadBalancerArn=str(arn))
            if isinstance(i, dict)]


def _listener_name(item: dict[str, Any]) -> str:
    """``<PROTOCOL>-<port>``, for example ``HTTPS-443``."""
    return f"{item.get('Protocol', 'listener')}-{item.get('Port', '')}"


LISTENERS = CollectionSpec(
    name="listeners",
    client="elbv2",
    lister=_list_listeners,
    key=lambda i: _id_of(i["ListenerArn"]),
    ops=frozenset({"DescribeListeners"}),
    display=_listener_name,
    arn=_arn_field("ListenerArn"),
    redact="elbv2-listener",
    files=(
        FileSpec("protocol", field_text("Protocol")),
        FileSpec("port", field_text("Port")),
    ),
    links=(
        LinkSpec("load-balancer", refs.LOAD_BALANCERS,
                 lambda rc: rc.item.get("LoadBalancerArn"), by="arn"),
        LinkSpec("target-groups", refs.TARGET_GROUPS,
                 lambda rc: _action_target_groups(
                     rc.item.get("DefaultActions")),
                 by="arn", many=True),
        LinkSpec("certificates", refs.ACM_CERTIFICATES,
                 lambda rc: pluck(rc.item.get("Certificates"),
                                  "CertificateArn"),
                 by="arn", many=True),
    ),
    children=(RULES,),
    lookup={"arn": lambda i: str(i.get("ListenerArn", ""))},
    key_from_arn=_id_of,
)


# -- load balancers --


def _list_load_balancers(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated DescribeLoadBalancers call for the region."""
    return [i for i in lc.paginate("describe_load_balancers",
                                   "LoadBalancers")
            if isinstance(i, dict)]


def _listeners(rc: ResourceCtx) -> Content:
    """listeners.json (lazy, paginated DescribeListeners)."""
    arn = rc.item.get("LoadBalancerArn")
    if not arn:
        return []
    return rc.paginate("describe_listeners", "Listeners",
                       LoadBalancerArn=str(arn))


def _lb_attributes(rc: ResourceCtx) -> Content:
    """attributes.json (lazy DescribeLoadBalancerAttributes)."""
    arn = rc.item.get("LoadBalancerArn")
    if not arn:
        return []
    resp = rc.call("describe_load_balancer_attributes",
                   LoadBalancerArn=str(arn))
    return list(resp.get("Attributes", []) or [])


def _lb_target_groups(rc: ResourceCtx) -> list[str]:
    """Target groups attached to this load balancer (cached listing)."""
    arn = rc.item.get("LoadBalancerArn")
    if not arn:
        return []
    groups = rc.paginate("describe_target_groups", "TargetGroups")
    return sorted(str(g["TargetGroupName"]) for g in groups
                  if isinstance(g, dict) and g.get("TargetGroupName")
                  and arn in (g.get("LoadBalancerArns") or []))


LOAD_BALANCERS = CollectionSpec(
    name="load-balancers",
    client="elbv2",
    lister=_list_load_balancers,
    key=lambda i: str(i["LoadBalancerName"]),
    ops=frozenset({"DescribeLoadBalancers", "DescribeListeners",
                   "DescribeLoadBalancerAttributes", "DescribeTags",
                   "DescribeTargetGroups"}),
    arn=_arn_field("LoadBalancerArn"),
    tags=TagSpec(fetch=_tags_from("LoadBalancerArn")),
    files=(
        FileSpec("dns-name", field_text("DNSName")),
        FileSpec("type", field_text("Type")),
        FileSpec("scheme", field_text("Scheme")),
        FileSpec("listeners.json", _listeners, lazy=True,
                 redact="elbv2-listeners"),
        FileSpec("attributes.json", _lb_attributes, lazy=True),
    ),
    links=(
        LinkSpec("vpc", refs.VPCS, lambda rc: rc.item.get("VpcId")),
        LinkSpec("subnets", refs.SUBNETS,
                 lambda rc: pluck(rc.item.get("AvailabilityZones"),
                                  "SubnetId"),
                 many=True),
        LinkSpec("security-groups", refs.SECURITY_GROUPS,
                 lambda rc: _strings(rc.item.get("SecurityGroups")),
                 many=True),
        LinkSpec("target-groups", refs.TARGET_GROUPS, _lb_target_groups,
                 many=True),
    ),
    children=(LISTENERS,),
    lookup={"arn": lambda i: str(i.get("LoadBalancerArn", "")),
            "name": lambda i: str(i.get("LoadBalancerName", ""))},
    key_from_arn=lb_key_from_arn,
)


# -- target groups --


def _list_target_groups(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated DescribeTargetGroups call for the region."""
    return [i for i in lc.paginate("describe_target_groups",
                                   "TargetGroups")
            if isinstance(i, dict)]


def _health(rc: ResourceCtx) -> Content:
    """health.json (lazy DescribeTargetHealth)."""
    arn = rc.item.get("TargetGroupArn")
    if not arn:
        return []
    resp = rc.call("describe_target_health", TargetGroupArn=str(arn))
    return list(resp.get("TargetHealthDescriptions", []) or [])


def _tg_attributes(rc: ResourceCtx) -> Content:
    """attributes.json (lazy DescribeTargetGroupAttributes)."""
    arn = rc.item.get("TargetGroupArn")
    if not arn:
        return []
    resp = rc.call("describe_target_group_attributes",
                   TargetGroupArn=str(arn))
    return list(resp.get("Attributes", []) or [])


TARGET_GROUPS = CollectionSpec(
    name="target-groups",
    client="elbv2",
    lister=_list_target_groups,
    key=lambda i: str(i["TargetGroupName"]),
    ops=frozenset({"DescribeTargetGroups", "DescribeTargetHealth",
                   "DescribeTargetGroupAttributes", "DescribeTags"}),
    arn=_arn_field("TargetGroupArn"),
    tags=TagSpec(fetch=_tags_from("TargetGroupArn")),
    files=(
        FileSpec("protocol", field_text("Protocol")),
        FileSpec("port", field_text("Port")),
        FileSpec("target-type", field_text("TargetType")),
        FileSpec("health.json", _health, lazy=True),
        FileSpec("attributes.json", _tg_attributes, lazy=True),
    ),
    links=(
        LinkSpec("vpc", refs.VPCS, lambda rc: rc.item.get("VpcId")),
        LinkSpec("load-balancers", refs.LOAD_BALANCERS,
                 lambda rc: _strings(rc.item.get("LoadBalancerArns")),
                 by="arn", many=True),
    ),
    lookup={"arn": lambda i: str(i.get("TargetGroupArn", "")),
            "name": lambda i: str(i.get("TargetGroupName", ""))},
    key_from_arn=tg_key_from_arn,
)


SERVICE = ServiceSpec(
    dirname="elbv2",
    scope="region",
    collections=(
        LOAD_BALANCERS,
        TARGET_GROUPS,
    ),
)
