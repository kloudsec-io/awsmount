"""Amazon ECS provider (docs/coverage.md).

Collections: clusters (with nested ``services``) and task-definitions.
Clusters and services are listed with a list call followed by batched
describe calls (100 clusters / 10 services per call), so their
``describe.json`` is derived from the listing. Task definitions are
listed by ARN only; their ``describe.json`` is lazy (one
DescribeTaskDefinition when read) and redacted with ``ecs-taskdef``.
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
from awsmount.providers.common import (
    chunks,
    name_from_arn,
    resource_from_arn,
)
from awsmount.providers.ec2 import field_text, pluck

if TYPE_CHECKING:
    from awsmount.session.context import Scope

__all__ = [
    "CLUSTERS",
    "SERVICE",
    "SERVICES",
    "TASK_DEFINITIONS",
    "taskdef_key",
]

ArnFn = Callable[[dict[str, Any], "Scope"], "str | None"]

CLUSTER_BATCH = 100
SERVICE_BATCH = 10
CLUSTER_INCLUDE = ["TAGS", "SETTINGS", "STATISTICS"]
TASKDEF_PREFIX = "task-definition/"

_TAGS = TagSpec(inline="tags", style="list")


def taskdef_key(value: str) -> str:
    """``family:revision`` from a task definition ARN (or the value)."""
    resource = resource_from_arn(value)
    if resource.startswith(TASKDEF_PREFIX):
        return resource[len(TASKDEF_PREFIX):]
    return resource


def _strings(value: Any) -> list[str]:
    """Non-empty strings of a list field."""
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, str) and v]


def _arn_field(field: str) -> ArnFn:
    """ARN function returning the item field ``field``."""

    def build(item: dict[str, Any], scope: Scope) -> str | None:
        value = item.get(field)
        return str(value) if value else None

    return build


# -- clusters --


def _list_clusters(lc: ListCtx) -> list[dict[str, Any]]:
    """ListClusters, then DescribeClusters in batches of 100."""
    arns = sorted(a for a in lc.paginate("list_clusters", "clusterArns")
                  if isinstance(a, str) and a)
    out: list[dict[str, Any]] = []
    for batch in chunks(arns, CLUSTER_BATCH):
        resp = lc.call("describe_clusters", clusters=batch,
                       include=CLUSTER_INCLUDE)
        out.extend(c for c in resp.get("clusters", []) or []
                   if isinstance(c, dict))
    return out


# -- services (nested under a cluster) --


def _list_services(lc: ListCtx) -> list[dict[str, Any]]:
    """ListServices for the parent cluster, then DescribeServices (10)."""
    parent = lc.parent
    if parent is None:
        return []
    cluster = str(parent.item.get("clusterArn") or parent.key)
    arns = sorted(a for a in lc.paginate("list_services", "serviceArns",
                                         cluster=cluster)
                  if isinstance(a, str) and a)
    out: list[dict[str, Any]] = []
    for batch in chunks(arns, SERVICE_BATCH):
        resp = lc.call("describe_services", cluster=cluster,
                       services=batch, include=["TAGS"])
        out.extend(s for s in resp.get("services", []) or []
                   if isinstance(s, dict))
    return out


def _awsvpc(field: str) -> Callable[[ResourceCtx], list[str]]:
    """Values of ``networkConfiguration.awsvpcConfiguration.<field>``."""

    def values(rc: ResourceCtx) -> list[str]:
        network = rc.item.get("networkConfiguration")
        if not isinstance(network, dict):
            return []
        config = network.get("awsvpcConfiguration")
        if not isinstance(config, dict):
            return []
        return _strings(config.get(field))

    return values


SERVICES = CollectionSpec(
    name="services",
    client="ecs",
    lister=_list_services,
    key=lambda i: str(i["serviceName"]),
    ops=frozenset({"ListServices", "DescribeServices"}),
    arn=_arn_field("serviceArn"),
    tags=_TAGS,
    files=(
        FileSpec("status", field_text("status")),
        FileSpec("desired-count", field_text("desiredCount")),
    ),
    links=(
        LinkSpec("cluster", refs.ECS_CLUSTERS,
                 lambda rc: rc.item.get("clusterArn"), by="arn"),
        LinkSpec("task-definition", refs.ECS_TASK_DEFINITIONS,
                 lambda rc: rc.item.get("taskDefinition"), by="arn"),
        LinkSpec("target-groups", refs.TARGET_GROUPS,
                 lambda rc: pluck(rc.item.get("loadBalancers"),
                                  "targetGroupArn"),
                 by="arn", many=True),
        LinkSpec("subnets", refs.SUBNETS, _awsvpc("subnets"), many=True),
        LinkSpec("security-groups", refs.SECURITY_GROUPS,
                 _awsvpc("securityGroups"), many=True),
        LinkSpec("role", refs.IAM_ROLES,
                 lambda rc: rc.item.get("roleArn"), by="arn"),
    ),
    lookup={"arn": lambda i: str(i.get("serviceArn", "")),
            "name": lambda i: str(i.get("serviceName", ""))},
    key_from_arn=name_from_arn,
)


CLUSTERS = CollectionSpec(
    name="clusters",
    client="ecs",
    lister=_list_clusters,
    key=lambda i: str(i["clusterName"]),
    ops=frozenset({"ListClusters", "DescribeClusters"}),
    arn=_arn_field("clusterArn"),
    tags=_TAGS,
    files=(
        FileSpec("status", field_text("status")),
    ),
    children=(SERVICES,),
    lookup={"arn": lambda i: str(i.get("clusterArn", "")),
            "name": lambda i: str(i.get("clusterName", ""))},
    key_from_arn=name_from_arn,
)


# -- task definitions --


def _list_task_definitions(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated ListTaskDefinitions (status ACTIVE), ARNs only."""
    arns = lc.paginate("list_task_definitions", "taskDefinitionArns",
                       status="ACTIVE")
    return [{"taskDefinitionArn": a} for a in arns
            if isinstance(a, str) and a]


def _describe_taskdef(rc: ResourceCtx) -> dict[str, Any]:
    """describe.json (lazy DescribeTaskDefinition with tags)."""
    arn = str(rc.item.get("taskDefinitionArn") or rc.key)
    return rc.call("describe_task_definition", taskDefinition=arn,
                   include=["TAGS"])


def _taskdef(rc: ResourceCtx) -> dict[str, Any]:
    """The ``taskDefinition`` part of the describe response."""
    data = rc.detail().get("taskDefinition")
    return data if isinstance(data, dict) else {}


def _taskdef_tags(rc: ResourceCtx) -> dict[str, str]:
    """Tags from the describe response (``[{key, value}]``)."""
    out: dict[str, str] = {}
    for tag in rc.detail().get("tags", []) or []:
        if isinstance(tag, dict) and "key" in tag:
            out[str(tag["key"])] = str(tag.get("value", ""))
    return out


TASK_DEFINITIONS = CollectionSpec(
    name="task-definitions",
    client="ecs",
    lister=_list_task_definitions,
    key=lambda i: taskdef_key(str(i["taskDefinitionArn"])),
    ops=frozenset({"ListTaskDefinitions", "DescribeTaskDefinition"}),
    arn=_arn_field("taskDefinitionArn"),
    describe=_describe_taskdef,
    redact="ecs-taskdef",
    tags=TagSpec(fetch=_taskdef_tags),
    links=(
        LinkSpec("role", refs.IAM_ROLES,
                 lambda rc: _taskdef(rc).get("taskRoleArn"), by="arn"),
        LinkSpec("execution-role", refs.IAM_ROLES,
                 lambda rc: _taskdef(rc).get("executionRoleArn"),
                 by="arn"),
    ),
    lookup={"arn": lambda i: str(i.get("taskDefinitionArn", ""))},
    key_from_arn=taskdef_key,
)


SERVICE = ServiceSpec(
    dirname="ecs",
    scope="region",
    collections=(
        CLUSTERS,
        TASK_DEFINITIONS,
    ),
)
