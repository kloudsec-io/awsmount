"""Amazon EKS provider: clusters, with nested node groups and add-ons.

ListClusters returns names only, so the listing stays one call and
``describe.json`` is lazy (one DescribeCluster when read). Tags and the
links are derived from that lazy describe. ``describe.json`` uses the
``eks`` rule set: the EKS Connector ``activationCode`` (the agent
registration secret) is redacted unless ``--reveal``.

``nodegroups/`` and ``addons/`` are nested collections. ListNodegroups
and ListAddons return names only (and there is no batch describe), so
each listing stays one call per cluster and the nodegroup or add-on
``describe.json`` is lazy, like the cluster's. Their ARNs contain a UUID
that only the describe response has, so they get no ``arn`` file: the
ARN is in ``describe.json``. The add-on ``configurationValues`` blob is
free-form user configuration, so the ``eks-addon`` rule set hides it.
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
from awsmount.providers.common import make_arn, name_from_arn
from awsmount.providers.ec2 import pluck
from awsmount.vfs.render import Content

if TYPE_CHECKING:
    from awsmount.session.context import Scope

__all__ = ["ADDONS", "CLUSTERS", "NODEGROUPS", "SERVICE"]


def _strings(value: Any) -> list[str]:
    """Non-empty strings of a list field."""
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, str) and v]


def _list_clusters(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated ListClusters call (names only)."""
    return [{"name": n} for n in lc.paginate("list_clusters", "clusters")
            if isinstance(n, str) and n]


def _describe(rc: ResourceCtx) -> dict[str, Any]:
    """describe.json (lazy DescribeCluster)."""
    return rc.call("describe_cluster", name=rc.key)


def _cluster(rc: ResourceCtx) -> dict[str, Any]:
    """The ``cluster`` part of the describe response."""
    data = rc.detail().get("cluster")
    return data if isinstance(data, dict) else {}


def _vpc_config(rc: ResourceCtx) -> dict[str, Any]:
    """resourcesVpcConfig of the cluster ({} when absent)."""
    config = _cluster(rc).get("resourcesVpcConfig")
    return config if isinstance(config, dict) else {}


def _security_groups(rc: ResourceCtx) -> list[str]:
    """Additional and cluster security groups."""
    config = _vpc_config(rc)
    groups = _strings(config.get("securityGroupIds"))
    extra = config.get("clusterSecurityGroupId")
    if isinstance(extra, str) and extra:
        groups.append(extra)
    return sorted(set(groups))


def _nodegroups(rc: ResourceCtx) -> Content:
    """nodegroups.json (lazy, paginated ListNodegroups)."""
    return rc.paginate("list_nodegroups", "nodegroups", clusterName=rc.key)


def _addons(rc: ResourceCtx) -> Content:
    """addons.json (lazy, paginated ListAddons)."""
    return rc.paginate("list_addons", "addons", clusterName=rc.key)


def _tags(rc: ResourceCtx) -> dict[str, str]:
    """Tags from the describe response (a map)."""
    tags = _cluster(rc).get("tags") or {}
    if not isinstance(tags, dict):
        return {}
    return {str(k): str(v) for k, v in tags.items()}


def _arn(item: dict[str, Any], scope: Scope) -> str | None:
    """Cluster ARN built from the name (no API call)."""
    name = item.get("name")
    if not name:
        return None
    return make_arn(scope, "eks", f"cluster/{name}")


# -- node groups (nested under a cluster) --


def _list_nodegroups(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated ListNodegroups for the parent cluster (names)."""
    parent = lc.parent
    if parent is None:
        return []
    cluster = parent.key
    names = lc.paginate("list_nodegroups", "nodegroups",
                        clusterName=cluster)
    return [{"name": n, "cluster": cluster} for n in sorted(names)
            if isinstance(n, str) and n]


def _describe_nodegroup(rc: ResourceCtx) -> dict[str, Any]:
    """describe.json (lazy DescribeNodegroup)."""
    return rc.call("describe_nodegroup",
                   clusterName=rc.item["cluster"], nodegroupName=rc.key)


def _nodegroup(rc: ResourceCtx) -> dict[str, Any]:
    """The ``nodegroup`` part of the describe response."""
    data = rc.detail().get("nodegroup")
    return data if isinstance(data, dict) else {}


def _nodegroup_tags(rc: ResourceCtx) -> dict[str, str]:
    """Tags from the describe response (a map)."""
    tags = _nodegroup(rc).get("tags") or {}
    if not isinstance(tags, dict):
        return {}
    return {str(k): str(v) for k, v in tags.items()}


def _launch_template(rc: ResourceCtx) -> dict[str, Any]:
    """The custom launch template of the node group ({} when none)."""
    data = _nodegroup(rc).get("launchTemplate")
    return data if isinstance(data, dict) else {}


def _resources(rc: ResourceCtx) -> dict[str, Any]:
    """The ``resources`` of the node group (its Auto Scaling groups)."""
    data = _nodegroup(rc).get("resources")
    return data if isinstance(data, dict) else {}


NODEGROUPS = CollectionSpec(
    name="nodegroups",
    client="eks",
    lister=_list_nodegroups,
    key=lambda i: str(i["name"]),
    ops=frozenset({"ListNodegroups", "DescribeNodegroup"}),
    describe=_describe_nodegroup,
    tags=TagSpec(fetch=_nodegroup_tags),
    links=(
        LinkSpec("cluster", refs.EKS_CLUSTERS,
                 lambda rc: rc.item.get("cluster")),
        LinkSpec("role", refs.IAM_ROLES,
                 lambda rc: _nodegroup(rc).get("nodeRole"), by="arn"),
        LinkSpec("subnets", refs.SUBNETS,
                 lambda rc: _strings(_nodegroup(rc).get("subnets")),
                 many=True),
        LinkSpec("launch-template", refs.LAUNCH_TEMPLATES,
                 lambda rc: _launch_template(rc).get("id")),
        LinkSpec("autoscaling-groups", refs.AUTOSCALING_GROUPS,
                 lambda rc: pluck(_resources(rc).get("autoScalingGroups"),
                                  "name"),
                 many=True),
    ),
    lookup={"name": lambda i: str(i.get("name", ""))},
)


# -- add-ons (nested under a cluster) --


def _list_addons(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated ListAddons for the parent cluster (names)."""
    parent = lc.parent
    if parent is None:
        return []
    cluster = parent.key
    names = lc.paginate("list_addons", "addons", clusterName=cluster)
    return [{"name": n, "cluster": cluster} for n in sorted(names)
            if isinstance(n, str) and n]


def _describe_addon(rc: ResourceCtx) -> dict[str, Any]:
    """describe.json (lazy DescribeAddon)."""
    return rc.call("describe_addon",
                   clusterName=rc.item["cluster"], addonName=rc.key)


def _addon(rc: ResourceCtx) -> dict[str, Any]:
    """The ``addon`` part of the describe response."""
    data = rc.detail().get("addon")
    return data if isinstance(data, dict) else {}


def _addon_tags(rc: ResourceCtx) -> dict[str, str]:
    """Tags from the describe response (a map)."""
    tags = _addon(rc).get("tags") or {}
    if not isinstance(tags, dict):
        return {}
    return {str(k): str(v) for k, v in tags.items()}


ADDONS = CollectionSpec(
    name="addons",
    client="eks",
    lister=_list_addons,
    key=lambda i: str(i["name"]),
    ops=frozenset({"ListAddons", "DescribeAddon"}),
    describe=_describe_addon,
    redact="eks-addon",
    tags=TagSpec(fetch=_addon_tags),
    links=(
        LinkSpec("cluster", refs.EKS_CLUSTERS,
                 lambda rc: rc.item.get("cluster")),
        LinkSpec("role", refs.IAM_ROLES,
                 lambda rc: _addon(rc).get("serviceAccountRoleArn"),
                 by="arn"),
    ),
    lookup={"name": lambda i: str(i.get("name", ""))},
)


CLUSTERS = CollectionSpec(
    name="clusters",
    client="eks",
    lister=_list_clusters,
    key=lambda i: str(i["name"]),
    ops=frozenset({"ListClusters", "DescribeCluster", "ListNodegroups",
                   "ListAddons"}),
    arn=_arn,
    describe=_describe,
    redact="eks",
    tags=TagSpec(fetch=_tags),
    files=(
        FileSpec("nodegroups.json", _nodegroups, lazy=True),
        FileSpec("addons.json", _addons, lazy=True),
    ),
    links=(
        LinkSpec("role", refs.IAM_ROLES,
                 lambda rc: _cluster(rc).get("roleArn"), by="arn"),
        LinkSpec("vpc", refs.VPCS,
                 lambda rc: _vpc_config(rc).get("vpcId")),
        LinkSpec("subnets", refs.SUBNETS,
                 lambda rc: _strings(_vpc_config(rc).get("subnetIds")),
                 many=True),
        LinkSpec("security-groups", refs.SECURITY_GROUPS,
                 _security_groups, many=True),
    ),
    children=(NODEGROUPS, ADDONS),
    lookup={"name": lambda i: str(i.get("name", ""))},
    key_from_arn=name_from_arn,
)


SERVICE = ServiceSpec(
    dirname="eks",
    scope="region",
    collections=(CLUSTERS,),
)
