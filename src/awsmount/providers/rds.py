"""Amazon RDS provider: DB instances and clusters (docs/coverage.md).

Both collections are listed with one paginated describe call; every
file is derived from that listing (no lazy files). Tags are inline
(``TagList``). ``describe.json`` uses the ``rds`` redaction rule set.
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
from awsmount.providers.common import kms_ref, make_arn, name_from_arn
from awsmount.providers.ec2 import field_text, pluck, text
from awsmount.vfs.render import Content

if TYPE_CHECKING:
    from awsmount.session.context import Scope

__all__ = ["CLUSTERS", "INSTANCES", "MEMBERS", "SERVICE"]

ArnFn = Callable[[dict[str, Any], "Scope"], "str | None"]

_TAGS = TagSpec(inline="TagList", style="list")


def _rds_arn(arn_field: str, id_field: str, kind: str) -> ArnFn:
    """ARN from ``arn_field``, or built as ``<kind>:<id>``."""

    def build(item: dict[str, Any], scope: Scope) -> str | None:
        arn = item.get(arn_field)
        if arn:
            return str(arn)
        ident = item.get(id_field)
        if not ident:
            return None
        return make_arn(scope, "rds", f"{kind}:{ident}")

    return build


def _security_groups(rc: ResourceCtx) -> list[str]:
    """VPC security group ids of an instance or cluster."""
    return pluck(rc.item.get("VpcSecurityGroups"), "VpcSecurityGroupId")


# -- instances --


def _list_instances(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated DescribeDBInstances call for the region."""
    return [i for i in lc.paginate("describe_db_instances", "DBInstances")
            if isinstance(i, dict)]


def _instance_endpoint(rc: ResourceCtx) -> Content:
    """endpoint: ``address:port`` (or just the address)."""
    endpoint = rc.item.get("Endpoint")
    if not isinstance(endpoint, dict) or not endpoint.get("Address"):
        return ""
    port = endpoint.get("Port")
    address = text(endpoint.get("Address"))
    return f"{address}:{port}" if port else address


def _subnet_group(rc: ResourceCtx) -> dict[str, Any]:
    """DBSubnetGroup of an instance ({} when absent)."""
    group = rc.item.get("DBSubnetGroup")
    return group if isinstance(group, dict) else {}


INSTANCES = CollectionSpec(
    name="instances",
    client="rds",
    lister=_list_instances,
    key=lambda i: str(i["DBInstanceIdentifier"]),
    ops=frozenset({"DescribeDBInstances"}),
    arn=_rds_arn("DBInstanceArn", "DBInstanceIdentifier", "db"),
    redact="rds",
    tags=_TAGS,
    files=(
        FileSpec("engine", field_text("Engine")),
        FileSpec("status", field_text("DBInstanceStatus")),
        FileSpec("endpoint", _instance_endpoint),
    ),
    links=(
        LinkSpec("cluster", refs.RDS_CLUSTERS,
                 lambda rc: rc.item.get("DBClusterIdentifier")),
        LinkSpec("vpc", refs.VPCS,
                 lambda rc: _subnet_group(rc).get("VpcId")),
        LinkSpec("subnets", refs.SUBNETS,
                 lambda rc: pluck(_subnet_group(rc).get("Subnets"),
                                  "SubnetIdentifier"),
                 many=True),
        LinkSpec("security-groups", refs.SECURITY_GROUPS,
                 _security_groups, many=True),
        LinkSpec("kms-key", refs.KMS_KEYS,
                 lambda rc: kms_ref(rc.item.get("KmsKeyId"))),
    ),
    lookup={"arn": lambda i: str(i.get("DBInstanceArn", ""))},
    key_from_arn=name_from_arn,
)


# -- clusters --


def _list_clusters(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated DescribeDBClusters call for the region."""
    return [i for i in lc.paginate("describe_db_clusters", "DBClusters")
            if isinstance(i, dict)]


# -- cluster members (nested under a cluster) --


def _list_members(lc: ListCtx) -> list[dict[str, Any]]:
    """The members of the parent cluster, from its listing (no call)."""
    parent = lc.parent
    if parent is None:
        return []
    members = parent.item.get("DBClusterMembers")
    if not isinstance(members, list):
        return []
    return [m for m in members
            if isinstance(m, dict) and m.get("DBInstanceIdentifier")]


def _member_role(rc: ResourceCtx) -> Content:
    """``writer`` or ``reader``."""
    return "writer" if rc.item.get("IsClusterWriter") else "reader"


MEMBERS = CollectionSpec(
    name="members",
    client="rds",
    lister=_list_members,
    key=lambda i: str(i["DBInstanceIdentifier"]),
    ops=frozenset({"DescribeDBClusters"}),
    files=(
        FileSpec("role", _member_role),
        FileSpec("promotion-tier", field_text("PromotionTier")),
    ),
    links=(
        LinkSpec("instance", refs.RDS_INSTANCES,
                 lambda rc: rc.item.get("DBInstanceIdentifier")),
        LinkSpec("cluster", refs.RDS_CLUSTERS,
                 lambda rc: rc.parent.key if rc.parent else None),
    ),
    lookup={"name": lambda i: str(i.get("DBInstanceIdentifier", ""))},
)


CLUSTERS = CollectionSpec(
    name="clusters",
    client="rds",
    lister=_list_clusters,
    key=lambda i: str(i["DBClusterIdentifier"]),
    ops=frozenset({"DescribeDBClusters"}),
    arn=_rds_arn("DBClusterArn", "DBClusterIdentifier", "cluster"),
    redact="rds",
    tags=_TAGS,
    files=(
        FileSpec("engine", field_text("Engine")),
        FileSpec("status", field_text("Status")),
        FileSpec("endpoint", field_text("Endpoint")),
    ),
    links=(
        LinkSpec("instances", refs.RDS_INSTANCES,
                 lambda rc: pluck(rc.item.get("DBClusterMembers"),
                                  "DBInstanceIdentifier"),
                 many=True),
        LinkSpec("security-groups", refs.SECURITY_GROUPS,
                 _security_groups, many=True),
        LinkSpec("kms-key", refs.KMS_KEYS,
                 lambda rc: kms_ref(rc.item.get("KmsKeyId"))),
    ),
    children=(MEMBERS,),
    lookup={"arn": lambda i: str(i.get("DBClusterArn", ""))},
    key_from_arn=name_from_arn,
)


SERVICE = ServiceSpec(
    dirname="rds",
    scope="region",
    collections=(
        INSTANCES,
        CLUSTERS,
    ),
)
