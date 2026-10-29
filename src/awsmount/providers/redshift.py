"""Amazon Redshift provider: provisioned clusters.

One paginated DescribeClusters call lists the clusters with all their
fields, so every file and link is derived from the listing (no lazy
files). Tags are inline. Redshift Serverless, snapshots, databases and
queries are not covered. The master password is never returned by AWS; a
pending password change is hidden by the generic heuristic.
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
from awsmount.providers.common import kms_ref, make_arn
from awsmount.providers.ec2 import field_text, pluck
from awsmount.vfs.render import Content

if TYPE_CHECKING:
    from awsmount.session.context import Scope

__all__ = ["CLUSTERS", "SERVICE"]


def _list_clusters(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated DescribeClusters call."""
    return [c for c in lc.paginate("describe_clusters", "Clusters")
            if isinstance(c, dict)]


def _arn(item: dict[str, Any], scope: Scope) -> str | None:
    ident = item.get("ClusterIdentifier")
    if not ident:
        return None
    return make_arn(scope, "redshift", f"cluster:{ident}")


def _endpoint(rc: ResourceCtx) -> Content:
    """``address:port`` of the cluster endpoint (empty while creating)."""
    endpoint = rc.item.get("Endpoint")
    if not isinstance(endpoint, dict) or not endpoint.get("Address"):
        return ""
    return f"{endpoint['Address']}:{endpoint.get('Port', '')}"


CLUSTERS = CollectionSpec(
    name="clusters",
    client="redshift",
    lister=_list_clusters,
    key=lambda i: str(i["ClusterIdentifier"]),
    ops=frozenset({"DescribeClusters"}),
    arn=_arn,
    tags=TagSpec(inline="Tags", style="list"),
    files=(
        FileSpec("status", field_text("ClusterStatus")),
        FileSpec("node-type", field_text("NodeType")),
        FileSpec("endpoint", _endpoint),
    ),
    links=(
        LinkSpec("vpc", refs.VPCS, lambda rc: rc.item.get("VpcId")),
        LinkSpec("security-groups", refs.SECURITY_GROUPS,
                 lambda rc: pluck(rc.item.get("VpcSecurityGroups"),
                                  "VpcSecurityGroupId"),
                 many=True),
        LinkSpec("roles", refs.IAM_ROLES,
                 lambda rc: pluck(rc.item.get("IamRoles"), "IamRoleArn"),
                 by="arn", many=True),
        LinkSpec("kms-key", refs.KMS_KEYS,
                 lambda rc: kms_ref(rc.item.get("KmsKeyId"))),
    ),
    lookup={"name": lambda i: str(i.get("ClusterIdentifier", ""))},
)


SERVICE = ServiceSpec(
    dirname="redshift",
    scope="region",
    collections=(CLUSTERS,),
)
