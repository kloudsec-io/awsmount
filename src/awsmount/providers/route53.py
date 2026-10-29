"""Amazon Route 53 provider (global, docs/coverage.md).

Collection: hosted-zones. One paginated ``ListHostedZones`` call lists
the account. The directory name is the zone name without its trailing
dot, and the key is the zone id without ``/hostedzone/``.
``describe.json``, ``private`` and ``record-count`` are derived from
the listing. ``records.json`` (ListResourceRecordSets), the tags and
the ``vpcs/`` links of private zones (GetHostedZone) are lazy. VPC
links point into the regional ``vpc/vpcs`` collection and are omitted
when that region is not mounted.
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
from awsmount.providers.ec2 import text
from awsmount.vfs.render import Content

if TYPE_CHECKING:
    from awsmount.session.context import Scope

__all__ = ["HOSTED_ZONES", "SERVICE", "zone_id"]

ZONE_PREFIX = "/hostedzone/"


def zone_id(value: str) -> str:
    """Hosted zone id without the ``/hostedzone/`` prefix."""
    if value.startswith(ZONE_PREFIX):
        return value[len(ZONE_PREFIX):]
    return value


def _list_zones(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated ListHostedZones call for the account."""
    return [z for z in lc.paginate("list_hosted_zones", "HostedZones")
            if isinstance(z, dict) and z.get("Id")]


def _zone_key(item: dict[str, Any]) -> str:
    """Zone id without the prefix."""
    return zone_id(str(item["Id"]))


def _display(item: dict[str, Any]) -> str:
    """Zone name without the trailing dot (the id when empty)."""
    name = str(item.get("Name") or "")
    if len(name) > 1 and name.endswith("."):
        name = name[:-1]
    return name or _zone_key(item)


def _is_private(item: dict[str, Any]) -> bool:
    """True for private hosted zones."""
    config = item.get("Config")
    return isinstance(config, dict) and bool(config.get("PrivateZone"))


def _zone_arn(item: dict[str, Any], scope: Scope) -> str | None:
    """``arn:<p>:route53:::hostedzone/<id>``."""
    if not item.get("Id"):
        return None
    return make_arn(scope, "route53", f"hostedzone/{_zone_key(item)}",
                    account="", regional=False)


def _private(rc: ResourceCtx) -> Content:
    """private: ``true`` or ``false``."""
    return "true" if _is_private(rc.item) else "false"


def _record_count(rc: ResourceCtx) -> Content:
    """record-count as listed."""
    return text(rc.item.get("ResourceRecordSetCount"))


def _records(rc: ResourceCtx) -> Content:
    """records.json (lazy, paginated ListResourceRecordSets)."""
    return rc.paginate("list_resource_record_sets", "ResourceRecordSets",
                       HostedZoneId=rc.key)


def _zone_vpcs(rc: ResourceCtx) -> list[str]:
    """ARNs of the VPCs associated with a private zone (GetHostedZone).

    ARNs carry the VPC region, so links go to the right region dir and
    are omitted when that region is not mounted.
    """
    if not _is_private(rc.item):
        return []
    resp = rc.call("get_hosted_zone", Id=rc.key)
    account = rc.scope.account.account_id or ""
    out: set[str] = set()
    for vpc in resp.get("VPCs", []) or []:
        if not isinstance(vpc, dict):
            continue
        vpc_id = vpc.get("VPCId")
        region = vpc.get("VPCRegion")
        if vpc_id and region:
            out.add(f"arn:{rc.scope.partition}:ec2:{region}:{account}"
                    f":vpc/{vpc_id}")
    return sorted(out)


def _tags(rc: ResourceCtx) -> dict[str, str]:
    """Tags from ListTagsForResource (ResourceType=hostedzone)."""
    resp = rc.call("list_tags_for_resource", ResourceType="hostedzone",
                   ResourceId=rc.key)
    tag_set = resp.get("ResourceTagSet") or {}
    return {str(t["Key"]): str(t.get("Value", ""))
            for t in tag_set.get("Tags", []) or []
            if isinstance(t, dict) and "Key" in t}


HOSTED_ZONES = CollectionSpec(
    name="hosted-zones",
    client="route53",
    lister=_list_zones,
    key=_zone_key,
    ops=frozenset({"ListHostedZones", "ListResourceRecordSets",
                   "GetHostedZone", "ListTagsForResource"}),
    display=_display,
    arn=_zone_arn,
    name_of=_display,
    tags=TagSpec(fetch=_tags),
    files=(
        FileSpec("private", _private),
        FileSpec("record-count", _record_count),
        FileSpec("records.json", _records, lazy=True),
    ),
    links=(
        LinkSpec("vpcs", refs.VPCS, _zone_vpcs, by="arn", many=True),
    ),
    lookup={"name": _display},
    key_from_arn=name_from_arn,
)


SERVICE = ServiceSpec(
    dirname="route53",
    scope="global",
    collections=(
        HOSTED_ZONES,
    ),
)
