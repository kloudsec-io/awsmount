"""EC2 provider (docs/coverage.md).

Collections: instances, volumes, snapshots (owned), key-pairs,
elastic-ips, network-interfaces and amis (owned). Every collection is
listed with one (paginated) describe call. ``describe.json`` and the
small text files are derived from that listing. Only ``user-data`` is
lazy, and it is whole-file redacted unless ``--reveal`` is given.
"""

from __future__ import annotations

import base64
import binascii
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
    drop_dead,
    kms_ref,
    make_arn,
    name_from_arn,
)
from awsmount.vfs.render import Content

if TYPE_CHECKING:
    from awsmount.session.context import Scope

__all__ = [
    "AMIS",
    "ELASTIC_IPS",
    "INSTANCES",
    "KEY_PAIRS",
    "LAUNCH_TEMPLATES",
    "NETWORK_INTERFACES",
    "SERVICE",
    "SNAPSHOTS",
    "VOLUMES",
    "ec2_arn",
    "field_text",
    "pluck",
    "text",
]

ArnFn = Callable[[dict[str, Any], "Scope"], "str | None"]

_TAGS = TagSpec(inline="Tags", style="list")


# -- shared helpers (also used by the VPC provider) --


def text(value: Any) -> str:
    """Render a scalar as text; None becomes the empty string."""
    return "" if value is None else str(value)


def field_text(*path: str) -> Callable[[ResourceCtx], Content]:
    """File renderer returning the nested item field ``path`` as text."""

    def render(rc: ResourceCtx) -> Content:
        cur: Any = rc.item
        for part in path:
            cur = cur.get(part) if isinstance(cur, dict) else None
        return text(cur)

    return render


def pluck(items: Any, *path: str) -> list[str]:
    """Collect non-empty string values at ``path`` in a list of dicts."""
    out: list[str] = []
    if not isinstance(items, list):
        return out
    for entry in items:
        cur: Any = entry
        for part in path:
            cur = cur.get(part) if isinstance(cur, dict) else None
        if isinstance(cur, str) and cur:
            out.append(cur)
    return out


def ec2_arn(kind: str, id_field: str, *,
            owner_field: str | None = "OwnerId",
            accountless: bool = False) -> ArnFn:
    """Build an ARN function ``arn:<p>:ec2:<region>:<acct>:<kind>/<id>``.

    The account comes from ``owner_field`` on the item when present,
    otherwise from the scope. ``accountless`` ARNs (images, snapshots)
    leave the account field empty, as AWS does.
    """

    def build(item: dict[str, Any], scope: Scope) -> str | None:
        ident = item.get(id_field)
        if not ident:
            return None
        if accountless:
            account = ""
        else:
            owner = item.get(owner_field) if owner_field else None
            account = str(owner or scope.account.account_id or "")
        return make_arn(scope, "ec2", f"{kind}/{ident}", account=account)

    return build


# -- instances --


def _list_instances(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated DescribeInstances, flattened to instances."""
    out: list[dict[str, Any]] = []
    for reservation in lc.paginate("describe_instances", "Reservations"):
        if isinstance(reservation, dict):
            out.extend(i for i in reservation.get("Instances", [])
                       if isinstance(i, dict))
    # Terminated instances linger in DescribeInstances for about an hour.
    return drop_dead(out, lambda i: (i.get("State") or {}).get("Name"),
                     frozenset({"terminated"}))


def _user_data(rc: ResourceCtx) -> Content:
    """Lazy user-data: DescribeInstanceAttribute, base64-decoded."""
    resp = rc.call("describe_instance_attribute", InstanceId=rc.key,
                   Attribute="userData")
    value = (resp.get("UserData") or {}).get("Value")
    if not value:
        return b""
    try:
        return base64.b64decode(value)
    except (binascii.Error, ValueError):
        return str(value)


INSTANCES = CollectionSpec(
    name="instances",
    client="ec2",
    lister=_list_instances,
    key=lambda i: i["InstanceId"],
    ops=frozenset({"DescribeInstances", "DescribeInstanceAttribute"}),
    arn=ec2_arn("instance", "InstanceId", owner_field=None),
    tags=_TAGS,
    files=(
        FileSpec("state", field_text("State", "Name")),
        FileSpec("instance-type", field_text("InstanceType")),
        FileSpec("private-ip", field_text("PrivateIpAddress")),
        FileSpec("user-data", _user_data, lazy=True, whole="user-data"),
    ),
    links=(
        LinkSpec("subnet", refs.SUBNETS,
                 lambda rc: rc.item.get("SubnetId")),
        LinkSpec("vpc", refs.VPCS, lambda rc: rc.item.get("VpcId")),
        LinkSpec("image", refs.AMIS, lambda rc: rc.item.get("ImageId")),
        LinkSpec("key-pair", refs.KEY_PAIRS,
                 lambda rc: rc.item.get("KeyName")),
        LinkSpec("security-groups", refs.SECURITY_GROUPS,
                 lambda rc: pluck(rc.item.get("SecurityGroups"),
                                  "GroupId"),
                 many=True),
        LinkSpec("volumes", refs.VOLUMES,
                 lambda rc: pluck(rc.item.get("BlockDeviceMappings"),
                                  "Ebs", "VolumeId"),
                 many=True),
        LinkSpec("network-interfaces", refs.NETWORK_INTERFACES,
                 lambda rc: pluck(rc.item.get("NetworkInterfaces"),
                                  "NetworkInterfaceId"),
                 many=True),
    ),
    key_from_arn=name_from_arn,
)


# -- volumes --


def _list_volumes(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated DescribeVolumes."""
    return lc.paginate("describe_volumes", "Volumes")


VOLUMES = CollectionSpec(
    name="volumes",
    client="ec2",
    lister=_list_volumes,
    key=lambda i: i["VolumeId"],
    ops=frozenset({"DescribeVolumes"}),
    arn=ec2_arn("volume", "VolumeId", owner_field=None),
    tags=_TAGS,
    files=(
        FileSpec("state", field_text("State")),
        FileSpec("size-gib", field_text("Size")),
    ),
    links=(
        LinkSpec("instances", refs.INSTANCES,
                 lambda rc: pluck(rc.item.get("Attachments"),
                                  "InstanceId"),
                 many=True),
        LinkSpec("snapshot", refs.SNAPSHOTS,
                 lambda rc: rc.item.get("SnapshotId")),
        LinkSpec("kms-key", refs.KMS_KEYS,
                 lambda rc: kms_ref(rc.item.get("KmsKeyId"))),
    ),
    key_from_arn=name_from_arn,
)


# -- snapshots --


def _list_snapshots(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated DescribeSnapshots restricted to owned snapshots."""
    return lc.paginate("describe_snapshots", "Snapshots",
                       OwnerIds=["self"])


SNAPSHOTS = CollectionSpec(
    name="snapshots",
    client="ec2",
    lister=_list_snapshots,
    key=lambda i: i["SnapshotId"],
    ops=frozenset({"DescribeSnapshots"}),
    # display == key: links to snapshots that are not owned (and thus
    # not listed) are omitted instead of dangling.
    display=lambda i: i["SnapshotId"],
    arn=ec2_arn("snapshot", "SnapshotId", accountless=True),
    tags=_TAGS,
    files=(
        FileSpec("state", field_text("State")),
    ),
    links=(
        LinkSpec("volume", refs.VOLUMES,
                 lambda rc: rc.item.get("VolumeId")),
        LinkSpec("kms-key", refs.KMS_KEYS,
                 lambda rc: kms_ref(rc.item.get("KmsKeyId"))),
    ),
    key_from_arn=name_from_arn,
)


# -- key pairs --


def _list_key_pairs(lc: ListCtx) -> list[dict[str, Any]]:
    """One DescribeKeyPairs call (not paginated)."""
    resp = lc.call("describe_key_pairs", IncludePublicKey=True)
    return [k for k in resp.get("KeyPairs", []) if isinstance(k, dict)]


KEY_PAIRS = CollectionSpec(
    name="key-pairs",
    client="ec2",
    lister=_list_key_pairs,
    key=lambda i: i["KeyName"],
    ops=frozenset({"DescribeKeyPairs"}),
    # display == key: links to deleted key pairs are omitted.
    display=lambda i: i["KeyName"],
    arn=ec2_arn("key-pair", "KeyPairId", owner_field=None),
    tags=_TAGS,
    files=(
        FileSpec("fingerprint", field_text("KeyFingerprint")),
        FileSpec("public-key", field_text("PublicKey")),
    ),
)


# -- elastic IPs --


def _list_addresses(lc: ListCtx) -> list[dict[str, Any]]:
    """One DescribeAddresses call (not paginated)."""
    resp = lc.call("describe_addresses")
    return [a for a in resp.get("Addresses", []) if isinstance(a, dict)]


ELASTIC_IPS = CollectionSpec(
    name="elastic-ips",
    client="ec2",
    lister=_list_addresses,
    key=lambda i: i.get("AllocationId") or i["PublicIp"],
    ops=frozenset({"DescribeAddresses"}),
    arn=ec2_arn("elastic-ip", "AllocationId", owner_field=None),
    tags=_TAGS,
    files=(
        FileSpec("public-ip", field_text("PublicIp")),
    ),
    links=(
        LinkSpec("instance", refs.INSTANCES,
                 lambda rc: rc.item.get("InstanceId")),
        LinkSpec("network-interface", refs.NETWORK_INTERFACES,
                 lambda rc: rc.item.get("NetworkInterfaceId")),
    ),
    key_from_arn=name_from_arn,
)


# -- network interfaces --


def _list_network_interfaces(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated DescribeNetworkInterfaces."""
    return lc.paginate("describe_network_interfaces", "NetworkInterfaces")


NETWORK_INTERFACES = CollectionSpec(
    name="network-interfaces",
    client="ec2",
    lister=_list_network_interfaces,
    key=lambda i: i["NetworkInterfaceId"],
    ops=frozenset({"DescribeNetworkInterfaces"}),
    arn=ec2_arn("network-interface", "NetworkInterfaceId"),
    # ENIs carry their tags under "TagSet", not "Tags".
    tags=TagSpec(inline="TagSet", style="list"),
    files=(
        FileSpec("status", field_text("Status")),
        FileSpec("private-ip", field_text("PrivateIpAddress")),
        FileSpec("interface-type", field_text("InterfaceType")),
    ),
    links=(
        LinkSpec("subnet", refs.SUBNETS,
                 lambda rc: rc.item.get("SubnetId")),
        LinkSpec("vpc", refs.VPCS, lambda rc: rc.item.get("VpcId")),
        LinkSpec("instance", refs.INSTANCES,
                 lambda rc: (rc.item.get("Attachment") or {})
                 .get("InstanceId")),
        LinkSpec("security-groups", refs.SECURITY_GROUPS,
                 lambda rc: pluck(rc.item.get("Groups"), "GroupId"),
                 many=True),
    ),
    key_from_arn=name_from_arn,
)


# -- AMIs --


def _list_images(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated DescribeImages restricted to owned images."""
    return lc.paginate("describe_images", "Images", Owners=["self"])


AMIS = CollectionSpec(
    name="amis",
    client="ec2",
    lister=_list_images,
    key=lambda i: i["ImageId"],
    ops=frozenset({"DescribeImages"}),
    # display == key: instance links to public / shared AMIs (not
    # listed, since only owned images are) are omitted, not dangling.
    display=lambda i: i["ImageId"],
    arn=ec2_arn("image", "ImageId", accountless=True),
    name_of=lambda i: i.get("Name"),
    tags=_TAGS,
    files=(
        FileSpec("state", field_text("State")),
    ),
    links=(
        LinkSpec("snapshots", refs.SNAPSHOTS,
                 lambda rc: pluck(rc.item.get("BlockDeviceMappings"),
                                  "Ebs", "SnapshotId"),
                 many=True),
    ),
    key_from_arn=name_from_arn,
)


# -- launch templates --


def _list_launch_templates(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated DescribeLaunchTemplates call.

    Template versions are not exposed: they hold the user data.
    """
    return [t for t in lc.paginate("describe_launch_templates",
                                   "LaunchTemplates")
            if isinstance(t, dict)]


LAUNCH_TEMPLATES = CollectionSpec(
    name="launch-templates",
    client="ec2",
    lister=_list_launch_templates,
    key=lambda i: str(i["LaunchTemplateId"]),
    ops=frozenset({"DescribeLaunchTemplates"}),
    display=lambda i: str(i["LaunchTemplateName"]),
    arn=ec2_arn("launch-template", "LaunchTemplateId", owner_field=None),
    tags=_TAGS,
    files=(
        FileSpec("default-version", field_text("DefaultVersionNumber")),
        FileSpec("latest-version", field_text("LatestVersionNumber")),
    ),
    lookup={"name": lambda i: str(i.get("LaunchTemplateName", ""))},
)

SERVICE = ServiceSpec(
    dirname="ec2",
    scope="region",
    collections=(
        INSTANCES,
        VOLUMES,
        SNAPSHOTS,
        KEY_PAIRS,
        ELASTIC_IPS,
        NETWORK_INTERFACES,
        AMIS,
        LAUNCH_TEMPLATES,
    ),
)
