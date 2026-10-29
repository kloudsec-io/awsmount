"""VPC family provider (docs/coverage.md), served through the ``ec2`` client.

Collections: vpcs, subnets, security-groups (rules.json, references/,
referenced-by/), route-tables, internet-gateways, nat-gateways,
network-acls, endpoints, peering-connections, dhcp-options,
transit-gateways and flow-logs. Every file is derived from the single
listing call of its collection (no lazy files).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from awsmount.providers import refs
from awsmount.providers.base import (
    CollectionSpec,
    FileSpec,
    LinkSpec,
    ListCtx,
    RefSource,
    ResourceCtx,
    ServiceSpec,
    TagSpec,
)
from awsmount.providers.common import (
    drop_dead,
    name_from_arn,
    parse_json_text,
)
from awsmount.providers.ec2 import ec2_arn, field_text, pluck

if TYPE_CHECKING:
    from awsmount.session.context import Scope

__all__ = [
    "DHCP_OPTIONS",
    "ENDPOINTS",
    "FLOW_LOGS",
    "INTERNET_GATEWAYS",
    "NAT_GATEWAYS",
    "NETWORK_ACLS",
    "PEERING_CONNECTIONS",
    "ROUTE_TABLES",
    "SECURITY_GROUPS",
    "SERVICE",
    "SUBNETS",
    "TRANSIT_GATEWAYS",
    "VPCS",
]

_TAGS = TagSpec(inline="Tags", style="list")


def _lister(op: str, key: str, *,
            state_of: Callable[[dict[str, Any]], Any] | None = None,
            dead: frozenset[str] = frozenset(),
            ) -> Callable[[ListCtx], list[dict[str, Any]]]:
    """Lister making one paginated ``op`` call, returning ``key`` items.

    With ``state_of`` and ``dead``, resources AWS still reports in a
    terminal state (deleted NAT gateways, ...) are dropped.
    """

    def lister(lc: ListCtx) -> list[dict[str, Any]]:
        items = [i for i in lc.paginate(op, key) if isinstance(i, dict)]
        if state_of is not None and dead:
            items = drop_dead(items, state_of, dead)
        return items

    lister.__doc__ = f"One paginated {op} call for the region."
    return lister


# -- vpcs --


def _dhcp_ref(rc: ResourceCtx) -> str | None:
    """DHCP options id of a VPC; ``default`` means no options set."""
    value = rc.item.get("DhcpOptionsId")
    if not value or value == "default":
        return None
    return str(value)


VPCS = CollectionSpec(
    name="vpcs",
    client="ec2",
    lister=_lister("describe_vpcs", "Vpcs"),
    key=lambda i: i["VpcId"],
    ops=frozenset({"DescribeVpcs"}),
    arn=ec2_arn("vpc", "VpcId"),
    tags=_TAGS,
    files=(
        FileSpec("cidr", field_text("CidrBlock")),
    ),
    links=(
        LinkSpec("dhcp-options", refs.DHCP_OPTIONS, _dhcp_ref),
    ),
    key_from_arn=name_from_arn,
)


# -- subnets --


def _subnet_arn(item: dict[str, Any], scope: Scope) -> str | None:
    """SubnetArn from the listing, or built from the id."""
    arn = item.get("SubnetArn")
    if arn:
        return str(arn)
    return ec2_arn("subnet", "SubnetId")(item, scope)


SUBNETS = CollectionSpec(
    name="subnets",
    client="ec2",
    lister=_lister("describe_subnets", "Subnets"),
    key=lambda i: i["SubnetId"],
    ops=frozenset({"DescribeSubnets"}),
    arn=_subnet_arn,
    tags=_TAGS,
    files=(
        FileSpec("cidr", field_text("CidrBlock")),
        FileSpec("availability-zone", field_text("AvailabilityZone")),
    ),
    links=(
        LinkSpec("vpc", refs.VPCS, lambda rc: rc.item.get("VpcId")),
    ),
    key_from_arn=name_from_arn,
)


# -- security groups --


def _flatten(perms: list[dict[str, Any]],
             direction: str) -> list[dict[str, Any]]:
    """Flatten IpPermissions into one row per peer."""
    rows: list[dict[str, Any]] = []
    for p in perms:
        if not isinstance(p, dict):
            continue
        base = {"direction": direction,
                "protocol": p.get("IpProtocol"),
                "from_port": p.get("FromPort"),
                "to_port": p.get("ToPort")}
        for r in p.get("IpRanges", []):
            rows.append({**base, "cidr": r.get("CidrIp"),
                         "description": r.get("Description")})
        for r in p.get("Ipv6Ranges", []):
            rows.append({**base, "cidr": r.get("CidrIpv6"),
                         "description": r.get("Description")})
        for r in p.get("PrefixListIds", []):
            rows.append({**base, "prefix_list": r.get("PrefixListId"),
                         "description": r.get("Description")})
        for r in p.get("UserIdGroupPairs", []):
            rows.append({**base, "group": r.get("GroupId"),
                         "account": r.get("UserId"),
                         "description": r.get("Description")})
    return sorted(rows, key=lambda d: json.dumps(d, sort_keys=True,
                                                 default=str))


def _rules(rc: ResourceCtx) -> list[dict[str, Any]]:
    """rules.json: derived from the listing, no API call."""
    i = rc.item
    return (_flatten(i.get("IpPermissions", []), "ingress")
            + _flatten(i.get("IpPermissionsEgress", []), "egress"))


def _pairs(i: dict[str, Any]) -> list[dict[str, Any]]:
    """Every UserIdGroupPair of a group's rules that names a group."""
    perms = (list(i.get("IpPermissions", []))
             + list(i.get("IpPermissionsEgress", [])))
    return [g for p in perms if isinstance(p, dict)
            for g in p.get("UserIdGroupPairs", [])
            if isinstance(g, dict) and g.get("GroupId")]


def _rule_refs(i: dict[str, Any]) -> list[str]:
    """Security group ids referenced by a group's rules."""
    return [str(g["GroupId"]) for g in _pairs(i)]


def _referenced_groups(rc: ResourceCtx) -> list[str]:
    """Security groups referenced by this group's rules (sorted).

    A peer group owned by another account is given as an
    account-qualified ARN, so the link goes to that account when it is
    mounted and is omitted otherwise (never into this account).
    """
    own = rc.scope.account.account_id
    out: set[str] = set()
    for pair in _pairs(rc.item):
        group = str(pair["GroupId"])
        owner = pair.get("UserId")
        if owner and own and str(owner) != own:
            out.add(f"arn:{rc.scope.partition}:ec2:{rc.scope.region}:"
                    f"{owner}:security-group/{group}")
        else:
            out.add(group)
    return sorted(out)


def _sg_arn(i: dict[str, Any], s: Scope) -> str | None:
    """Security group ARN (listing value when present)."""
    arn = i.get("SecurityGroupArn")
    if arn:
        return str(arn)
    return ec2_arn("security-group", "GroupId")(i, s)


def _lambda_sgs(i: dict[str, Any]) -> list[str]:
    """Security groups of a Lambda function's VPC config."""
    config = i.get("VpcConfig") or {}
    return [g for g in config.get("SecurityGroupIds", [])
            if isinstance(g, str)]


def _lb_sgs(i: dict[str, Any]) -> list[str]:
    """Security groups of a load balancer."""
    return [g for g in i.get("SecurityGroups", []) or []
            if isinstance(g, str)]


SECURITY_GROUPS = CollectionSpec(
    name="security-groups",
    client="ec2",
    lister=_lister("describe_security_groups", "SecurityGroups"),
    key=lambda i: i["GroupId"],
    ops=frozenset({"DescribeSecurityGroups"}),
    arn=_sg_arn,
    name_of=lambda i: i.get("GroupName"),
    tags=_TAGS,
    files=(
        FileSpec("rules.json", _rules),
        FileSpec("group-name", field_text("GroupName")),
        FileSpec("vpc-id", field_text("VpcId")),
    ),
    links=(
        LinkSpec("vpc", refs.VPCS, lambda rc: rc.item.get("VpcId")),
        LinkSpec("references", refs.SECURITY_GROUPS, _referenced_groups,
                 many=True),
    ),
    referenced_by=(
        RefSource(refs.NETWORK_INTERFACES,
                  lambda i: pluck(i.get("Groups"), "GroupId")),
        RefSource(refs.INSTANCES,
                  lambda i: pluck(i.get("SecurityGroups"), "GroupId")),
        RefSource(refs.SECURITY_GROUPS, _rule_refs),
        RefSource(refs.LOAD_BALANCERS, _lb_sgs),
        RefSource(refs.LAMBDA_FUNCTIONS, _lambda_sgs),
        RefSource(refs.RDS_INSTANCES,
                  lambda i: pluck(i.get("VpcSecurityGroups"),
                                  "VpcSecurityGroupId")),
        RefSource(refs.VPC_ENDPOINTS,
                  lambda i: pluck(i.get("Groups"), "GroupId")),
    ),
    key_from_arn=name_from_arn,
)


# -- route tables --


def _igw_targets(rc: ResourceCtx) -> list[str]:
    """Internet gateways used as route targets."""
    return [g for g in pluck(rc.item.get("Routes"), "GatewayId")
            if g.startswith("igw-")]


ROUTE_TABLES = CollectionSpec(
    name="route-tables",
    client="ec2",
    lister=_lister("describe_route_tables", "RouteTables"),
    key=lambda i: i["RouteTableId"],
    ops=frozenset({"DescribeRouteTables"}),
    arn=ec2_arn("route-table", "RouteTableId"),
    tags=_TAGS,
    files=(
        FileSpec("routes.json", lambda rc: rc.item.get("Routes", [])),
    ),
    links=(
        LinkSpec("vpc", refs.VPCS, lambda rc: rc.item.get("VpcId")),
        LinkSpec("subnets", refs.SUBNETS,
                 lambda rc: pluck(rc.item.get("Associations"),
                                  "SubnetId"),
                 many=True),
        LinkSpec("internet-gateways", refs.INTERNET_GATEWAYS,
                 _igw_targets, many=True),
        LinkSpec("nat-gateways", refs.NAT_GATEWAYS,
                 lambda rc: pluck(rc.item.get("Routes"), "NatGatewayId"),
                 many=True),
        LinkSpec("peering-connections", refs.PEERING_CONNECTIONS,
                 lambda rc: pluck(rc.item.get("Routes"),
                                  "VpcPeeringConnectionId"),
                 many=True),
    ),
    key_from_arn=name_from_arn,
)


# -- internet gateways --


INTERNET_GATEWAYS = CollectionSpec(
    name="internet-gateways",
    client="ec2",
    lister=_lister("describe_internet_gateways", "InternetGateways"),
    key=lambda i: i["InternetGatewayId"],
    ops=frozenset({"DescribeInternetGateways"}),
    arn=ec2_arn("internet-gateway", "InternetGatewayId"),
    tags=_TAGS,
    links=(
        LinkSpec("vpcs", refs.VPCS,
                 lambda rc: pluck(rc.item.get("Attachments"), "VpcId"),
                 many=True),
    ),
    key_from_arn=name_from_arn,
)


# -- NAT gateways --


NAT_GATEWAYS = CollectionSpec(
    name="nat-gateways",
    client="ec2",
    lister=_lister("describe_nat_gateways", "NatGateways",
                   state_of=lambda i: i.get("State"),
                   dead=frozenset({"deleted"})),
    key=lambda i: i["NatGatewayId"],
    ops=frozenset({"DescribeNatGateways"}),
    arn=ec2_arn("natgateway", "NatGatewayId", owner_field=None),
    tags=_TAGS,
    files=(
        FileSpec("state", field_text("State")),
    ),
    links=(
        LinkSpec("vpc", refs.VPCS, lambda rc: rc.item.get("VpcId")),
        LinkSpec("subnet", refs.SUBNETS,
                 lambda rc: rc.item.get("SubnetId")),
        LinkSpec("network-interfaces", refs.NETWORK_INTERFACES,
                 lambda rc: pluck(rc.item.get("NatGatewayAddresses"),
                                  "NetworkInterfaceId"),
                 many=True),
        LinkSpec("elastic-ips", refs.ELASTIC_IPS,
                 lambda rc: pluck(rc.item.get("NatGatewayAddresses"),
                                  "AllocationId"),
                 many=True),
    ),
    key_from_arn=name_from_arn,
)


# -- network ACLs --


NETWORK_ACLS = CollectionSpec(
    name="network-acls",
    client="ec2",
    lister=_lister("describe_network_acls", "NetworkAcls"),
    key=lambda i: i["NetworkAclId"],
    ops=frozenset({"DescribeNetworkAcls"}),
    arn=ec2_arn("network-acl", "NetworkAclId"),
    tags=_TAGS,
    files=(
        FileSpec("entries.json", lambda rc: rc.item.get("Entries", [])),
    ),
    links=(
        LinkSpec("vpc", refs.VPCS, lambda rc: rc.item.get("VpcId")),
        LinkSpec("subnets", refs.SUBNETS,
                 lambda rc: pluck(rc.item.get("Associations"),
                                  "SubnetId"),
                 many=True),
    ),
    key_from_arn=name_from_arn,
)


# -- VPC endpoints --


def _str_list(value: Any) -> list[str]:
    """Non-empty strings of a list field."""
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, str) and v]


def _endpoint_policy(rc: ResourceCtx) -> Any:
    """policy.json: the parsed PolicyDocument of the endpoint."""
    return parse_json_text(rc.item.get("PolicyDocument"))


ENDPOINTS = CollectionSpec(
    name="endpoints",
    client="ec2",
    lister=_lister("describe_vpc_endpoints", "VpcEndpoints",
                   state_of=lambda i: i.get("State"),
                   dead=frozenset({"deleted"})),
    key=lambda i: i["VpcEndpointId"],
    ops=frozenset({"DescribeVpcEndpoints"}),
    arn=ec2_arn("vpc-endpoint", "VpcEndpointId"),
    tags=_TAGS,
    files=(
        FileSpec("policy.json", _endpoint_policy),
    ),
    links=(
        LinkSpec("vpc", refs.VPCS, lambda rc: rc.item.get("VpcId")),
        LinkSpec("subnets", refs.SUBNETS,
                 lambda rc: _str_list(rc.item.get("SubnetIds")),
                 many=True),
        LinkSpec("route-tables", refs.ROUTE_TABLES,
                 lambda rc: _str_list(rc.item.get("RouteTableIds")),
                 many=True),
        LinkSpec("security-groups", refs.SECURITY_GROUPS,
                 lambda rc: pluck(rc.item.get("Groups"), "GroupId"),
                 many=True),
        LinkSpec("network-interfaces", refs.NETWORK_INTERFACES,
                 lambda rc: _str_list(rc.item.get("NetworkInterfaceIds")),
                 many=True),
    ),
    key_from_arn=name_from_arn,
)


# -- peering connections --


def _peer_vpc(side: str) -> Callable[[ResourceCtx], str | None]:
    """ARN of the requester/accepter VPC, so links are account-scoped.

    The link is omitted when that account or region is not mounted.
    """

    def values(rc: ResourceCtx) -> str | None:
        info = rc.item.get(side) or {}
        vpc = info.get("VpcId")
        if not vpc:
            return None
        owner = info.get("OwnerId") or rc.scope.account.account_id or ""
        region = info.get("Region") or rc.scope.region
        return f"arn:{rc.scope.partition}:ec2:{region}:{owner}:vpc/{vpc}"

    return values


PEERING_CONNECTIONS = CollectionSpec(
    name="peering-connections",
    client="ec2",
    lister=_lister("describe_vpc_peering_connections",
                   "VpcPeeringConnections",
                   state_of=lambda i: (i.get("Status") or {}).get("Code"),
                   dead=frozenset({"deleted", "rejected", "expired",
                                   "failed"})),
    key=lambda i: i["VpcPeeringConnectionId"],
    ops=frozenset({"DescribeVpcPeeringConnections"}),
    arn=ec2_arn("vpc-peering-connection", "VpcPeeringConnectionId",
                owner_field=None),
    tags=_TAGS,
    files=(
        FileSpec("status", field_text("Status", "Code")),
    ),
    links=(
        LinkSpec("requester-vpc", refs.VPCS,
                 _peer_vpc("RequesterVpcInfo"), by="arn"),
        LinkSpec("accepter-vpc", refs.VPCS,
                 _peer_vpc("AccepterVpcInfo"), by="arn"),
    ),
    key_from_arn=name_from_arn,
)


# -- DHCP options --


DHCP_OPTIONS = CollectionSpec(
    name="dhcp-options",
    client="ec2",
    lister=_lister("describe_dhcp_options", "DhcpOptions"),
    key=lambda i: i["DhcpOptionsId"],
    ops=frozenset({"DescribeDhcpOptions"}),
    arn=ec2_arn("dhcp-options", "DhcpOptionsId"),
    tags=_TAGS,
    key_from_arn=name_from_arn,
)


# -- transit gateways --


def _tgw_arn(item: dict[str, Any], scope: Scope) -> str | None:
    """TransitGatewayArn from the listing, or built from the id."""
    arn = item.get("TransitGatewayArn")
    if arn:
        return str(arn)
    return ec2_arn("transit-gateway", "TransitGatewayId")(item, scope)


TRANSIT_GATEWAYS = CollectionSpec(
    name="transit-gateways",
    client="ec2",
    lister=_lister("describe_transit_gateways", "TransitGateways",
                   state_of=lambda i: i.get("State"),
                   dead=frozenset({"deleted"})),
    key=lambda i: i["TransitGatewayId"],
    ops=frozenset({"DescribeTransitGateways"}),
    arn=_tgw_arn,
    tags=_TAGS,
    files=(
        FileSpec("state", field_text("State")),
    ),
    key_from_arn=name_from_arn,
)


# -- flow logs --


def _resource_with(prefix: str) -> Callable[[ResourceCtx], str | None]:
    """Flow log ResourceId when it starts with ``prefix``."""

    def values(rc: ResourceCtx) -> str | None:
        value = rc.item.get("ResourceId")
        if isinstance(value, str) and value.startswith(prefix):
            return value
        return None

    return values


FLOW_LOGS = CollectionSpec(
    name="flow-logs",
    client="ec2",
    lister=_lister("describe_flow_logs", "FlowLogs"),
    key=lambda i: i["FlowLogId"],
    ops=frozenset({"DescribeFlowLogs"}),
    arn=ec2_arn("vpc-flow-log", "FlowLogId", owner_field=None),
    tags=_TAGS,
    links=(
        # At most one of the three "resource" links has a value.
        LinkSpec("resource", refs.VPCS, _resource_with("vpc-")),
        LinkSpec("resource", refs.SUBNETS, _resource_with("subnet-")),
        LinkSpec("resource", refs.NETWORK_INTERFACES,
                 _resource_with("eni-")),
        LinkSpec("log-group", refs.LOG_GROUPS,
                 lambda rc: rc.item.get("LogGroupName")),
    ),
    key_from_arn=name_from_arn,
)


SERVICE = ServiceSpec(
    dirname="vpc",
    scope="region",
    collections=(
        VPCS,
        SUBNETS,
        SECURITY_GROUPS,
        ROUTE_TABLES,
        INTERNET_GATEWAYS,
        NAT_GATEWAYS,
        NETWORK_ACLS,
        ENDPOINTS,
        PEERING_CONNECTIONS,
        DHCP_OPTIONS,
        TRANSIT_GATEWAYS,
        FLOW_LOGS,
    ),
)
