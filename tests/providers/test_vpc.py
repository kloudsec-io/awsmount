"""VPC family content over the seeded estate (docs/coverage.md)."""

from __future__ import annotations

from collections.abc import Callable
from types import ModuleType
from typing import Any

import boto3

VPC_COLLECTIONS = ["dhcp-options", "endpoints", "flow-logs",
                   "internet-gateways", "nat-gateways", "network-acls",
                   "peering-connections", "route-tables",
                   "security-groups", "subnets", "transit-gateways",
                   "vpcs"]


def has_row(rows: list[dict[str, Any]], **expected: Any) -> bool:
    """True when some row contains every ``expected`` field."""
    return any(all(r.get(k) == v for k, v in expected.items())
               for r in rows)


def test_service_layout(mount: Any) -> None:
    """vpc/ holds exactly the twelve collections."""
    assert mount.ls(mount.path("vpc")) == VPC_COLLECTIONS


def test_all_collections_list_without_errors(mount: Any) -> None:
    """Every collection lists (incl. empty ones) with no errors.log."""
    for coll in VPC_COLLECTIONS:
        mount.ls(mount.path("vpc", coll))
    assert mount.errors() == ""


def test_vpcs(mount: Any, estate: Any, seedlib: ModuleType) -> None:
    """Both VPCs with cidr, name, tags and owner-scoped ARN."""
    vpcs = mount.ls(mount.path("vpc", "vpcs"))
    assert {estate.vpc_main, estate.vpc_peer} <= set(vpcs)
    base = mount.path("vpc", "vpcs", estate.vpc_main)
    assert mount.text(f"{base}/cidr") == f"{seedlib.MAIN_VPC_CIDR}\n"
    assert mount.text(f"{base}/name") == f"{seedlib.MAIN_VPC_NAME}\n"
    assert mount.json(f"{base}/tags.json")["Name"] == \
        seedlib.MAIN_VPC_NAME
    assert mount.text(f"{base}/arn") == (
        f"arn:aws:ec2:{estate.region}:{estate.account_id}:"
        f"vpc/{estate.vpc_main}\n")
    peer = mount.path("vpc", "vpcs", estate.vpc_peer)
    assert mount.text(f"{peer}/cidr") == f"{seedlib.PEER_VPC_CIDR}\n"


def test_subnets(mount: Any, estate: Any, seedlib: ModuleType) -> None:
    """Subnet cidr and availability-zone files."""
    base = mount.path("vpc", "subnets", estate.subnet_private)
    assert mount.text(f"{base}/cidr") == \
        f"{seedlib.PRIVATE_SUBNET_CIDR}\n"
    assert mount.text(f"{base}/availability-zone") == \
        f"{estate.region}b\n"
    assert mount.text(f"{base}/tags/Name") == "awsmount-private\n"


def test_security_group_entries(mount: Any, estate: Any) -> None:
    """Exact entry set of a security-group dir."""
    base = mount.path("vpc", "security-groups", estate.sg_app)
    assert set(mount.ls(base)) == {
        "arn", "describe.json", "group-name", "links", "name",
        "referenced-by", "rules.json", "tags", "tags.json", "vpc-id"}


def test_security_group_files(mount: Any, estate: Any,
                              seedlib: ModuleType) -> None:
    """group-name, name, vpc-id, arn, tags."""
    base = mount.path("vpc", "security-groups", estate.sg_web)
    assert mount.text(f"{base}/group-name") == f"{seedlib.SG_WEB}\n"
    assert mount.text(f"{base}/name") == f"{seedlib.SG_WEB}\n"
    assert mount.text(f"{base}/vpc-id") == f"{estate.vpc_main}\n"
    assert mount.text(f"{base}/arn").rstrip("\n").endswith(
        f":security-group/{estate.sg_web}")
    assert mount.text(f"{base}/tags/Name") == f"{seedlib.SG_WEB}\n"


def test_rules_json(mount: Any, estate: Any) -> None:
    """Flattened rule rows from the listing, sorted and stable."""
    app = mount.json(mount.path("vpc", "security-groups", estate.sg_app,
                                "rules.json"))
    assert has_row(app, direction="ingress", protocol="tcp",
                   from_port=8080, to_port=8080, group=estate.sg_web,
                   description="http from web")
    assert has_row(app, direction="egress", protocol="-1",
                   cidr="0.0.0.0/0")
    web_path = mount.path("vpc", "security-groups", estate.sg_web,
                          "rules.json")
    web = mount.json(web_path)
    assert has_row(web, direction="ingress", protocol="tcp",
                   from_port=443, cidr="0.0.0.0/0",
                   description="public https")
    assert has_row(web, direction="ingress", from_port=9100,
                   group=estate.sg_app)
    assert [r["direction"] for r in web].count("egress") >= 1
    first = mount.read(web_path)
    assert first == mount.read(web_path)
    lonely = mount.json(mount.path("vpc", "security-groups",
                                   estate.sg_lonely, "rules.json"))
    assert not any(r.get("direction") == "ingress" for r in lonely)


def test_route_tables(mount: Any, estate: Any,
                      seedlib: ModuleType) -> None:
    """routes.json carries the IGW, peering and NAT routes."""
    pub = mount.json(mount.path("vpc", "route-tables", estate.rtb_public,
                                "routes.json"))
    assert has_row(pub, DestinationCidrBlock="0.0.0.0/0",
                   GatewayId=estate.igw)
    assert has_row(pub, DestinationCidrBlock=seedlib.PEER_VPC_CIDR,
                   VpcPeeringConnectionId=estate.peering)
    priv = mount.json(mount.path("vpc", "route-tables",
                                 estate.rtb_private, "routes.json"))
    assert has_row(priv, DestinationCidrBlock="0.0.0.0/0",
                   NatGatewayId=estate.nat)
    assert mount.text(mount.path("vpc", "route-tables", estate.rtb_public,
                                 "name")) == f"{seedlib.PUBLIC_RT_NAME}\n"


def test_internet_and_nat_gateways(mount: Any, estate: Any) -> None:
    """IGW tags; NAT state."""
    igw = mount.path("vpc", "internet-gateways", estate.igw)
    assert mount.text(f"{igw}/tags/Name") == "awsmount-igw\n"
    nat = mount.path("vpc", "nat-gateways", estate.nat)
    assert mount.text(f"{nat}/state").strip() in ("available", "pending")


def test_network_acl_entries(mount: Any, estate: Any) -> None:
    """entries.json holds the seeded rules."""
    entries = mount.json(mount.path("vpc", "network-acls", estate.nacl,
                                    "entries.json"))
    assert has_row(entries, RuleNumber=100, Egress=False, Protocol="6",
                   RuleAction="allow", CidrBlock="0.0.0.0/0")
    assert has_row(entries, RuleNumber=100, Egress=True)


def test_endpoint_policy_is_parsed(mount: Any, estate: Any,
                                   seedlib: ModuleType) -> None:
    """policy.json is the parsed PolicyDocument, not a JSON string."""
    policy = mount.json(mount.path("vpc", "endpoints", estate.vpce_gateway,
                                   "policy.json"))
    assert policy == seedlib.ENDPOINT_POLICY


def test_peering_status(mount: Any, estate: Any) -> None:
    """Accepted peering is active."""
    path = mount.path("vpc", "peering-connections", estate.peering,
                      "status")
    assert mount.text(path) == "active\n"


def test_describe_matches_api(mount: Any, estate: Any) -> None:
    """Subnet describe.json equals the API item (keys sorted)."""
    client = boto3.client("ec2", region_name=estate.region)
    item = client.describe_subnets(
        SubnetIds=[estate.subnet_public])["Subnets"][0]
    got = mount.json(mount.path("vpc", "subnets", estate.subnet_public,
                                "describe.json"))
    assert got["SubnetId"] == item["SubnetId"]
    assert got["CidrBlock"] == item["CidrBlock"]
    assert got["VpcId"] == estate.vpc_main
    assert "ResponseMetadata" not in got


def test_vpc_only_mount(seed: Any, estate: Any,
                        make_mount: Callable[..., Any]) -> None:
    """--services vpc still serves the whole VPC family."""
    m = make_mount(services=frozenset({"vpc"}))
    assert m.ls(m.base) == ["vpc"]
    assert estate.sg_app in m.ls(m.path("vpc", "security-groups"))
    assert m.errors() == ""
