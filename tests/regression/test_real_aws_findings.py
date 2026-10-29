"""Findings from the first run against a real AWS account (2026-10-24)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

from awsmount.providers.common import drop_dead
from awsmount.session.redact import REDACTED, RedactionPolicy, is_secret_key

POLICY = RedactionPolicy(reveal=False)
_TESTS = Path(__file__).resolve().parents[1]


def _load_kit() -> ModuleType:
    """Load tests/providers/motokit.py by path (any import mode)."""
    name = "awsmount_tests_motokit"
    module = sys.modules.get(name)
    if module is not None:
        return module
    spec = importlib.util.spec_from_file_location(
        name, _TESTS / "providers" / "motokit.py")
    if spec is None or spec.loader is None:
        raise ImportError("cannot load motokit")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


kit = _load_kit()
moto_session = kit.moto_session
Mount = kit.Mount
REGION: str = kit.REGION


def test_imds_http_tokens_is_not_treated_as_a_secret() -> None:
    """EC2 MetadataOptions.HttpTokens is the IMDSv2 setting users audit.

    Real DescribeInstances output contains ``HttpTokens: required``; the
    generic "token" heuristic used to hide it.
    """
    instance = {
        "InstanceId": "i-0123456789abcdef0",
        "ClientToken": "a37b2d2d-58d4-0689-2e61-3ad305b12754",
        "MetadataOptions": {
            "State": "applied", "HttpTokens": "required",
            "HttpPutResponseHopLimit": 2, "HttpEndpoint": "enabled"},
    }
    out = POLICY.json("ec2", instance)
    assert out["MetadataOptions"]["HttpTokens"] == "required"
    assert out["MetadataOptions"]["HttpEndpoint"] == "enabled"
    assert out["InstanceId"] == instance["InstanceId"]
    # Idempotency tokens stay hidden on purpose (cheap to over-hide).
    assert out["ClientToken"] == REDACTED


def test_real_secret_looking_keys_are_still_hidden() -> None:
    """The allow-list is exact: similar-looking secret keys stay hidden."""
    out = POLICY.json(None, {
        "SessionToken": "FQoGZXIvYXdz-example",
        "AccessToken": "abc.def.ghi",
        "ApiKey": "k-123",
        "HttpTokens": "optional",
        "NextToken": "page-2",
    })
    assert out["SessionToken"] == REDACTED
    assert out["AccessToken"] == REDACTED
    assert out["ApiKey"] == REDACTED
    assert out["HttpTokens"] == "optional"
    assert out["NextToken"] == "page-2"


def test_is_secret_key_allow_list_is_case_insensitive() -> None:
    """Key case varies between AWS services."""
    assert not is_secret_key("HttpTokens")
    assert not is_secret_key("httptokens")
    assert is_secret_key("clientToken")
    assert is_secret_key("Token")
    assert is_secret_key("sessionToken")


# -- dead resources are hidden ---------------------------------------


def test_drop_dead_helper() -> None:
    """Terminal states are dropped, case-insensitively; others stay."""
    items = [{"id": 1, "s": "Deleted"}, {"id": 2, "s": "available"},
             {"id": 3, "s": None}]
    kept = drop_dead(items, lambda i: i["s"], frozenset({"deleted"}))
    assert [i["id"] for i in kept] == [2, 3]


def test_terminated_instances_are_not_listed(moto_session: Any) -> None:
    """AWS keeps returning terminated instances for about an hour."""
    ec2 = moto_session.client("ec2", region_name=REGION)
    ids = [i["InstanceId"] for i in ec2.run_instances(
        ImageId="ami-12c6146b", MinCount=2, MaxCount=2)["Instances"]]
    ec2.terminate_instances(InstanceIds=[ids[0]])
    listed = Mount().ls(Mount().path("ec2/instances"))
    assert ids[1] in listed
    assert ids[0] not in listed


def test_deleted_nat_and_tgw_are_not_listed(moto_session: Any) -> None:
    """Deleted NAT gateways and Transit Gateways linger in the API."""
    ec2 = moto_session.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.9.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(
        VpcId=vpc, CidrBlock="10.9.1.0/24")["Subnet"]["SubnetId"]
    eip = ec2.allocate_address(Domain="vpc")["AllocationId"]
    nat_gone = ec2.create_nat_gateway(
        SubnetId=subnet, AllocationId=eip)["NatGateway"]["NatGatewayId"]
    eip2 = ec2.allocate_address(Domain="vpc")["AllocationId"]
    nat_live = ec2.create_nat_gateway(
        SubnetId=subnet, AllocationId=eip2)["NatGateway"]["NatGatewayId"]
    ec2.delete_nat_gateway(NatGatewayId=nat_gone)
    tgw_gone = ec2.create_transit_gateway()["TransitGateway"][
        "TransitGatewayId"]
    tgw_live = ec2.create_transit_gateway()["TransitGateway"][
        "TransitGatewayId"]
    ec2.delete_transit_gateway(TransitGatewayId=tgw_gone)
    mount = Mount()
    nats = mount.ls(mount.path("vpc/nat-gateways"))
    assert nat_live in nats and nat_gone not in nats
    tgws = mount.ls(mount.path("vpc/transit-gateways"))
    assert tgw_live in tgws and tgw_gone not in tgws


# -- AWS returns some lists in unstable order -------------------------

from awsmount.vfs.render import to_json_text  # noqa: E402


def test_route_table_associations_render_identically_in_any_order() -> None:
    """Seen on a real account: two associations swapped between calls."""
    a = {"RouteTableAssociationId": "rtbassoc-06", "SubnetId": "subnet-a"}
    b = {"RouteTableAssociationId": "rtbassoc-0d", "SubnetId": "subnet-b"}
    one = to_json_text({"RouteTableId": "rtb-1", "Associations": [a, b]})
    two = to_json_text({"RouteTableId": "rtb-1", "Associations": [b, a]})
    assert one == two


def test_unordered_lists_are_sorted_everywhere() -> None:
    """Tags, security groups and IP permissions are order-insensitive."""
    inst = {"Tags": [{"Key": "b", "Value": "1"}, {"Key": "a", "Value": "2"}],
            "SecurityGroups": [{"GroupId": "sg-2"}, {"GroupId": "sg-1"}],
            "IpPermissions": [{"FromPort": 80}, {"FromPort": 22}]}
    swapped = {"Tags": list(reversed(inst["Tags"])),
               "SecurityGroups": list(reversed(inst["SecurityGroups"])),
               "IpPermissions": list(reversed(inst["IpPermissions"]))}
    assert to_json_text(inst) == to_json_text(swapped)


def test_ordered_lists_keep_the_api_order() -> None:
    """Order matters for these, so they must never be sorted."""
    layers = [{"Arn": "arn:z"}, {"Arn": "arn:a"}]  # later layers override
    behaviors = [{"PathPattern": "/z/*"}, {"PathPattern": "/a/*"}]
    out = to_json_text({"Layers": layers, "CacheBehaviors": behaviors})
    assert out.index("arn:z") < out.index("arn:a")
    assert out.index("/z/*") < out.index("/a/*")


def test_stabilize_does_not_mutate_its_input() -> None:
    """Rendering must not change cached API data."""
    data = {"Associations": [{"AssociationId": "b"}, {"AssociationId": "a"}]}
    to_json_text(data)
    assert [x["AssociationId"] for x in data["Associations"]] == ["b", "a"]
