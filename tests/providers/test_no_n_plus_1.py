"""Listing + reading describe.json of N resources costs O(1) calls."""

from __future__ import annotations

from collections.abc import Callable
from types import ModuleType
from typing import Any

import boto3
import pytest

from awsmount.session.redact import REDACTED
from awsmount.vfs.node import DirNode

SIZES = (5, 50)


def seed_bulk(seedlib: ModuleType, region: str,
              count: int) -> tuple[list[str], list[str]]:
    """``count`` instances (with user-data) and ``count`` SGs."""
    ec2 = boto3.client("ec2", region_name=region)
    vpc = ec2.create_vpc(CidrBlock="10.99.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.99.0.0/20",
                               AvailabilityZone=f"{region}a")
    groups = [ec2.create_security_group(
        GroupName=f"bulk-{i:03d}", Description="bulk",
        VpcId=vpc)["GroupId"] for i in range(count)]
    resp = ec2.run_instances(
        ImageId=seedlib.base_image_id(ec2), InstanceType="t3.micro",
        MinCount=count, MaxCount=count,
        SubnetId=subnet["Subnet"]["SubnetId"],
        SecurityGroupIds=[groups[0]], UserData=seedlib.USER_DATA,
        TagSpecifications=[{"ResourceType": "instance",
                            "Tags": [{"Key": "Name",
                                      "Value": "bulk"}]}])
    return [i["InstanceId"] for i in resp["Instances"]], groups


def read_dir_files(m: Any, path: str) -> None:
    """lstat every entry and read every regular file of a dir."""
    for name in m.ls(path):
        child = f"{path}/{name}"
        st = m.vfs.lstat(child)
        if st.is_file:
            m.read(child)
        elif st.is_dir and name == "tags":
            for tag in m.ls(child):
                m.read(f"{child}/{tag}")


@pytest.mark.parametrize("count", SIZES)
def test_listing_instances_is_one_page(
        moto_aws: None, seedlib: ModuleType, count: int,
        make_mount: Callable[..., Any],
        op_log: list[tuple[str, str]]) -> None:
    """ls of N instances = list pages only (moto: one page)."""
    instances, _groups = seed_bulk(seedlib, "us-east-1", count)
    m = make_mount()
    op_log.clear()
    before = m.calls()
    names = m.ls(m.path("ec2", "instances"))
    assert sorted(names) == sorted(instances)
    assert m.calls() - before == len(op_log) == 1
    assert op_log == [("ec2", "DescribeInstances")]


@pytest.mark.parametrize("count", SIZES)
def test_derived_files_cost_nothing(
        moto_aws: None, seedlib: ModuleType, count: int,
        make_mount: Callable[..., Any]) -> None:
    """describe.json, arn, name, tags... of N instances: zero calls."""
    instances, _groups = seed_bulk(seedlib, "us-east-1", count)
    m = make_mount()
    m.ls(m.path("ec2", "instances"))
    before = m.calls()
    for iid in instances:
        base = m.path("ec2", "instances", iid)
        assert iid in m.text(f"{base}/describe.json")
        read_dir_files(m, base)
    assert m.calls() == before


@pytest.mark.parametrize("count", SIZES)
def test_redacted_user_data_costs_nothing(
        moto_aws: None, seedlib: ModuleType, count: int,
        make_mount: Callable[..., Any]) -> None:
    """Whole-file redaction makes no DescribeInstanceAttribute call."""
    instances, _groups = seed_bulk(seedlib, "us-east-1", count)
    m = make_mount()
    m.ls(m.path("ec2", "instances"))
    before = m.calls()
    for iid in instances:
        data = m.read(m.path("ec2", "instances", iid, "user-data"))
        assert data == f"{REDACTED}\n".encode()
    assert m.calls() == before


def test_revealed_user_data_one_call_per_read(
        moto_aws: None, seedlib: ModuleType,
        make_mount: Callable[..., Any],
        op_log: list[tuple[str, str]]) -> None:
    """With --reveal: one call per instance read, cached afterwards."""
    instances, _groups = seed_bulk(seedlib, "us-east-1", 5)
    m = make_mount(reveal=True)
    m.ls(m.path("ec2", "instances"))
    op_log.clear()
    first = m.path("ec2", "instances", instances[0], "user-data")
    before = m.calls()
    assert seedlib.FAKE_SECRET.encode() in m.read(first)
    assert m.calls() - before == 1
    assert op_log == [("ec2", "DescribeInstanceAttribute")]
    m.read(first)
    assert m.calls() - before == 1


@pytest.mark.parametrize("count", SIZES)
def test_security_groups_list_once(
        moto_aws: None, seedlib: ModuleType, count: int,
        make_mount: Callable[..., Any],
        op_log: list[tuple[str, str]]) -> None:
    """N SGs: one list page; describe/rules/name files are free."""
    _instances, groups = seed_bulk(seedlib, "us-east-1", count)
    m = make_mount()
    op_log.clear()
    before = m.calls()
    names = m.ls(m.path("vpc", "security-groups"))
    assert set(groups) <= set(names)
    assert op_log == [("ec2", "DescribeSecurityGroups")]
    for gid in groups:
        base = m.path("vpc", "security-groups", gid)
        for name in ("describe.json", "rules.json", "group-name",
                     "vpc-id", "arn", "name", "tags.json"):
            m.read(f"{base}/{name}")
    assert m.calls() - before == 1


@pytest.mark.parametrize("count", SIZES)
def test_links_cost_is_bounded(
        moto_aws: None, seedlib: ModuleType, count: int,
        make_mount: Callable[..., Any],
        op_log: list[tuple[str, str]]) -> None:
    """Resolving all links of N instances lists each target once."""
    instances, _groups = seed_bulk(seedlib, "us-east-1", count)
    m = make_mount()
    m.ls(m.path("ec2", "instances"))
    op_log.clear()
    for iid in instances:
        links = m.path("ec2", "instances", iid, "links")
        for name in m.ls(links):
            node = m.vfs.resolve(f"{links}/{name}", follow=False)
            if isinstance(node, DirNode):
                m.ls(f"{links}/{name}")
    assert len(op_log) == len(set(op_log)), op_log
    # Link targets are confirmed against the (cached) target listings
    # so no dangling link is ever served (AWSM-009): at most one list
    # call per distinct target collection, whatever N is.
    assert len(op_log) <= 8, op_log


def test_cost_independent_of_n(
        moto_aws: None, seedlib: ModuleType,
        make_mount: Callable[..., Any]) -> None:
    """5 instances in one region cost as much as 50 in another."""
    seed_bulk(seedlib, "us-east-1", 5)
    seed_bulk(seedlib, "us-west-2", 50)
    m = make_mount(regions=("us-east-1", "us-west-2"))
    costs: list[int] = []
    for region, count in (("us-east-1", 5), ("us-west-2", 50)):
        path = f"/{m.account}/{region}/ec2/instances"
        before = m.calls()
        names = m.ls(path)
        assert len(names) == count
        for name in names:
            m.read(f"{path}/{name}/describe.json")
        costs.append(m.calls() - before)
    assert costs[0] == costs[1] == 1
