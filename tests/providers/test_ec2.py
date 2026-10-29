"""EC2 provider content over the seeded estate (docs/coverage.md)."""

from __future__ import annotations

import json
from collections.abc import Callable
from types import ModuleType
from typing import Any

import boto3
import pytest

from awsmount.session.redact import REDACTED, RedactionPolicy
from awsmount.vfs.node import DirNode
from awsmount.vfs.path import escape_name
from awsmount.vfs.render import to_json_text
from awsmount.vfs.walk import grep

EC2_COLLECTIONS = ["amis", "elastic-ips", "instances", "key-pairs",
                   "launch-templates", "network-interfaces", "snapshots",
                   "volumes"]


def ec2(estate: Any) -> Any:
    """Direct boto3 client (moto), outside the mount's budget."""
    return boto3.client("ec2", region_name=estate.region)


def canonical(item: dict[str, Any]) -> Any:
    """Expected describe.json payload for a raw API item."""
    return json.loads(to_json_text(RedactionPolicy(False).json(None, item)))


def instance_item(estate: Any, iid: str) -> dict[str, Any]:
    """The instance as DescribeInstances returns it."""
    resp = ec2(estate).describe_instances(InstanceIds=[iid])
    return resp["Reservations"][0]["Instances"][0]


def test_service_layout(mount: Any) -> None:
    """ec2/ holds exactly the eight collections."""
    assert mount.ls(mount.path("ec2")) == EC2_COLLECTIONS


def test_instances_are_id_keyed(mount: Any, estate: Any) -> None:
    """Instance dirs are named by InstanceId."""
    assert set(estate.instances) <= set(
        mount.ls(mount.path("ec2", "instances")))


def test_instance_entries(mount: Any, estate: Any) -> None:
    """Exact entry set of an instance dir."""
    base = mount.path("ec2", "instances", estate.instance_web)
    assert set(mount.ls(base)) == {
        "arn", "describe.json", "instance-type", "links", "name",
        "private-ip", "state", "tags", "tags.json", "user-data"}


def test_instance_describe_is_canonical(mount: Any, estate: Any) -> None:
    """describe.json = canonical render of the API item."""
    path = mount.path("ec2", "instances", estate.instance_web,
                      "describe.json")
    text = mount.text(path)
    assert "ResponseMetadata" not in text
    assert text == json.dumps(json.loads(text), indent=2, sort_keys=True,
                              ensure_ascii=False) + "\n"
    expected = canonical(instance_item(estate, estate.instance_web))
    assert json.loads(text) == expected


def test_instance_text_files(mount: Any, estate: Any,
                             seedlib: ModuleType) -> None:
    """state, instance-type, private-ip, arn and name."""
    item = instance_item(estate, estate.instance_web)
    base = mount.path("ec2", "instances", estate.instance_web)
    assert mount.text(f"{base}/state") == "running\n"
    assert mount.text(f"{base}/instance-type") == \
        f"{seedlib.INSTANCE_TYPE}\n"
    assert mount.text(f"{base}/private-ip") == \
        f"{item['PrivateIpAddress']}\n"
    assert mount.text(f"{base}/arn") == (
        f"arn:aws:ec2:{estate.region}:{estate.account_id}:"
        f"instance/{estate.instance_web}\n")
    assert mount.text(f"{base}/name") == "web-1\n"


def test_instance_tags(mount: Any, estate: Any,
                       seedlib: ModuleType) -> None:
    """tags.json and tags/<escaped Key>; tag values are not redacted."""
    base = mount.path("ec2", "instances", estate.instance_web)
    assert mount.json(f"{base}/tags.json") == seedlib.WEB_TAGS
    names = mount.ls(f"{base}/tags")
    assert names == sorted(escape_name(k) for k in seedlib.WEB_TAGS)
    assert "team%2Fowner" in names
    assert mount.read(f"{base}/tags/team%2Fowner") == b"alice\n"
    assert mount.read(f"{base}/tags/Environment") == b"prod\n"
    assert mount.text(f"{base}/tags/DbPassword") == \
        f"{seedlib.TAG_SECRET_VALUE}\n"


def test_user_data_redacted_by_default(mount: Any, estate: Any,
                                       seedlib: ModuleType) -> None:
    """user-data is whole-file redacted and its read costs no call.

    The collection listing (one DescribeInstances page) is primed first:
    Only the user-data read itself must make zero calls; the instances
    may well be listed.
    """
    for iid in estate.instances:
        assert "user-data" in mount.ls(
            mount.path("ec2", "instances", iid))
    before = mount.calls()
    for iid in estate.instances:
        data = mount.read(mount.path("ec2", "instances", iid, "user-data"))
        assert data == f"{REDACTED}\n".encode()
        assert seedlib.FAKE_SECRET.encode() not in data
    assert mount.calls() == before


def test_secret_not_greppable_by_default(mount: Any,
                                         seedlib: ModuleType) -> None:
    """grep -r over the whole region never finds the secret."""
    hits = list(grep(mount.vfs, seedlib.FAKE_SECRET, [mount.base],
                     recursive=True))
    assert hits == []


def test_reveal_shows_user_data(seed: Any, estate: Any,
                                seedlib: ModuleType,
                                make_mount: Callable[..., Any]) -> None:
    """--reveal decodes the real user-data."""
    m = make_mount(reveal=True)
    data = m.read(m.path("ec2", "instances", estate.instance_web,
                         "user-data"))
    assert data.startswith(b"#!/bin/bash")
    assert seedlib.FAKE_SECRET.encode() in data
    assert REDACTED.encode() not in data


def test_reveal_grep_finds_only_user_data(
        seed: Any, estate: Any, seedlib: ModuleType,
        make_mount: Callable[..., Any]) -> None:
    """With --reveal the secret lives in exactly the user-data files."""
    m = make_mount(reveal=True)
    hits = {h.path for h in grep(m.vfs, seedlib.FAKE_SECRET,
                                 [m.path("ec2")], recursive=True)}
    assert hits == {m.path("ec2", "instances", iid, "user-data")
                    for iid in estate.instances}


def test_volume_files(mount: Any, estate: Any,
                      seedlib: ModuleType) -> None:
    """Data volume: state, size-gib, tags."""
    base = mount.path("ec2", "volumes", estate.volume_data)
    assert mount.text(f"{base}/state") == "in-use\n"
    assert mount.text(f"{base}/size-gib") == \
        f"{seedlib.DATA_VOLUME_SIZE}\n"
    assert mount.text(f"{base}/tags/Name") == \
        f"{seedlib.DATA_VOLUME_NAME}\n"
    assert mount.text(f"{base}/name") == f"{seedlib.DATA_VOLUME_NAME}\n"


def test_snapshots_owned_only(mount: Any, estate: Any) -> None:
    """Owned snapshot listed with state and accountless ARN."""
    snaps = mount.ls(mount.path("ec2", "snapshots"))
    assert estate.snapshot_data in snaps
    base = mount.path("ec2", "snapshots", estate.snapshot_data)
    assert mount.text(f"{base}/state").strip() in ("completed", "pending")
    assert mount.text(f"{base}/arn") == (
        f"arn:aws:ec2:{estate.region}::snapshot/"
        f"{estate.snapshot_data}\n")


def test_key_pairs(mount: Any, estate: Any) -> None:
    """Key pair dir by KeyName with a fingerprint."""
    assert estate.key_name in mount.ls(mount.path("ec2", "key-pairs"))
    base = mount.path("ec2", "key-pairs", estate.key_name)
    assert mount.text(f"{base}/fingerprint").strip()
    assert "public-key" in mount.ls(base)


def test_elastic_ips(mount: Any, estate: Any) -> None:
    """EIPs keyed by AllocationId with public-ip."""
    eips = mount.ls(mount.path("ec2", "elastic-ips"))
    assert {estate.eip_web, estate.eip_nat} <= set(eips)
    base = mount.path("ec2", "elastic-ips", estate.eip_web)
    assert mount.text(f"{base}/public-ip") == f"{estate.eip_web_ip}\n"


def test_network_interface_files(mount: Any, estate: Any,
                                 seedlib: ModuleType) -> None:
    """ENI files and TagSet-based tags."""
    resp = ec2(estate).describe_network_interfaces(
        NetworkInterfaceIds=[estate.eni_extra])
    item = resp["NetworkInterfaces"][0]
    base = mount.path("ec2", "network-interfaces", estate.eni_extra)
    assert mount.text(f"{base}/private-ip") == \
        f"{item['PrivateIpAddress']}\n"
    assert mount.text(f"{base}/status").strip() in ("in-use", "available")
    assert "interface-type" in mount.ls(base)
    assert mount.text(f"{base}/tags/Name") == f"{seedlib.ENI_NAME}\n"
    assert mount.text(f"{base}/name") == f"{seedlib.ENI_NAME}\n"
    assert json.loads(mount.text(f"{base}/describe.json")) == \
        canonical(item)


def test_amis_owned_only(mount: Any, estate: Any,
                         seedlib: ModuleType) -> None:
    """Golden AMI listed (name, state); public base AMI is not."""
    amis = mount.ls(mount.path("ec2", "amis"))
    assert estate.image_golden in amis
    assert estate.base_image not in amis
    base = mount.path("ec2", "amis", estate.image_golden)
    assert mount.text(f"{base}/name") == f"{seedlib.GOLDEN_IMAGE_NAME}\n"
    assert mount.text(f"{base}/state") == "available\n"


def test_every_resource_has_describe_json(mount: Any) -> None:
    """Each ec2 resource dir has a JSON-object describe.json."""
    for coll in EC2_COLLECTIONS:
        path = mount.path("ec2", coll)
        names = mount.ls(path)
        assert names, coll
        for name in names:
            assert isinstance(mount.vfs.resolve(f"{path}/{name}"), DirNode)
            assert isinstance(mount.json(f"{path}/{name}/describe.json"),
                              dict)
    assert mount.errors() == ""


def test_launch_templates_listing_is_one_call(mount: Any) -> None:
    before = mount.calls()
    mount.ls(mount.path("ec2", "launch-templates"))
    assert mount.calls() - before == 1


def test_launch_template_files(mount: Any, seed: Any) -> None:
    """Dirs are named by template name; the id and ARN come from AWS."""
    svc = seed.services
    assert mount.ls(mount.path("ec2", "launch-templates")) == [
        svc.launch_template_name]
    d = mount.path("ec2", "launch-templates", svc.launch_template_name)
    assert mount.json(f"{d}/describe.json")["LaunchTemplateId"] == \
        svc.launch_template_id
    assert mount.text(f"{d}/arn") == (
        f"arn:aws:ec2:{svc.region}:{svc.account_id}:launch-template/"
        f"{svc.launch_template_id}\n")
    assert mount.text(f"{d}/default-version") == "1\n"
    assert mount.text(f"{d}/latest-version") == "1\n"
    assert mount.json(f"{d}/tags.json")["team"] == "platform"


@pytest.mark.parametrize("revealed", [False, True])
def test_launch_template_user_data_is_never_read(
        make_mount: Callable[..., Any], seed: Any, seedlib: ModuleType,
        revealed: bool) -> None:
    """Template versions hold the user data: they are not exposed, even
    with --reveal."""
    m = make_mount(reveal=revealed)
    d = m.path("ec2", "launch-templates", seed.services.launch_template_name)
    assert not [n for n in m.ls(d) if "version" in n and "." in n
                and n.endswith(".json")]
    hits = list(grep(m.vfs, seedlib.FAKE_SECRET,
                     [m.path("ec2", "launch-templates")], recursive=True))
    assert hits == []
