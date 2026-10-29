"""EC2 Auto Scaling provider over the seeded estate."""

from __future__ import annotations

from typing import Any

LAUNCH_TEMPLATES = "ec2/launch-templates"
GROUPS = "autoscaling/groups"


def test_listing_is_one_call(mount: Any) -> None:
    before = mount.calls()
    mount.ls(mount.path(GROUPS))
    assert mount.calls() - before == 1


def test_group_files_and_tags(mount: Any, seed: Any) -> None:
    svc = seed.services
    assert {svc.asg_name, svc.eks_asg_name} <= set(
        mount.ls(mount.path(GROUPS)))
    d = mount.path(f"{GROUPS}/{svc.asg_name}")
    doc = mount.json(f"{d}/describe.json")
    assert doc["AutoScalingGroupName"] == svc.asg_name
    assert mount.text(f"{d}/arn") == doc["AutoScalingGroupARN"] + "\n"
    assert mount.text(f"{d}/arn").startswith("arn:aws:autoscaling:")
    assert mount.text(f"{d}/min-size") == "0\n"
    assert mount.text(f"{d}/max-size") == "1\n"
    assert mount.json(f"{d}/tags.json")["team"] == "platform"


def test_group_links(mount: Any, seed: Any) -> None:
    svc = seed.services
    links = mount.path(f"{GROUPS}/{svc.asg_name}/links")
    assert mount.realpath(f"{links}/launch-template") == mount.path(
        f"{LAUNCH_TEMPLATES}/{svc.launch_template_name}")
    subnets = mount.ls(f"{links}/subnets")
    assert subnets == [seed.ec2_vpc.subnet_private]
    assert mount.realpath(f"{links}/subnets/{subnets[0]}") == mount.path(
        f"vpc/subnets/{seed.ec2_vpc.subnet_private}")
    groups = mount.ls(f"{links}/target-groups")
    assert len(groups) == 1
    assert mount.realpath(f"{links}/target-groups/{groups[0]}") == \
        mount.path(f"elbv2/target-groups/{groups[0]}")
