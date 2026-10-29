"""Relationship symlinks over the seeded estate.

See ARCHITECTURE: Links and referenced-by.
"""

from __future__ import annotations

import posixpath
from collections.abc import Callable
from typing import Any

from awsmount.errors import NotFound
from awsmount.vfs.node import DirNode, SymlinkNode


def assert_link(m: Any, link: str, expected: str) -> None:
    """``link`` is relative and resolves to the directory ``expected``."""
    target = m.readlink(link)
    assert not target.startswith("/"), target
    joined = posixpath.normpath(
        posixpath.join(posixpath.dirname(link), target))
    assert joined == expected
    assert m.realpath(link) == expected
    assert isinstance(m.vfs.resolve(link), DirNode)


def many(m: Any, path: str) -> list[str]:
    """Entries of a ``many`` link directory."""
    return m.ls(path)


def test_instance_subnet_link_exact_target(mount: Any, estate: Any) -> None:
    """Documented example: subnet -> ../../../../vpc/subnets/<id>."""
    link = mount.path("ec2", "instances", estate.instance_web, "links",
                      "subnet")
    assert mount.readlink(link) == \
        f"../../../../vpc/subnets/{estate.subnet_public}"
    assert_link(mount, link,
                mount.path("vpc", "subnets", estate.subnet_public))


def test_instance_single_links(mount: Any, estate: Any) -> None:
    """vpc, image (owned AMI) and key-pair links."""
    links = mount.path("ec2", "instances", estate.instance_web, "links")
    assert_link(mount, f"{links}/vpc",
                mount.path("vpc", "vpcs", estate.vpc_main))
    assert mount.readlink(f"{links}/image") == \
        f"../../../amis/{estate.image_golden}"
    assert_link(mount, f"{links}/image",
                mount.path("ec2", "amis", estate.image_golden))
    assert mount.readlink(f"{links}/key-pair") == \
        f"../../../key-pairs/{estate.key_name}"
    assert_link(mount, f"{links}/key-pair",
                mount.path("ec2", "key-pairs", estate.key_name))


def test_instance_link_entries(mount: Any, estate: Any) -> None:
    """Every documented instance link is present."""
    links = mount.path("ec2", "instances", estate.instance_web, "links")
    assert set(mount.ls(links)) == {
        "subnet", "vpc", "image", "key-pair", "security-groups",
        "volumes", "network-interfaces"}


def test_link_to_unowned_ami_is_omitted(mount: Any, estate: Any) -> None:
    """The builder runs a public AMI that is not listed: no link."""
    links = mount.path("ec2", "instances", estate.instance_builder,
                       "links")
    assert "image" not in mount.ls(links)


def test_instance_security_groups_many(mount: Any, estate: Any) -> None:
    """many-links are a dir of id-named relative symlinks."""
    sgs = mount.path("ec2", "instances", estate.instance_web, "links",
                     "security-groups")
    assert many(mount, sgs) == [estate.sg_web]
    link = f"{sgs}/{estate.sg_web}"
    assert mount.readlink(link) == \
        f"../../../../../vpc/security-groups/{estate.sg_web}"
    assert_link(mount, link,
                mount.path("vpc", "security-groups", estate.sg_web))


def test_instance_network_interfaces(mount: Any, estate: Any) -> None:
    """The secondary ENI attached to app-1 is linked."""
    enis = mount.path("ec2", "instances", estate.instance_app, "links",
                      "network-interfaces")
    assert estate.eni_extra in many(mount, enis)
    assert_link(mount, f"{enis}/{estate.eni_extra}",
                mount.path("ec2", "network-interfaces", estate.eni_extra))


def test_instance_volumes(mount: Any, estate: Any) -> None:
    """Volume links exist and all land in ec2/volumes."""
    vols = mount.path("ec2", "instances", estate.instance_web, "links",
                      "volumes")
    entries = many(mount, vols)
    assert entries
    for name in entries:
        assert_link(mount, f"{vols}/{name}",
                    mount.path("ec2", "volumes", name))


def test_volume_and_snapshot_links(mount: Any, estate: Any) -> None:
    """volume -> instances/, snapshot -> volume."""
    inst = mount.path("ec2", "volumes", estate.volume_data, "links",
                      "instances")
    assert many(mount, inst) == [estate.instance_web]
    assert_link(mount, f"{inst}/{estate.instance_web}",
                mount.path("ec2", "instances", estate.instance_web))
    assert_link(mount, mount.path("ec2", "snapshots",
                                  estate.snapshot_data, "links",
                                  "volume"),
                mount.path("ec2", "volumes", estate.volume_data))


def test_eip_and_eni_links(mount: Any, estate: Any) -> None:
    """elastic IP -> instance; ENI -> subnet, instance, SGs."""
    assert_link(mount, mount.path("ec2", "elastic-ips", estate.eip_web,
                                  "links", "instance"),
                mount.path("ec2", "instances", estate.instance_web))
    links = mount.path("ec2", "network-interfaces", estate.eni_extra,
                       "links")
    assert_link(mount, f"{links}/subnet",
                mount.path("vpc", "subnets", estate.subnet_private))
    assert_link(mount, f"{links}/vpc",
                mount.path("vpc", "vpcs", estate.vpc_main))
    assert_link(mount, f"{links}/instance",
                mount.path("ec2", "instances", estate.instance_app))
    assert many(mount, f"{links}/security-groups") == [estate.sg_app]


def test_security_group_links(mount: Any, estate: Any) -> None:
    """vpc link plus references/ to groups used in rules."""
    links = mount.path("vpc", "security-groups", estate.sg_app, "links")
    assert mount.readlink(f"{links}/vpc") == \
        f"../../../vpcs/{estate.vpc_main}"
    assert_link(mount, f"{links}/vpc",
                mount.path("vpc", "vpcs", estate.vpc_main))
    assert many(mount, f"{links}/references") == [estate.sg_web]
    assert mount.readlink(f"{links}/references/{estate.sg_web}") == \
        f"../../../{estate.sg_web}"
    lonely = mount.path("vpc", "security-groups", estate.sg_lonely,
                        "links", "references")
    assert many(mount, lonely) == []


def test_subnet_links(mount: Any, estate: Any) -> None:
    """subnet -> vpc (both VPCs)."""
    assert_link(mount, mount.path("vpc", "subnets", estate.subnet_peer,
                                  "links", "vpc"),
                mount.path("vpc", "vpcs", estate.vpc_peer))


def test_route_table_links(mount: Any, estate: Any) -> None:
    """Public and private route tables link their targets."""
    pub = mount.path("vpc", "route-tables", estate.rtb_public, "links")
    assert_link(mount, f"{pub}/vpc",
                mount.path("vpc", "vpcs", estate.vpc_main))
    assert many(mount, f"{pub}/subnets") == [estate.subnet_public]
    assert many(mount, f"{pub}/internet-gateways") == [estate.igw]
    assert many(mount, f"{pub}/peering-connections") == [estate.peering]
    assert_link(mount, f"{pub}/internet-gateways/{estate.igw}",
                mount.path("vpc", "internet-gateways", estate.igw))
    priv = mount.path("vpc", "route-tables", estate.rtb_private, "links")
    assert many(mount, f"{priv}/nat-gateways") == [estate.nat]
    assert many(mount, f"{priv}/subnets") == [estate.subnet_private]
    assert_link(mount, f"{priv}/nat-gateways/{estate.nat}",
                mount.path("vpc", "nat-gateways", estate.nat))


def test_gateway_links(mount: Any, estate: Any) -> None:
    """IGW -> vpcs/; NAT -> subnet, vpc, elastic-ips/."""
    assert many(mount, mount.path("vpc", "internet-gateways", estate.igw,
                                  "links", "vpcs")) == [estate.vpc_main]
    nat = mount.path("vpc", "nat-gateways", estate.nat, "links")
    assert_link(mount, f"{nat}/subnet",
                mount.path("vpc", "subnets", estate.subnet_public))
    assert_link(mount, f"{nat}/vpc",
                mount.path("vpc", "vpcs", estate.vpc_main))
    assert many(mount, f"{nat}/elastic-ips") == [estate.eip_nat]
    assert_link(mount, f"{nat}/elastic-ips/{estate.eip_nat}",
                mount.path("ec2", "elastic-ips", estate.eip_nat))


def test_network_acl_links(mount: Any, estate: Any) -> None:
    """Custom NACL -> vpc and its associated subnet."""
    links = mount.path("vpc", "network-acls", estate.nacl, "links")
    assert_link(mount, f"{links}/vpc",
                mount.path("vpc", "vpcs", estate.vpc_main))
    assert estate.subnet_public in many(mount, f"{links}/subnets")


def test_endpoint_links(mount: Any, estate: Any) -> None:
    """Gateway endpoint -> route-tables; interface -> SGs, subnets."""
    gw = mount.path("vpc", "endpoints", estate.vpce_gateway, "links")
    assert_link(mount, f"{gw}/vpc",
                mount.path("vpc", "vpcs", estate.vpc_main))
    assert many(mount, f"{gw}/route-tables") == [estate.rtb_private]
    itf = mount.path("vpc", "endpoints", estate.vpce_interface, "links")
    assert many(mount, f"{itf}/security-groups") == [estate.sg_db]
    assert many(mount, f"{itf}/subnets") == [estate.subnet_private]


def test_peering_links(mount: Any, estate: Any) -> None:
    """ARN-scoped requester/accepter links resolve locally."""
    links = mount.path("vpc", "peering-connections", estate.peering,
                       "links")
    assert_link(mount, f"{links}/requester-vpc",
                mount.path("vpc", "vpcs", estate.vpc_main))
    assert_link(mount, f"{links}/accepter-vpc",
                mount.path("vpc", "vpcs", estate.vpc_peer))


def test_no_dangling_or_absolute_symlinks(mount: Any) -> None:
    """Every symlink is relative and lands inside a mounted collection.

    Links to ``global`` collections (for example a
    stack or function role in ``iam/roles``) point to
    ``/<acct>/global/...``, so targets must stay inside the account
    directory, not necessarily inside the region. Id-keyed
    collections compute the dirname with ``escape_name(key)``
    and make no API call, so a link may point to a resource that no
    longer exists (e.g. a snapshot whose source volume was deleted,
    which moto's ``create_image`` produces). Such a link must still be
    relative, stay inside the account, and point into an existing,
    mounted collection directory. Every link that resolves must resolve
    to a directory.
    """
    account_root = posixpath.dirname(mount.base)
    resolved = 0
    resolved_outside_snapshots = 0
    for path, node in mount.vfs.walk(mount.base):
        if not isinstance(node, SymlinkNode):
            continue
        target_text = node.readlink()
        assert not target_text.startswith("/"), path
        joined = posixpath.normpath(
            posixpath.join(posixpath.dirname(path), target_text))
        assert joined.startswith(account_root + "/"), path
        try:
            target = mount.vfs.resolve(path)
        except NotFound:
            collection = posixpath.dirname(joined)
            assert isinstance(mount.vfs.resolve(collection), DirNode), path
            continue
        resolved += 1
        if "/ec2/snapshots/" not in path:
            resolved_outside_snapshots += 1
        assert isinstance(target, DirNode), path
        assert target.path.startswith(account_root + "/"), path
        assert target.path == joined, path
    assert resolved > 20
    assert resolved_outside_snapshots > 0


def test_links_to_unmounted_service_are_omitted(
        seed: Any, estate: Any, make_mount: Callable[..., Any]) -> None:
    """With only ec2 mounted, VPC-family links disappear cleanly."""
    m = make_mount(services=frozenset({"ec2"}))
    assert m.ls(m.base) == ["ec2"]
    links = m.path("ec2", "instances", estate.instance_web, "links")
    names = m.ls(links)
    assert "subnet" not in names and "vpc" not in names
    assert m.ls(f"{links}/security-groups") == []
    assert "key-pair" in names
    assert_link(m, f"{links}/key-pair",
                m.path("ec2", "key-pairs", estate.key_name))


def test_nodegroup_links_to_its_autoscaling_group(mount: Any,
                                                  seed: Any) -> None:
    """EKS reports the name of the group that runs the nodes."""
    c, svc = seed.compute, seed.services
    d = mount.path("eks", "clusters", c.eks_cluster, "nodegroups",
                   c.eks_nodegroup, "links")
    groups = many(mount, f"{d}/autoscaling-groups")
    assert groups == [svc.eks_asg_name]
    assert_link(mount, f"{d}/autoscaling-groups/{groups[0]}",
                mount.path("autoscaling", "groups", svc.eks_asg_name))
    assert "launch-template" not in mount.ls(d)  # no custom template
