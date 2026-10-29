"""Redshift provider (clusters) over the seeded estate."""

from __future__ import annotations

from typing import Any

CLUSTERS = "redshift/clusters"


def test_listing_is_one_call(mount: Any, seed: Any) -> None:
    before = mount.calls()
    assert mount.ls(mount.path(CLUSTERS)) == [seed.services.redshift_cluster]
    assert mount.calls() - before == 1


def test_cluster_files_and_tags(mount: Any, seed: Any,
                                seedlib: Any) -> None:
    name = seed.services.redshift_cluster
    d = mount.path(f"{CLUSTERS}/{name}")
    doc = mount.json(f"{d}/describe.json")
    assert doc["ClusterIdentifier"] == name
    assert seedlib.FAKE_SECRET not in str(doc)
    assert mount.text(f"{d}/status") == "available\n"
    assert mount.text(f"{d}/node-type") == "dc2.large\n"
    assert ".redshift." in mount.text(f"{d}/endpoint")
    assert mount.text(f"{d}/arn") == (
        f"arn:aws:redshift:{seed.services.region}:"
        f"{seed.services.account_id}:cluster:{name}\n")
    assert mount.json(f"{d}/tags.json")["team"] == "platform"


def test_security_group_link(mount: Any, seed: Any) -> None:
    sg = seed.ec2_vpc.sg_db
    d = mount.path(f"{CLUSTERS}/{seed.services.redshift_cluster}/links")
    assert mount.realpath(f"{d}/security-groups/{sg}") == mount.path(
        f"vpc/security-groups/{sg}")
