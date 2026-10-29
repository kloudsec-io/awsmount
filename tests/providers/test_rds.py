"""RDS provider against moto (redaction rule ``rds``)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

from awsmount.providers import refs
from awsmount.session.redact import REDACTED
from awsmount.vfs.path import escape_name


def _load_kit() -> ModuleType:
    """Load tests/providers/motokit.py by path (any import mode)."""
    name = "awsmount_tests_motokit"
    module = sys.modules.get(name)
    if module is None:
        path = Path(__file__).resolve().with_name("motokit.py")
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return module


kit = _load_kit()
seed = kit.seed
moto_session = kit.moto_session
compute = kit.compute

INSTANCES = "rds/instances"
CLUSTERS = "rds/clusters"
PG = f"{INSTANCES}/{seed.RDS_INSTANCE}"
MEMBER = f"{INSTANCES}/{seed.RDS_CLUSTER_MEMBER}"
AURORA = f"{CLUSTERS}/{seed.RDS_CLUSTER}"


def test_instances_listing_one_call_describe_derived(
        compute: Any) -> None:
    m = kit.Mount()
    before = m.calls()
    assert m.ls(m.path(INSTANCES)) == sorted(
        [seed.RDS_INSTANCE, seed.RDS_CLUSTER_MEMBER])
    assert m.calls() - before == 1
    listed = m.calls()
    doc = m.json(m.path(f"{PG}/describe.json"))
    assert doc["DBInstanceIdentifier"] == seed.RDS_INSTANCE
    assert doc["Engine"] == "postgres"
    assert doc["MasterUsername"] == seed.RDS_MASTER_USER
    assert "ResponseMetadata" not in doc
    m.json(m.path(f"{MEMBER}/describe.json"))
    assert m.calls() == listed


def test_instance_files(compute: Any) -> None:
    m = kit.Mount()
    doc = m.json(m.path(f"{PG}/describe.json"))
    assert m.text(m.path(f"{PG}/engine")) == "postgres\n"
    assert m.text(m.path(f"{PG}/status")) == "available\n"
    endpoint = m.text(m.path(f"{PG}/endpoint")).strip()
    assert seed.RDS_INSTANCE in endpoint
    assert m.text(m.path(f"{PG}/arn")).strip() == doc["DBInstanceArn"]


def test_inline_tags_cost_no_call(compute: Any) -> None:
    m = kit.Mount()
    m.ls(m.path(PG))
    before = m.calls()
    assert m.json(m.path(f"{PG}/tags.json")) == dict(
        sorted(seed.RDS_TAGS.items()))
    assert m.text(m.path(f"{PG}/tags/team")) == "data\n"
    assert m.calls() == before


def test_master_password_is_never_served(compute: Any) -> None:
    m = kit.Mount()
    for rel in (PG, MEMBER, AURORA):
        assert m.grep(m.path(rel), kit.FAKE_SECRET) == []
    for rel in (INSTANCES, CLUSTERS):
        assert m.grep(m.path(rel), kit.FAKE_SECRET) == []


def test_rds_rule_redacts_injected_password(
        compute: Any, moto_session: Any) -> None:
    client = moto_session.client("rds", region_name=kit.REGION)
    item = client.describe_db_instances(
        DBInstanceIdentifier=seed.RDS_INSTANCE)["DBInstances"][0]
    item["MasterUserPassword"] = kit.FAKE_SECRET
    m = kit.Mount()
    for ref in (refs.RDS_INSTANCES, refs.RDS_CLUSTERS):
        spec = m.ctx.registry.collection(ref)
        assert spec is not None, ref
        out = m.ctx.redaction.json(spec.redact, item)
        assert out["MasterUserPassword"] == REDACTED
        assert out["DBInstanceIdentifier"] == seed.RDS_INSTANCE
        assert item["MasterUserPassword"] == kit.FAKE_SECRET
    revealed = kit.Mount(reveal=True)
    spec = revealed.ctx.registry.collection(refs.RDS_INSTANCES)
    assert spec is not None
    out = revealed.ctx.redaction.json(spec.redact, item)
    assert out["MasterUserPassword"] == kit.FAKE_SECRET


def test_instance_links(compute: Any) -> None:
    m = kit.Mount()
    net = compute.network
    links = m.path(f"{PG}/links")
    assert m.target(f"{links}/vpc") == m.path(f"vpc/vpcs/{net.vpc_main}")
    assert m.targets(f"{links}/subnets") == {
        m.path(f"vpc/subnets/{net.subnet_public}"),
        m.path(f"vpc/subnets/{net.subnet_private}")}
    assert m.targets(f"{links}/security-groups") == {
        m.path(f"vpc/security-groups/{net.sg_db}")}
    assert m.relative_links(f"{links}/security-groups")
    assert "cluster" not in m.ls(links)
    member_links = m.path(f"{MEMBER}/links")
    assert m.target(f"{member_links}/cluster") == m.path(AURORA)


def test_cluster_files_and_links(compute: Any) -> None:
    m = kit.Mount()
    before = m.calls()
    assert m.ls(m.path(CLUSTERS)) == [seed.RDS_CLUSTER]
    assert m.calls() - before == 1
    doc = m.json(m.path(f"{AURORA}/describe.json"))
    assert doc["DBClusterIdentifier"] == seed.RDS_CLUSTER
    assert m.text(m.path(f"{AURORA}/engine")) == "aurora-postgresql\n"
    assert m.text(m.path(f"{AURORA}/status")).strip()
    links = m.path(f"{AURORA}/links")
    assert m.targets(f"{links}/instances") == {m.path(MEMBER)}
    assert m.targets(f"{links}/security-groups") == {
        m.path(f"vpc/security-groups/{compute.network.sg_db}")}


def test_security_group_referenced_by_instance(compute: Any) -> None:
    m = kit.Mount()
    refby = m.path(
        f"vpc/security-groups/{compute.network.sg_db}/referenced-by")
    entry = escape_name(f"rds-instances-{seed.RDS_INSTANCE}")
    assert entry in m.ls(refby)
    assert m.target(f"{refby}/{entry}") == m.path(PG)


def test_access_denied_listing_degrades_to_empty_dir(
        compute: Any) -> None:
    m = kit.Mount()
    m.deny("rds", "DescribeDBInstances")
    assert m.ls(m.path(INSTANCES)) == []
    lines = m.denied("rds")
    assert len(lines) == 1
    assert lines[0][4] == "describe_db_instances"
    assert m.ls(m.path(CLUSTERS)) == [seed.RDS_CLUSTER]


def test_members_come_from_the_cluster_listing(compute: Any) -> None:
    m = kit.Mount()
    m.ls(m.path(CLUSTERS))
    before = m.calls()
    members = m.path(f"{AURORA}/members")
    assert m.ls(members) == [seed.RDS_CLUSTER_MEMBER]
    assert m.calls() == before
    d = f"{members}/{seed.RDS_CLUSTER_MEMBER}"
    doc = m.json(f"{d}/describe.json")
    assert doc["DBInstanceIdentifier"] == seed.RDS_CLUSTER_MEMBER
    assert m.text(f"{d}/role") in ("writer\n", "reader\n")
    assert m.text(f"{d}/promotion-tier") == f"{doc['PromotionTier']}\n"


def test_member_links(compute: Any) -> None:
    m = kit.Mount()
    links = m.path(f"{AURORA}/members/{seed.RDS_CLUSTER_MEMBER}/links")
    assert m.target(f"{links}/instance") == m.path(MEMBER)
    assert m.target(f"{links}/cluster") == m.path(AURORA)
    assert m.relative_links(links)
