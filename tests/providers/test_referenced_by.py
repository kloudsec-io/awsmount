"""``security-groups/<id>/referenced-by/``.

See ARCHITECTURE: Links and referenced-by.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from awsmount.providers import refs
from awsmount.vfs.node import DirNode


def refdir(m: Any, group: str) -> str:
    """Path of a group's referenced-by directory."""
    return m.path("vpc", "security-groups", group, "referenced-by")


def test_app_group_dependents(mount: Any, estate: Any) -> None:
    """Instance, ENI and other groups' rules all point at sg-app."""
    entries = set(mount.ls(refdir(mount, estate.sg_app)))
    expected = {
        f"ec2-instances-{estate.instance_app}": mount.path(
            "ec2", "instances", estate.instance_app),
        f"ec2-network-interfaces-{estate.eni_extra}": mount.path(
            "ec2", "network-interfaces", estate.eni_extra),
        f"vpc-security-groups-{estate.sg_web}": mount.path(
            "vpc", "security-groups", estate.sg_web),
        f"vpc-security-groups-{estate.sg_db}": mount.path(
            "vpc", "security-groups", estate.sg_db),
    }
    assert set(expected) <= entries, entries
    for name, target in expected.items():
        assert mount.realpath(f"{refdir(mount, estate.sg_app)}/{name}") \
            == target


def test_exact_relative_targets(mount: Any, estate: Any) -> None:
    """Targets match the documented example shapes."""
    base = refdir(mount, estate.sg_app)
    assert mount.readlink(
        f"{base}/ec2-instances-{estate.instance_app}") == \
        f"../../../../ec2/instances/{estate.instance_app}"
    assert mount.readlink(
        f"{base}/vpc-security-groups-{estate.sg_web}") == \
        f"../../{estate.sg_web}"


def test_web_group_dependents(mount: Any, estate: Any) -> None:
    """sg-web: web + builder instances and sg-app's rule."""
    entries = set(mount.ls(refdir(mount, estate.sg_web)))
    assert {f"ec2-instances-{estate.instance_web}",
            f"ec2-instances-{estate.instance_builder}",
            f"vpc-security-groups-{estate.sg_app}"} <= entries
    assert f"ec2-instances-{estate.instance_app}" not in entries


def test_db_group_referenced_by_endpoint(mount: Any, estate: Any) -> None:
    """Interface endpoint and sg-app's... no: sg-db is used by both."""
    entries = set(mount.ls(refdir(mount, estate.sg_db)))
    name = f"vpc-endpoints-{estate.vpce_interface}"
    assert name in entries
    assert mount.realpath(f"{refdir(mount, estate.sg_db)}/{name}") == \
        mount.path("vpc", "endpoints", estate.vpce_interface)
    assert not any(e.startswith("ec2-instances-") for e in entries)


def test_unreferenced_group_is_empty(mount: Any, estate: Any) -> None:
    """Nothing uses sg-lonely."""
    assert mount.ls(refdir(mount, estate.sg_lonely)) == []


def test_every_entry_is_a_real_reference(mount: Any) -> None:
    """Each entry resolves, and the source actually names the group."""
    groups = mount.ls(mount.path("vpc", "security-groups"))
    checked = 0
    for group in groups:
        base = refdir(mount, group)
        for name in mount.ls(base):
            node = mount.vfs.resolve(f"{base}/{name}")
            assert isinstance(node, DirNode), name
            describe = mount.text(f"{base}/{name}/describe.json")
            assert group in describe, (group, name)
            checked += 1
    assert checked >= 8


def test_build_cost_is_one_list_per_source(
        seed: Any, estate: Any, make_mount: Callable[..., Any],
        op_log: list[tuple[str, str]]) -> None:
    """One cached list call per mounted source, then zero."""
    m = make_mount()
    m.ls(m.path("vpc", "security-groups"))
    spec = m.ctx.registry.collection(refs.SECURITY_GROUPS)
    assert spec is not None
    mounted = [s.source for s in spec.referenced_by
               if m.ctx.registry.collection(s.source) is not None]
    expected = len([r for r in mounted if r != refs.SECURITY_GROUPS])
    op_log.clear()
    before = m.calls()
    m.ls(refdir(m, estate.sg_app))
    assert m.calls() - before == expected
    assert len(op_log) == expected == len(set(op_log)), op_log
    before = m.calls()
    for group in (estate.sg_web, estate.sg_db, estate.sg_lonely):
        m.ls(refdir(m, group))
    assert m.calls() == before


def test_unmounted_sources_are_skipped(
        seed: Any, estate: Any, make_mount: Callable[..., Any]) -> None:
    """With ec2 not mounted only vpc-* entries remain."""
    m = make_mount(services=frozenset({"vpc"}))
    entries = m.ls(refdir(m, estate.sg_app))
    assert entries
    assert all(e.startswith("vpc-") for e in entries), entries
