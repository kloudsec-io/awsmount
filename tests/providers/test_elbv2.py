"""ELBv2 provider against moto (docs/coverage.md)."""

from __future__ import annotations

import errno
import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from awsmount.errors import PermissionDenied
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

LBS = "elbv2/load-balancers"
TGS = "elbv2/target-groups"
ALB = f"{LBS}/{seed.ALB_NAME}"
TG = f"{TGS}/{seed.TG_NAME}"


def test_listing_costs_one_call_and_describe_is_derived(
        compute: Any) -> None:
    m = kit.Mount()
    before = m.calls()
    assert m.ls(m.path(LBS)) == [seed.ALB_NAME]
    assert m.calls() - before == 1
    listed = m.calls()
    doc = m.json(m.path(f"{ALB}/describe.json"))
    assert doc["LoadBalancerArn"] == compute.alb_arn
    assert doc["LoadBalancerName"] == seed.ALB_NAME
    assert doc["Type"] == "application"
    assert doc["VpcId"] == compute.network.vpc_main
    assert "ResponseMetadata" not in doc
    assert m.calls() == listed


def test_load_balancer_derived_files(compute: Any) -> None:
    m = kit.Mount()
    assert m.text(m.path(f"{ALB}/dns-name")).strip() == compute.alb_dns
    assert m.text(m.path(f"{ALB}/type")) == "application\n"
    assert m.text(m.path(f"{ALB}/scheme")) == "internet-facing\n"
    assert m.text(m.path(f"{ALB}/arn")).strip() == compute.alb_arn


def test_listeners_and_attributes_are_lazy(compute: Any) -> None:
    m = kit.Mount()
    m.ls(m.path(ALB))
    before = m.calls()
    listeners = m.json(m.path(f"{ALB}/listeners.json"))
    assert m.calls() - before == 1
    assert [x["ListenerArn"] for x in listeners] == [compute.listener_arn]
    assert listeners[0]["Port"] == 80
    action = listeners[0]["DefaultActions"][0]
    assert action["Type"] == "forward"
    assert action["TargetGroupArn"] == compute.target_group_arn
    attributes = m.text(m.path(f"{ALB}/attributes.json"))
    assert "deletion_protection.enabled" in attributes


def test_load_balancer_tags_are_fetched_lazily(compute: Any) -> None:
    m = kit.Mount()
    m.ls(m.path(ALB))
    before = m.calls()
    assert m.json(m.path(f"{ALB}/tags.json")) == dict(
        sorted(seed.ALB_TAGS.items()))
    assert m.calls() - before == 1
    assert m.text(m.path(f"{ALB}/tags/Environment")) == "prod\n"


def test_load_balancer_links(compute: Any) -> None:
    m = kit.Mount()
    net = compute.network
    links = m.path(f"{ALB}/links")
    assert m.target(f"{links}/vpc") == m.path(f"vpc/vpcs/{net.vpc_main}")
    assert m.targets(f"{links}/subnets") == {
        m.path(f"vpc/subnets/{net.subnet_public}"),
        m.path(f"vpc/subnets/{net.subnet_private}")}
    assert m.targets(f"{links}/security-groups") == {
        m.path(f"vpc/security-groups/{net.sg_web}")}
    assert m.targets(f"{links}/target-groups") == {m.path(TG)}
    assert m.relative_links(f"{links}/target-groups")


def test_target_group_files(compute: Any) -> None:
    m = kit.Mount()
    assert m.ls(m.path(TGS)) == [seed.TG_NAME]
    doc = m.json(m.path(f"{TG}/describe.json"))
    assert doc["TargetGroupArn"] == compute.target_group_arn
    assert m.text(m.path(f"{TG}/protocol")) == "HTTP\n"
    assert m.text(m.path(f"{TG}/port")) == "80\n"
    assert m.text(m.path(f"{TG}/target-type")) == "instance\n"
    health = m.text(m.path(f"{TG}/health.json"))
    assert compute.network.instance_web in health
    attributes = m.text(m.path(f"{TG}/attributes.json"))
    assert "deregistration_delay.timeout_seconds" in attributes
    assert m.json(m.path(f"{TG}/tags.json")) == dict(
        sorted(seed.TG_TAGS.items()))


def test_target_group_links(compute: Any) -> None:
    m = kit.Mount()
    links = m.path(f"{TG}/links")
    assert m.target(f"{links}/vpc") == m.path(
        f"vpc/vpcs/{compute.network.vpc_main}")
    assert m.targets(f"{links}/load-balancers") == {m.path(ALB)}


def test_security_group_referenced_by_load_balancer(compute: Any) -> None:
    m = kit.Mount()
    refby = m.path(
        f"vpc/security-groups/{compute.network.sg_web}/referenced-by")
    entry = escape_name(f"elbv2-load-balancers-{seed.ALB_NAME}")
    assert entry in m.ls(refby)
    assert m.target(f"{refby}/{entry}") == m.path(ALB)
    db_refby = m.path(
        f"vpc/security-groups/{compute.network.sg_db}/referenced-by")
    assert entry not in m.ls(db_refby)


def test_access_denied_listing_degrades_to_empty_dir(
        compute: Any) -> None:
    m = kit.Mount()
    m.deny("elbv2", "DescribeLoadBalancers")
    assert m.ls(m.path(LBS)) == []
    lines = m.denied("elbv2")
    assert len(lines) == 1
    assert lines[0][4] == "describe_load_balancers"
    assert m.ls(m.path(TGS)) == [seed.TG_NAME]


def test_access_denied_on_lazy_file_is_eacces(compute: Any) -> None:
    m = kit.Mount()
    m.deny("elbv2", "DescribeTargetHealth")
    with pytest.raises(PermissionDenied) as info:
        m.read(m.path(f"{TG}/health.json"))
    assert info.value.errno == errno.EACCES
    assert m.denied("elbv2", "describe_target_health")
    assert m.text(m.path(f"{TG}/protocol")) == "HTTP\n"


LISTENERS = f"{ALB}/listeners"
LISTENER = f"{LISTENERS}/HTTP-80"
RULES = f"{LISTENER}/rules"


def test_listeners_one_call_and_derived_files(compute: Any) -> None:
    m = kit.Mount()
    m.ls(m.path(LBS))
    before = m.calls()
    assert m.ls(m.path(LISTENERS)) == ["HTTP-80"]
    assert m.calls() - before == 1
    doc = m.json(m.path(f"{LISTENER}/describe.json"))
    assert doc["ListenerArn"] == compute.listener_arn
    assert m.text(m.path(f"{LISTENER}/arn")) == compute.listener_arn + "\n"
    assert m.text(m.path(f"{LISTENER}/port")) == "80\n"
    assert m.text(m.path(f"{LISTENER}/protocol")) == "HTTP\n"
    assert m.calls() - before == 1  # describe.json is derived


def test_listener_links(compute: Any) -> None:
    m = kit.Mount()
    links = m.path(f"{LISTENER}/links")
    assert m.target(f"{links}/load-balancer") == m.path(ALB)
    assert m.targets(f"{links}/target-groups") == {m.path(TG)}
    assert m.relative_links(f"{links}/target-groups")


def test_rules(compute: Any) -> None:
    m = kit.Mount()
    rules = m.path(RULES)
    assert m.ls(rules) == ["10", "default"]
    rule = m.json(f"{rules}/10/describe.json")
    assert rule["RuleArn"] == compute.listener_rule_arn
    assert rule["Conditions"][0]["Field"] == "path-pattern"
    assert m.text(f"{rules}/10/priority") == "10\n"
    assert m.text(f"{rules}/10/arn") == compute.listener_rule_arn + "\n"
    assert m.json(f"{rules}/default/describe.json")["IsDefault"] is True
    assert m.targets(f"{rules}/10/links/target-groups") == {m.path(TG)}


def test_access_denied_on_listeners_degrades_to_empty_dir(
        compute: Any) -> None:
    m = kit.Mount()
    m.deny("elbv2", "DescribeListeners")
    assert m.ls(m.path(LISTENERS)) == []
    assert m.denied("elbv2", "describe_listeners")
    assert m.ls(m.path(TGS)) == [seed.TG_NAME]


def test_access_denied_on_rules_degrades_to_empty_dir(
        compute: Any) -> None:
    m = kit.Mount()
    m.deny("elbv2", "DescribeRules")
    assert m.ls(m.path(RULES)) == []
    assert m.denied("elbv2", "describe_rules")
