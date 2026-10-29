"""CloudFormation provider and type map against moto (docs/coverage.md)."""

from __future__ import annotations

import errno
import importlib.util
import json
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from awsmount.errors import PermissionDenied
from awsmount.providers import ProviderRegistry, cfn_types, refs
from awsmount.providers.base import CollectionRef
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
management = kit.management

STACKS = "cloudformation/stacks"
STACK = f"{STACKS}/{seed.STACK_NAME}"
RESOURCES = f"{STACK}/resources"

# Logical ids declared in the seeded stack template.
TEMPLATE_RESOURCES = ("AppLogs", "Handle", "WebSG")

CORE_TYPES: dict[str, CollectionRef] = {
    "AWS::EC2::Instance": refs.INSTANCES,
    "AWS::EC2::SecurityGroup": refs.SECURITY_GROUPS,
    "AWS::EC2::Subnet": refs.SUBNETS,
    "AWS::EC2::VPC": refs.VPCS,
    "AWS::ECS::Cluster": refs.ECS_CLUSTERS,
    "AWS::ElasticLoadBalancingV2::LoadBalancer": refs.LOAD_BALANCERS,
    "AWS::KMS::Key": refs.KMS_KEYS,
    "AWS::Lambda::Function": refs.LAMBDA_FUNCTIONS,
    "AWS::Logs::LogGroup": refs.LOG_GROUPS,
    "AWS::RDS::DBInstance": refs.RDS_INSTANCES,
}

MOTO_WAIT_HANDLE_GAP = (
    "moto does not model AWS::CloudFormation::WaitConditionHandle: "
    "ListStackResources returns it with an empty LogicalResourceId")


def _params(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {r["ParameterKey"]: r.get("ParameterValue") for r in rows}


def _type_map() -> Mapping[str, CollectionRef]:
    """The largest ``AWS::*`` -> CollectionRef mapping in cfn_types."""
    found: list[Mapping[str, CollectionRef]] = []
    for value in vars(cfn_types).values():
        if not isinstance(value, Mapping) or not value:
            continue
        keys_ok = all(isinstance(k, str) and k.startswith("AWS::")
                      for k in value)
        values_ok = all(isinstance(v, CollectionRef)
                        for v in value.values())
        if keys_ok and values_ok:
            found.append(value)
    assert found, "cfn_types defines no CloudFormation type map"
    return max(found, key=len)


# -- the CloudFormation type -> CollectionRef map ---------------------


def test_type_map_is_well_formed() -> None:
    mapping = _type_map()
    pattern = re.compile(r"^AWS::[A-Za-z0-9]+::[A-Za-z0-9]+$")
    known = {v for v in vars(refs).values()
             if isinstance(v, CollectionRef)}
    registry = ProviderRegistry()
    for cfn_type, ref in mapping.items():
        assert pattern.match(cfn_type), cfn_type
        assert ref in known, (cfn_type, ref)
        if registry.service(ref.scope, ref.service) is not None:
            assert registry.collection(ref) is not None, (cfn_type, ref)


@pytest.mark.parametrize("cfn_type,ref", sorted(CORE_TYPES.items()))
def test_type_map_core_entries(cfn_type: str, ref: CollectionRef) -> None:
    assert _type_map().get(cfn_type) == ref


def test_type_map_ignores_unmapped_types() -> None:
    mapping = _type_map()
    assert "AWS::CloudFormation::WaitConditionHandle" not in mapping


# -- stacks -----------------------------------------------------------


def test_listing_one_call_and_describe_derived(management: Any) -> None:
    m = kit.Mount()
    before = m.calls()
    assert m.ls(m.path(STACKS)) == [seed.STACK_NAME]
    assert m.calls() - before == 1
    listed = m.calls()
    doc = m.json(m.path(f"{STACK}/describe.json"))
    assert doc["StackName"] == seed.STACK_NAME
    assert doc["StackId"] == management.stack_id
    assert doc["StackStatus"] == "CREATE_COMPLETE"
    assert "ResponseMetadata" not in doc
    assert m.calls() == listed


def test_stack_files(management: Any) -> None:
    m = kit.Mount()
    assert m.text(m.path(f"{STACK}/status")) == "CREATE_COMPLETE\n"
    outputs = m.text(m.path(f"{STACK}/outputs.json"))
    assert management.stack_sg_id
    assert management.stack_sg_id in outputs
    assert seed.STACK_OUTPUT_SG in outputs
    assert m.json(m.path(f"{STACK}/tags.json")) == dict(
        sorted(seed.STACK_TAGS.items()))
    assert m.text(m.path(f"{STACK}/tags/Environment")) == "prod\n"


def test_secret_parameters_redacted(management: Any) -> None:
    m = kit.Mount()
    raw = m.text(m.path(f"{STACK}/parameters.json"))
    assert kit.FAKE_SECRET not in raw
    params = _params(json.loads(raw))
    assert params["DbPassword"] == REDACTED
    assert params["Environment"] == seed.STACK_ENVIRONMENT
    assert params["VpcId"] == management.network.vpc_main
    describe = m.text(m.path(f"{STACK}/describe.json"))
    assert kit.FAKE_SECRET not in describe
    described = _params(json.loads(describe)["Parameters"])
    assert described["DbPassword"] == REDACTED
    assert described["Environment"] == seed.STACK_ENVIRONMENT


def test_reveal_shows_secret_parameters(management: Any) -> None:
    m = kit.Mount(reveal=True)
    params = _params(m.json(m.path(f"{STACK}/parameters.json")))
    assert params["DbPassword"] == kit.FAKE_SECRET


def test_template_whole_file_redacted_without_api_call(
        management: Any) -> None:
    m = kit.Mount()
    m.ls(m.path(STACK))
    before = m.calls()
    assert m.read(m.path(f"{STACK}/template")) == \
        (REDACTED + "\n").encode("utf-8")
    assert m.calls() == before


def test_template_revealed_costs_one_call(management: Any) -> None:
    m = kit.Mount(reveal=True)
    m.ls(m.path(STACK))
    before = m.calls()
    template = m.text(m.path(f"{STACK}/template"))
    assert m.calls() - before == 1
    assert "AWS::EC2::SecurityGroup" in template
    assert seed.STACK_LOG_GROUP in template


def test_stack_role_link(management: Any) -> None:
    m = kit.Mount()
    links = m.path(f"{STACK}/links")
    if m.mounted(refs.IAM_ROLES):
        assert m.target(f"{links}/role") == m.gpath(
            f"iam/roles/{seed.CFN_ROLE_NAME}")
    else:
        assert "role" not in m.ls(links)


# -- nested stack resources -------------------------------------------


def test_resources_listing_and_files(management: Any) -> None:
    m = kit.Mount()
    m.ls(m.path(STACK))
    before = m.calls()
    listing = m.ls(m.path(RESOURCES))
    assert m.calls() - before == 1
    assert len(listing) == len(TEMPLATE_RESOURCES)
    assert {"AppLogs", "WebSG"} <= set(listing)
    web = f"{RESOURCES}/WebSG"
    assert m.text(m.path(f"{web}/type")) == "AWS::EC2::SecurityGroup\n"
    assert m.text(m.path(f"{web}/physical-id")).strip() == \
        management.stack_sg_id
    assert m.text(m.path(f"{web}/status")) == "CREATE_COMPLETE\n"
    logs = f"{RESOURCES}/AppLogs"
    assert m.text(m.path(f"{logs}/type")) == "AWS::Logs::LogGroup\n"
    assert m.text(m.path(f"{logs}/physical-id")).strip() == \
        seed.STACK_LOG_GROUP


@pytest.mark.xfail(strict=True, reason=MOTO_WAIT_HANDLE_GAP)
def test_unmapped_resource_listed_without_target(management: Any) -> None:
    m = kit.Mount()
    assert m.ls(m.path(RESOURCES)) == list(TEMPLATE_RESOURCES)
    handle_links = m.path(f"{RESOURCES}/Handle/links")
    assert "target" not in m.ls(handle_links)


def test_resource_target_links(management: Any) -> None:
    m = kit.Mount()
    web_links = m.path(f"{RESOURCES}/WebSG/links")
    assert m.target(f"{web_links}/target") == m.path(
        f"vpc/security-groups/{management.stack_sg_id}")
    assert not m.vfs.readlink(f"{web_links}/target").startswith("/")
    if m.mounted(refs.LOG_GROUPS):
        log_links = m.path(f"{RESOURCES}/AppLogs/links")
        assert m.target(f"{log_links}/target") == m.path(
            "logs/log-groups/" + escape_name(seed.STACK_LOG_GROUP))


def test_access_denied_listing_degrades_to_empty_dir(
        management: Any) -> None:
    m = kit.Mount()
    m.deny("cloudformation", "DescribeStacks")
    assert m.ls(m.path(STACKS)) == []
    lines = m.denied("cloudformation")
    assert len(lines) == 1
    assert lines[0][4] == "describe_stacks"
    assert management.network.vpc_main in m.ls(m.path("vpc/vpcs"))


def test_access_denied_on_lazy_template_is_eacces(
        management: Any) -> None:
    m = kit.Mount(reveal=True)
    m.deny("cloudformation", "GetTemplate")
    with pytest.raises(PermissionDenied) as info:
        m.read(m.path(f"{STACK}/template"))
    assert info.value.errno == errno.EACCES
    assert m.denied("cloudformation", "get_template")
    assert m.text(m.path(f"{STACK}/status")) == "CREATE_COMPLETE\n"
