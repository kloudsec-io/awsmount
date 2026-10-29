"""Lambda provider against moto (redaction rule ``lambda``)."""

from __future__ import annotations

import errno
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from awsmount.errors import PermissionDenied
from awsmount.providers import refs
from awsmount.session.redact import REDACTED, RedactionPolicy
from awsmount.vfs.path import escape_name
from awsmount.vfs.render import to_json_text


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

FUNCTIONS = "lambda/functions"
API = f"{FUNCTIONS}/{seed.LAMBDA_API}"
WORKER = f"{FUNCTIONS}/{seed.LAMBDA_WORKER}"


def test_listing_costs_one_call_and_describe_is_derived(
        compute: Any) -> None:
    m = kit.Mount()
    before = m.calls()
    names = m.ls(m.path(FUNCTIONS))
    assert names == sorted([seed.LAMBDA_API, seed.LAMBDA_WORKER])
    assert m.calls() - before == 1
    listed = m.calls()
    for name in names:
        doc = m.json(m.path(f"{FUNCTIONS}/{name}/describe.json"))
        assert doc["FunctionName"] == name
        assert "ResponseMetadata" not in doc
    assert m.calls() == listed


def test_describe_is_canonical_redacted_listing(
        compute: Any, moto_session: Any) -> None:
    client = moto_session.client("lambda", region_name=kit.REGION)
    listed = {f["FunctionName"]: f
              for f in client.list_functions()["Functions"]}
    expected = RedactionPolicy(False).json("lambda",
                                           listed[seed.LAMBDA_API])
    m = kit.Mount()
    raw = m.read(m.path(f"{API}/describe.json"))
    doc = json.loads(raw)
    assert doc == json.loads(to_json_text(expected))
    assert raw == to_json_text(doc).encode("utf-8")
    assert doc["FunctionArn"] == compute.lambda_api_arn
    assert doc["Role"] == compute.lambda_role_arn


def test_derived_files_and_tags(compute: Any) -> None:
    m = kit.Mount()
    assert m.text(m.path(f"{API}/runtime")) == seed.LAMBDA_RUNTIME + "\n"
    assert m.text(m.path(f"{API}/arn")).strip() == compute.lambda_api_arn
    assert m.json(m.path(f"{API}/tags.json")) == dict(
        sorted(seed.LAMBDA_TAGS.items()))
    assert m.ls(m.path(f"{API}/tags")) == sorted(seed.LAMBDA_TAGS)
    assert m.text(m.path(f"{API}/tags/team")) == "payments\n"


def test_environment_values_redacted_by_default(compute: Any) -> None:
    m = kit.Mount()
    text = m.text(m.path(f"{API}/describe.json"))
    assert kit.FAKE_SECRET not in text
    variables = json.loads(text)["Environment"]["Variables"]
    assert sorted(variables) == sorted(seed.LAMBDA_ENV)
    assert set(variables.values()) == {REDACTED}
    for name in ("tags.json", "runtime", "arn"):
        assert kit.FAKE_SECRET not in m.text(m.path(f"{API}/{name}"))


def test_reveal_shows_environment_only_in_that_session(
        compute: Any) -> None:
    revealed = kit.Mount(reveal=True)
    doc = revealed.json(revealed.path(f"{API}/describe.json"))
    assert doc["Environment"]["Variables"] == seed.LAMBDA_ENV
    again = kit.Mount()
    assert kit.FAKE_SECRET not in again.text(
        again.path(f"{API}/describe.json"))


def test_lazy_policy_aliases_and_mappings(compute: Any) -> None:
    m = kit.Mount()
    m.ls(m.path(API))
    before = m.calls()
    policy = m.text(m.path(f"{API}/policy.json"))
    assert seed.LAMBDA_PERMISSION_SID in policy
    assert "lambda:InvokeFunction" in policy
    assert m.calls() - before == 1
    cached = m.calls()
    assert m.text(m.path(f"{API}/policy.json")) == policy
    assert m.calls() == cached
    aliases = m.json(m.path(f"{API}/aliases.json"))
    assert isinstance(aliases, list)
    assert [a["Name"] for a in aliases] == [seed.LAMBDA_ALIAS]
    assert m.json(m.path(f"{API}/event-source-mappings.json")) == []


def test_links(compute: Any) -> None:
    m = kit.Mount()
    net = compute.network
    links = m.path(f"{API}/links")
    assert m.targets(f"{links}/subnets") == {
        m.path(f"vpc/subnets/{net.subnet_public}"),
        m.path(f"vpc/subnets/{net.subnet_private}")}
    assert m.targets(f"{links}/security-groups") == {
        m.path(f"vpc/security-groups/{net.sg_app}")}
    assert m.relative_links(f"{links}/subnets")
    names = m.ls(links)
    if m.mounted(refs.LOG_GROUPS):
        assert m.target(f"{links}/log-group") == m.path(
            "logs/log-groups/" + escape_name(seed.LAMBDA_LOG_GROUP))
    if m.mounted(refs.IAM_ROLES):
        assert m.target(f"{links}/role") == m.gpath(
            f"iam/roles/{seed.LAMBDA_ROLE_NAME}")
    else:
        assert "role" not in names


def test_function_without_vpc_has_no_network_links(compute: Any) -> None:
    m = kit.Mount()
    links = m.path(f"{WORKER}/links")
    assert m.ls(f"{links}/subnets") == []
    assert m.ls(f"{links}/security-groups") == []
    assert "vpc" not in m.ls(links)


def test_security_group_referenced_by_function(compute: Any) -> None:
    m = kit.Mount()
    refby = m.path(
        f"vpc/security-groups/{compute.network.sg_app}/referenced-by")
    names = m.ls(refby)
    entry = escape_name(f"lambda-functions-{seed.LAMBDA_API}")
    assert entry in names
    assert m.target(f"{refby}/{entry}") == m.path(API)
    assert escape_name(f"lambda-functions-{seed.LAMBDA_WORKER}") \
        not in names
    web_refby = m.path(
        f"vpc/security-groups/{compute.network.sg_web}/referenced-by")
    assert entry not in m.ls(web_refby)


def test_access_denied_listing_degrades_to_empty_dir(
        compute: Any) -> None:
    m = kit.Mount()
    m.deny("lambda", "ListFunctions")
    assert m.ls(m.path(FUNCTIONS)) == []
    lines = m.denied("lambda")
    assert len(lines) == 1
    assert lines[0][4] == "list_functions"
    assert lines[0][1] == m.account.account_id
    assert lines[0][2] == kit.REGION
    assert seed.ALB_NAME in m.ls(m.path("elbv2/load-balancers"))


def test_access_denied_on_lazy_file_is_eacces(compute: Any) -> None:
    m = kit.Mount()
    m.deny("lambda", "GetPolicy")
    with pytest.raises(PermissionDenied) as info:
        m.read(m.path(f"{API}/policy.json"))
    assert info.value.errno == errno.EACCES
    assert m.denied("lambda", "get_policy")
    doc = m.json(m.path(f"{API}/describe.json"))
    assert doc["FunctionName"] == seed.LAMBDA_API
