"""API Gateway (REST) provider against a seeded moto backend.

Covers the derived listing with the name collision rule, inline map
tags, lazy resources/stages/deployments/authorizers (one call each),
stage-variable redaction (rule ``apigw-stages``) and ``--reveal``, the
denied data-plane operations, and AccessDenied degradation.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import boto3
import pytest

from awsmount.errors import ForbiddenOperation, PermissionDenied
from awsmount.session.redact import REDACTED
from awsmount.vfs.render import to_json_text


def _load_kit() -> ModuleType:
    """Load tests/providers/motokit.py by path (any import mode)."""
    name = "awsmount_tests_motokit"
    module = sys.modules.get(name)
    if module is not None:
        return module
    path = Path(__file__).resolve().parent / "motokit.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        del sys.modules[name]
        raise
    return module


kit = _load_kit()
seed = kit.seed
moto_session = kit.moto_session


@pytest.fixture(scope="module")
def api(moto_session: boto3.Session) -> Any:
    """The seeded API Gateway estate."""
    return seed.seed_apigateway(moto_session)


def _apis(session: boto3.Session) -> dict[str, dict[str, Any]]:
    """GetRestApis items by id, read directly from moto."""
    client = session.client("apigateway", region_name=kit.REGION)
    out: dict[str, dict[str, Any]] = {}
    for page in client.get_paginator("get_rest_apis").paginate():
        for item in page.get("items", []):
            out[item["id"]] = item
    return out


def _dirnames(api: Any) -> dict[str, str]:
    """Expected dirname per API id (collision rule for duplicates)."""
    names = {api.api_id: seed.API_NAME}
    for ident in api.dup_api_ids:
        names[ident] = f"{seed.API_DUP_NAME}~{ident}"
    return names


def _canon(obj: Any) -> Any:
    """Canonical JSON round-trip (datetimes become ISO strings)."""
    return json.loads(to_json_text(obj))


def test_listing_names_and_derived_files(
        api: Any, moto_session: boto3.Session) -> None:
    """Dirnames follow the collision rule; derived files cost nothing."""
    m = kit.Mount(reveal=True)
    apis = m.path("apigateway/rest-apis")
    expected = _dirnames(api)
    assert m.ls(apis) == sorted(expected.values())
    raw = _apis(moto_session)
    assert set(raw) == set(expected)
    before = m.calls()
    for ident, dirname in expected.items():
        base = f"{apis}/{dirname}"
        assert m.json(f"{base}/describe.json") == _canon(raw[ident])
        assert m.text(f"{base}/name") == raw[ident]["name"] + "\n"
        assert m.text(f"{base}/arn") == (
            f"arn:aws:apigateway:{kit.REGION}::/restapis/{ident}\n")
    assert m.text(f"{apis}/{seed.API_NAME}/endpoint-type") == "REGIONAL\n"
    for ident in api.dup_api_ids:
        assert m.text(f"{apis}/{expected[ident]}/endpoint-type") == \
            "EDGE\n"
    assert m.calls() == before


def test_inline_tags_are_not_redacted(api: Any) -> None:
    """Map-style inline tags: no call, values served as-is."""
    m = kit.Mount()
    apis = m.path("apigateway/rest-apis")
    m.ls(apis)
    before = m.calls()
    base = f"{apis}/{seed.API_NAME}"
    assert m.json(f"{base}/tags.json") == seed.API_TAGS
    assert m.text(f"{base}/tags/ApiToken") == seed.TAG_SECRET_VALUE + "\n"
    dup = f"{apis}/{seed.API_DUP_NAME}~{api.dup_api_ids[0]}"
    assert m.json(f"{dup}/tags.json") == {}
    assert m.ls(f"{dup}/tags") == []
    assert m.calls() == before


def test_default_describe_keeps_identity_fields(
        api: Any, moto_session: boto3.Session) -> None:
    """Redacted describe.json still carries id, name and description."""
    m = kit.Mount()
    base = m.path(f"apigateway/rest-apis/{seed.API_NAME}")
    data = m.json(f"{base}/describe.json")
    raw = _apis(moto_session)[api.api_id]
    assert data["id"] == api.api_id
    assert data["name"] == seed.API_NAME
    assert data["description"] == seed.API_DESCRIPTION
    assert data["endpointConfiguration"]["types"] == ["REGIONAL"]
    assert data["tags"] == raw["tags"] == seed.API_TAGS


def test_lazy_files_cost_one_call_each(api: Any) -> None:
    """resources, deployments and authorizers: one call each, cached."""
    m = kit.Mount()
    base = m.path(f"apigateway/rest-apis/{seed.API_NAME}")
    m.ls(base)
    before = m.calls()
    resources = m.json(f"{base}/resources.json")
    by_path = {r["path"]: r["id"] for r in resources}
    assert by_path == dict(api.resources)
    assert set(by_path) == {"/", *seed.API_RESOURCE_PATHS}
    deployments = m.json(f"{base}/deployments.json")
    assert [d["id"] for d in deployments] == [api.deployment_id]
    assert deployments[0]["description"] == \
        seed.API_DEPLOYMENT_DESCRIPTION
    authorizers = m.json(f"{base}/authorizers.json")
    assert [a["id"] for a in authorizers] == [api.authorizer_id]
    assert authorizers[0]["name"] == seed.API_AUTHORIZER
    assert authorizers[0]["type"] == "TOKEN"
    assert m.calls() == before + 3
    m.json(f"{base}/resources.json")
    m.json(f"{base}/authorizers.json")
    assert m.calls() == before + 3


def test_stage_variables_redacted_by_default(api: Any) -> None:
    """Every stage variable value is redacted; names are kept."""
    m = kit.Mount()
    base = m.path(f"apigateway/rest-apis/{seed.API_NAME}")
    stages = m.json(f"{base}/stages.json")["item"]
    assert [s["stageName"] for s in stages] == [seed.API_STAGE]
    assert stages[0]["deploymentId"] == api.deployment_id
    assert stages[0]["variables"] == {
        k: REDACTED for k in seed.API_STAGE_VARIABLES}
    assert seed.FAKE_SECRET not in m.text(f"{base}/stages.json")
    assert m.grep(m.path("apigateway"), seed.FAKE_SECRET) == []


def test_stage_variables_revealed_on_request(api: Any) -> None:
    """--reveal serves the raw variables, and only there."""
    m = kit.Mount(reveal=True)
    base = m.path(f"apigateway/rest-apis/{seed.API_NAME}")
    stages = m.json(f"{base}/stages.json")["item"]
    assert stages[0]["variables"] == seed.API_STAGE_VARIABLES
    assert m.grep(m.path("apigateway"), seed.FAKE_SECRET) == [
        f"{base}/stages.json"]


def test_data_plane_ops_are_denied_even_with_reveal(api: Any) -> None:
    """API keys, exports and SDKs are never fetched."""
    m = kit.Mount(reveal=True)
    client = m.ctx.clients.get(m.account.profile, kit.REGION,
                               "apigateway")
    before = m.calls()
    with pytest.raises(ForbiddenOperation):
        client.get_api_keys(includeValues=True)
    with pytest.raises(ForbiddenOperation):
        client.get_export(restApiId=api.api_id, stageName=seed.API_STAGE,
                          exportType="swagger")
    with pytest.raises(ForbiddenOperation):
        client.delete_rest_api(restApiId=api.api_id)
    assert m.calls() == before
    assert seed.API_NAME in m.ls(m.path("apigateway/rest-apis"))


def test_access_denied_listing_degrades(api: Any) -> None:
    """Denied GetRestApis: empty dir plus one errors.log line."""
    m = kit.Mount()
    m.deny("apigateway", "GetRestApis")
    assert m.ls(m.path("apigateway/rest-apis")) == []
    rows = m.denied("apigateway", "get_rest_apis")
    assert len(rows) == 1
    assert rows[0][2] == kit.REGION
    assert m.ls(m.path("apigateway")) == ["rest-apis"]


def test_access_denied_lazy_stages_is_eacces(api: Any) -> None:
    """Denied GetStages: stages.json EACCES, other files still served."""
    m = kit.Mount()
    m.deny("apigateway", "GetStages")
    base = m.path(f"apigateway/rest-apis/{seed.API_NAME}")
    with pytest.raises(PermissionDenied):
        m.read(f"{base}/stages.json")
    assert [d["id"] for d in m.json(f"{base}/deployments.json")] == [
        api.deployment_id]
    assert m.denied("apigateway", "get_stages")


def test_seed_apigateway_is_idempotent(
        api: Any, moto_session: boto3.Session) -> None:
    """Running the seed again reuses every API, stage and authorizer."""
    assert seed.seed_apigateway(moto_session) == api
    assert len(_apis(moto_session)) == 1 + seed.API_DUP_COUNT
