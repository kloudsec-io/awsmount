"""AWS Organizations provider (global) against a seeded moto backend.

Covers accounts, roots and service control policies: derived
``describe.json`` (no N+1), the lazy policy document, the "if allowed"
semantics (organization not in use -> silent empty dir; AccessDenied
-> empty dir plus errors.log), and the read-only guard.
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
def org(moto_session: boto3.Session) -> Any:
    """The seeded organization."""
    return seed.seed_organizations(moto_session)


def _client(session: boto3.Session) -> Any:
    return session.client("organizations", region_name=kit.REGION)


def _items(session: boto3.Session, op: str, key: str,
           **params: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for page in _client(session).get_paginator(op).paginate(**params):
        out.extend(page.get(key, []))
    return out


def _canon(obj: Any) -> Any:
    """Canonical JSON round-trip (datetimes become ISO strings)."""
    return json.loads(to_json_text(obj))


def _org_rows(m: Any) -> list[list[str]]:
    return [cols for cols in m.error_lines()
            if len(cols) >= 8 and cols[3] == "organizations"]


def test_accounts_listing_is_derived(
        org: Any, moto_session: boto3.Session) -> None:
    """One ListAccounts call; every derived file costs nothing more."""
    m = kit.Mount(reveal=True)
    accounts = m.gpath("organizations/accounts")
    raw = {a["Id"]: a for a in _items(moto_session, "list_accounts",
                                      "Accounts")}
    assert m.ls(accounts) == sorted(raw)
    assert m.account.account_id in raw
    assert org.member_account_id in raw
    before = m.calls()
    for ident, item in raw.items():
        base = f"{accounts}/{ident}"
        assert m.json(f"{base}/describe.json") == _canon(item)
        assert m.text(f"{base}/arn") == item["Arn"] + "\n"
        assert m.text(f"{base}/account-name") == item["Name"] + "\n"
        assert m.text(f"{base}/status") == item["Status"] + "\n"
    member = f"{accounts}/{org.member_account_id}"
    assert m.text(f"{member}/account-name") == seed.ORG_ACCOUNT_NAME + "\n"
    assert m.text(f"{member}/name") == seed.ORG_ACCOUNT_NAME + "\n"
    assert m.json(f"{member}/describe.json")["Email"] == \
        seed.ORG_ACCOUNT_EMAIL
    assert "tags.json" not in m.ls(member)
    assert m.calls() == before


def test_roots_listing(org: Any, moto_session: boto3.Session) -> None:
    """The single root is listed with its derived describe.json."""
    m = kit.Mount(reveal=True)
    roots = m.gpath("organizations/roots")
    assert m.ls(roots) == [org.root_id]
    raw = _items(moto_session, "list_roots", "Roots")[0]
    base = f"{roots}/{org.root_id}"
    assert m.json(f"{base}/describe.json") == _canon(raw)
    assert m.text(f"{base}/arn") == raw["Arn"] + "\n"
    assert m.text(f"{base}/name") == raw["Name"] + "\n"
    assert org.root_id.startswith("r-")


def test_policy_document_is_lazy(org: Any) -> None:
    """document.json: one DescribePolicy call, then cached."""
    m = kit.Mount()
    policies = m.gpath("organizations/policies")
    assert org.policy_id in m.ls(policies)
    base = f"{policies}/{org.policy_id}"
    assert m.text(f"{base}/name") == seed.ORG_POLICY_NAME + "\n"
    item = m.json(f"{base}/describe.json")
    assert item["Type"] == seed.ORG_POLICY_TYPE
    assert item["Description"] == seed.ORG_POLICY_DESCRIPTION
    before = m.calls()
    assert m.json(f"{base}/document.json") == seed.org_policy_document()
    assert m.calls() == before + 1
    m.json(f"{base}/document.json")
    assert m.calls() == before + 1


def test_only_service_control_policies_are_listed(
        org: Any, moto_session: boto3.Session) -> None:
    """The listing uses Filter=SERVICE_CONTROL_POLICY."""
    m = kit.Mount()
    raw = _items(moto_session, "list_policies", "Policies",
                 Filter=seed.ORG_POLICY_TYPE)
    assert m.ls(m.gpath("organizations/policies")) == sorted(
        p["Id"] for p in raw)
    for ident in m.ls(m.gpath("organizations/policies")):
        data = m.json(
            m.gpath(f"organizations/policies/{ident}/describe.json"))
        assert data["Type"] == seed.ORG_POLICY_TYPE


def test_organization_not_in_use_is_silent(org: Any) -> None:
    """AWSOrganizationsNotInUseException: empty dir, no log entry."""
    m = kit.Mount()
    m.deny("organizations", "ListAccounts",
           code="AWSOrganizationsNotInUseException")
    assert m.ls(m.gpath("organizations/accounts")) == []
    assert _org_rows(m) == []
    assert m.ls(m.gpath("organizations/roots")) == [org.root_id]


def test_access_denied_listing_degrades(org: Any) -> None:
    """Denied ListRoots: empty dir, one errors.log line, rest served."""
    m = kit.Mount()
    m.deny("organizations", "ListRoots")
    assert m.ls(m.gpath("organizations/roots")) == []
    rows = m.denied("organizations", "list_roots")
    assert len(rows) == 1
    assert rows[0][1] == m.account.account_id
    assert org.member_account_id in m.ls(
        m.gpath("organizations/accounts"))


def test_access_denied_lazy_document_is_eacces(org: Any) -> None:
    """Denied DescribePolicy: document.json EACCES, describe served."""
    m = kit.Mount()
    m.deny("organizations", "DescribePolicy")
    base = m.gpath(f"organizations/policies/{org.policy_id}")
    with pytest.raises(PermissionDenied):
        m.read(f"{base}/document.json")
    assert m.json(f"{base}/describe.json")["Id"] == org.policy_id
    assert m.denied("organizations", "describe_policy")


def test_mount_clients_cannot_mutate_organizations(
        org: Any, moto_session: boto3.Session) -> None:
    """Write operations are refused before any HTTP request."""
    m = kit.Mount(reveal=True)
    client = m.ctx.clients.get(m.account.profile, kit.REGION,
                               "organizations")
    before = m.calls()
    with pytest.raises(ForbiddenOperation):
        client.leave_organization()
    with pytest.raises(ForbiddenOperation):
        client.create_account(Email="x@awsmount.example",
                              AccountName="awsmount-intruder")
    with pytest.raises(ForbiddenOperation):
        client.delete_policy(PolicyId=org.policy_id)
    assert m.calls() == before
    names = {a["Name"] for a in _items(moto_session, "list_accounts",
                                       "Accounts")}
    assert "awsmount-intruder" not in names
    policies = _items(moto_session, "list_policies", "Policies",
                      Filter=seed.ORG_POLICY_TYPE)
    assert org.policy_id in {p["Id"] for p in policies}


def test_seed_organizations_is_idempotent(
        org: Any, moto_session: boto3.Session) -> None:
    """Running the seed again reuses the organization and its parts."""
    accounts = len(_items(moto_session, "list_accounts", "Accounts"))
    assert seed.seed_organizations(moto_session) == org
    assert len(_items(moto_session, "list_accounts",
                      "Accounts")) == accounts
    names = [p["Name"] for p in _items(moto_session, "list_policies",
                                       "Policies",
                                       Filter=seed.ORG_POLICY_TYPE)]
    assert names.count(seed.ORG_POLICY_NAME) == 1
