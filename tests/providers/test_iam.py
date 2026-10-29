"""IAM provider (global) against a seeded moto backend (docs/coverage.md).

Covers users, roles, groups and customer-managed policies: derived
``describe.json`` (no N+1), lazy detail files, tags (never redacted),
relationship links, access key metadata (secrets are never served,
with or without ``--reveal``), the read-only guard and AccessDenied
degradation.
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
from awsmount.session.redact import REDACTED, RedactionPolicy
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
def iam_seed(moto_session: boto3.Session) -> Any:
    """The seeded IAM estate."""
    return seed.seed_iam(moto_session)


def _raw(session: boto3.Session, op: str, key: str,
         **params: Any) -> list[dict[str, Any]]:
    """Items of a paginated IAM call made directly against moto."""
    client = session.client("iam", region_name=kit.REGION)
    out: list[dict[str, Any]] = []
    for page in client.get_paginator(op).paginate(**params):
        out.extend(page.get(key, []))
    return out


def _canon(obj: Any) -> Any:
    """Canonical JSON round-trip (datetimes become ISO strings)."""
    return json.loads(to_json_text(obj))


def test_users_listing_and_describe_are_derived(
        iam_seed: Any, moto_session: boto3.Session) -> None:
    """describe.json/arn/name equal the ListUsers item; no extra call."""
    m = kit.Mount(reveal=True)
    users = m.gpath("iam/users")
    raw = {u["UserName"]: u
           for u in _raw(moto_session, "list_users", "Users")}
    assert set(raw) == {seed.IAM_USER, seed.IAM_USER_PLAIN}
    assert m.ls(users) == sorted(raw)
    before = m.calls()
    for name, item in raw.items():
        base = f"{users}/{name}"
        assert m.json(f"{base}/describe.json") == _canon(item)
        assert m.text(f"{base}/arn") == item["Arn"] + "\n"
        assert m.text(f"{base}/name") == name + "\n"
    assert m.calls() == before
    assert raw[seed.IAM_USER]["Arn"] == iam_seed.user_arn


def test_user_tags_are_lazy_and_never_redacted(iam_seed: Any) -> None:
    """tags.json costs one ListUserTags call; values are served as-is."""
    m = kit.Mount()
    base = m.gpath(f"iam/users/{seed.IAM_USER}")
    m.ls(base)
    before = m.calls()
    assert m.json(f"{base}/tags.json") == seed.IAM_USER_TAGS
    assert m.calls() == before + 1
    assert "team%2Fowner" in m.ls(f"{base}/tags")
    assert m.text(f"{base}/tags/team%2Fowner") == "alice\n"
    assert m.text(f"{base}/tags/DbPassword") == \
        seed.TAG_SECRET_VALUE + "\n"
    assert m.calls() == before + 1


def test_user_detail_files(iam_seed: Any) -> None:
    """Attached/inline policies, groups and MFA devices of a user."""
    m = kit.Mount()
    base = m.gpath(f"iam/users/{seed.IAM_USER}")
    attached = m.json(f"{base}/attached-policies.json")
    assert attached == [{"PolicyArn": iam_seed.policy_arn,
                         "PolicyName": seed.IAM_POLICY}]
    groups = m.json(f"{base}/groups.json")
    assert [g["GroupName"] for g in groups] == [seed.IAM_GROUP]
    inline = f"{base}/inline-policies"
    assert m.ls(inline) == [f"{seed.IAM_USER_INLINE}.json"]
    assert m.json(f"{inline}/{seed.IAM_USER_INLINE}.json") == \
        seed.iam_inline_document(seed.IAM_USER_INLINE)
    mfa = m.json(f"{base}/mfa-devices.json")
    assert [d["SerialNumber"] for d in mfa] == [iam_seed.mfa_serial]
    plain = m.gpath(f"iam/users/{seed.IAM_USER_PLAIN}")
    assert m.json(f"{plain}/attached-policies.json") == []
    assert m.ls(f"{plain}/inline-policies") == []
    assert m.json(f"{plain}/access-keys.json") == []


def test_user_links_are_relative_and_resolve(iam_seed: Any) -> None:
    """links/groups and links/policies point at the global dirs."""
    m = kit.Mount()
    links = m.gpath(f"iam/users/{seed.IAM_USER}/links")
    assert m.ls(links) == ["groups", "policies"]
    assert m.ls(f"{links}/groups") == [seed.IAM_GROUP]
    assert m.targets(f"{links}/groups") == {
        m.gpath(f"iam/groups/{seed.IAM_GROUP}")}
    assert m.targets(f"{links}/policies") == {
        m.gpath(f"iam/policies/{seed.IAM_POLICY}")}
    assert m.relative_links(f"{links}/groups")
    assert m.relative_links(f"{links}/policies")


def test_role_trust_policy_and_trust_links(iam_seed: Any) -> None:
    """Trust policy is derived; only same-account principals link."""
    m = kit.Mount()
    roles = m.gpath("iam/roles")
    assert seed.IAM_ROLE in m.ls(roles)
    base = f"{roles}/{seed.IAM_ROLE}"
    before = m.calls()
    assert m.json(f"{base}/trust-policy.json") == \
        seed.iam_trust_policy(iam_seed.account_id)
    assert m.text(f"{base}/arn") == iam_seed.role_arn + "\n"
    assert m.calls() == before
    links = f"{base}/links"
    assert m.ls(f"{links}/trusts") == [seed.IAM_TRUSTED_ROLE]
    assert m.targets(f"{links}/trusts") == {
        f"{roles}/{seed.IAM_TRUSTED_ROLE}"}
    assert m.ls(f"{links}/trusts-users") == [seed.IAM_USER]
    assert m.targets(f"{links}/trusts-users") == {
        m.gpath(f"iam/users/{seed.IAM_USER}")}
    assert m.targets(f"{links}/policies") == {
        m.gpath(f"iam/policies/{seed.IAM_POLICY}")}
    deployer_links = f"{roles}/{seed.IAM_TRUSTED_ROLE}/links"
    assert m.ls(f"{deployer_links}/trusts") == []
    assert m.ls(f"{deployer_links}/trusts-users") == []


def test_role_lazy_files(iam_seed: Any) -> None:
    """Instance profiles, inline policies, tags and last-used data."""
    m = kit.Mount()
    base = m.gpath(f"iam/roles/{seed.IAM_ROLE}")
    profiles = m.json(f"{base}/instance-profiles.json")
    assert [p["InstanceProfileName"] for p in profiles] == [
        seed.IAM_INSTANCE_PROFILE]
    assert profiles[0]["Arn"] == iam_seed.instance_profile_arn
    assert m.json(f"{base}/tags.json") == seed.IAM_ROLE_TAGS
    assert m.json(
        f"{base}/inline-policies/{seed.IAM_ROLE_INLINE}.json") == \
        seed.iam_inline_document(seed.IAM_ROLE_INLINE)
    assert [p["PolicyName"] for p in
            m.json(f"{base}/attached-policies.json")] == [seed.IAM_POLICY]
    assert isinstance(m.json(f"{base}/last-used.json"), (dict, type(None)))


def test_group_members_policies_and_no_tags(iam_seed: Any) -> None:
    """members/ links both users; groups have no tags."""
    m = kit.Mount()
    base = m.gpath(f"iam/groups/{seed.IAM_GROUP}")
    assert m.text(f"{base}/arn") == iam_seed.group_arn + "\n"
    assert "tags.json" not in m.ls(base)
    members = f"{base}/links/members"
    assert m.ls(members) == sorted([seed.IAM_USER, seed.IAM_USER_PLAIN])
    assert m.targets(members) == {
        m.gpath(f"iam/users/{seed.IAM_USER}"),
        m.gpath(f"iam/users/{seed.IAM_USER_PLAIN}")}
    assert m.json(
        f"{base}/inline-policies/{seed.IAM_GROUP_INLINE}.json") == \
        seed.iam_inline_document(seed.IAM_GROUP_INLINE)
    assert [p["PolicyArn"] for p in
            m.json(f"{base}/attached-policies.json")] == [
        iam_seed.policy_arn]


def test_policy_versions_entities_and_attachments(iam_seed: Any) -> None:
    """Default version document, versions, entities, attached-to links."""
    m = kit.Mount()
    policies = m.gpath("iam/policies")
    assert m.ls(policies) == [seed.IAM_POLICY]
    base = f"{policies}/{seed.IAM_POLICY}"
    item = m.json(f"{base}/describe.json")
    assert item["DefaultVersionId"] == "v2"
    assert item["AttachmentCount"] == 3
    assert m.json(f"{base}/document.json") == seed.iam_policy_document(2)
    versions = m.json(f"{base}/versions.json")
    assert sorted(v["VersionId"] for v in versions) == ["v1", "v2"]
    assert [v["VersionId"] for v in versions
            if v["IsDefaultVersion"]] == ["v2"]
    entities = m.json(f"{base}/entities.json")
    assert [u["UserName"] for u in entities["PolicyUsers"]] == [
        seed.IAM_USER]
    assert [g["GroupName"] for g in entities["PolicyGroups"]] == [
        seed.IAM_GROUP]
    assert [r["RoleName"] for r in entities["PolicyRoles"]] == [
        seed.IAM_ROLE]
    links = f"{base}/links"
    assert m.targets(f"{links}/attached-to-users") == {
        m.gpath(f"iam/users/{seed.IAM_USER}")}
    assert m.targets(f"{links}/attached-to-groups") == {
        m.gpath(f"iam/groups/{seed.IAM_GROUP}")}
    assert m.targets(f"{links}/attached-to-roles") == {
        m.gpath(f"iam/roles/{seed.IAM_ROLE}")}
    assert m.json(f"{base}/tags.json") == seed.IAM_POLICY_TAGS


@pytest.mark.parametrize("reveal", [False, True])
def test_access_key_secrets_are_never_served(iam_seed: Any,
                                             reveal: bool) -> None:
    """Only key metadata is listed, even with --reveal."""
    m = kit.Mount(reveal=reveal)
    users = m.gpath("iam/users")
    keys = m.json(f"{users}/{seed.IAM_USER}/access-keys.json")
    assert [k["AccessKeyId"] for k in keys] == [iam_seed.access_key_id]
    assert keys[0]["Status"] == "Active"
    assert all("SecretAccessKey" not in k for k in keys)
    assert m.grep(users, "SecretAccessKey") == []


def test_iam_rule_redacts_secret_defensively() -> None:
    """The ``iam`` rule hides a SecretAccessKey should one ever appear."""
    data = [{"AccessKeyId": "AKIAEXAMPLE", "SecretAccessKey": "s3cr3t",
             "Status": "Active"}]
    redacted = RedactionPolicy(False).json("iam", data)
    assert redacted == [{"AccessKeyId": "AKIAEXAMPLE",
                         "SecretAccessKey": REDACTED,
                         "Status": "Active"}]
    assert data[0]["SecretAccessKey"] == "s3cr3t"
    assert RedactionPolicy(True).json("iam", data) == data


def test_mount_clients_cannot_mutate_iam(
        iam_seed: Any, moto_session: boto3.Session) -> None:
    """Write operations are refused before any HTTP request."""
    m = kit.Mount(reveal=True)
    client = m.ctx.clients.get(m.account.profile, kit.REGION, "iam")
    with pytest.raises(ForbiddenOperation):
        client.create_access_key(UserName=seed.IAM_USER)
    with pytest.raises(ForbiddenOperation):
        client.delete_user(UserName=seed.IAM_USER_PLAIN)
    keys = _raw(moto_session, "list_access_keys", "AccessKeyMetadata",
                UserName=seed.IAM_USER)
    assert [k["AccessKeyId"] for k in keys] == [iam_seed.access_key_id]
    assert seed.IAM_USER_PLAIN in m.ls(m.gpath("iam/users"))


def test_access_denied_listing_degrades_to_empty_dir(
        iam_seed: Any) -> None:
    """Denied ListRoles: empty roles/, one errors.log line, rest works."""
    m = kit.Mount()
    m.deny("iam", "ListRoles")
    assert m.ls(m.gpath("iam/roles")) == []
    assert m.ls(m.gpath("iam/roles")) == []
    rows = m.denied("iam", "list_roles")
    assert len(rows) == 1
    assert rows[0][1] == m.account.account_id
    assert rows[0][6] == "AccessDenied"
    assert m.ls(m.gpath("iam/users")) == sorted(
        [seed.IAM_USER, seed.IAM_USER_PLAIN])
    assert m.ls(m.gpath("iam/policies")) == [seed.IAM_POLICY]


def test_access_denied_lazy_file_is_eacces(iam_seed: Any) -> None:
    """Denied lazy file -> PermissionDenied; siblings still readable."""
    m = kit.Mount()
    m.deny("iam", "ListAttachedUserPolicies")
    base = m.gpath(f"iam/users/{seed.IAM_USER}")
    with pytest.raises(PermissionDenied):
        m.read(f"{base}/attached-policies.json")
    assert m.ls(f"{base}/links/policies") == []
    assert m.ls(f"{base}/links/groups") == [seed.IAM_GROUP]
    groups = m.json(f"{base}/groups.json")
    assert [g["GroupName"] for g in groups] == [seed.IAM_GROUP]
    assert m.denied("iam", "list_attached_user_policies")


def test_seed_iam_is_idempotent(iam_seed: Any,
                                moto_session: boto3.Session) -> None:
    """Running the seed again changes nothing."""
    assert seed.seed_iam(moto_session) == iam_seed
    assert len(_raw(moto_session, "list_users", "Users")) == 2
    assert len(_raw(moto_session, "list_policy_versions", "Versions",
                    PolicyArn=iam_seed.policy_arn)) == 2
    assert len(_raw(moto_session, "get_group", "Users",
                    GroupName=seed.IAM_GROUP)) == 2
