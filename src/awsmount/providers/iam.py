"""AWS IAM provider (global, docs/coverage.md).

Collections: users, roles, groups and customer-managed policies. Each
is listed with one paginated call, and ``describe.json`` is derived
from that listing. These files are lazy: attached and inline policies,
group membership, access key metadata, MFA devices, instance profiles,
last-used data, policy documents, versions, entities and tags.

IAM never returns access key secrets. ``access-keys.json`` is still
redacted defensively (rule ``iam``).

The link protocol creates one directory per many-valued link, so some
relationships that one might expect under a single directory are split:

* a role's ``trusts/`` holds the trusted same-account roles, and
  ``trusts-users/`` holds the trusted same-account users;
* a policy's ``attached-to/{users,groups,roles}`` become
  ``attached-to-users/``, ``attached-to-groups/`` and
  ``attached-to-roles/``.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote

from awsmount.providers import refs
from awsmount.providers.base import (
    CollectionSpec,
    FileSpec,
    LinkSpec,
    ListCtx,
    ResourceCtx,
    ServiceSpec,
    SubdirSpec,
    TagSpec,
)
from awsmount.providers.common import (
    as_list,
    name_from_arn,
    parse_arn,
    parse_json_text,
)
from awsmount.vfs.render import Content

if TYPE_CHECKING:
    from awsmount.session.context import Scope

__all__ = [
    "GROUPS",
    "POLICIES",
    "ROLES",
    "SERVICE",
    "USERS",
    "policy_document",
]

ENTITY_KEYS = ("PolicyGroups", "PolicyUsers", "PolicyRoles")

Renderer = Callable[[ResourceCtx], Content]
Entries = Callable[[ResourceCtx], dict[str, Callable[[], Content]]]
Values = Callable[[ResourceCtx], list[str]]
TagFetch = Callable[[ResourceCtx], dict[str, str]]


# -- shared helpers --


def policy_document(value: Any) -> Any:
    """A policy document as JSON; URL-encoded text is decoded first."""
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", "replace")
    if isinstance(value, str):
        doc = value.strip()
        if doc and not doc.startswith(("{", "[")):
            doc = unquote(doc)
        return parse_json_text(doc)
    return value


def _arn(item: dict[str, Any], scope: Scope) -> str | None:
    """ARN of an IAM entity as listed."""
    arn = item.get("Arn")
    return str(arn) if arn else None


def _lister(op: str, key: str) -> Callable[[ListCtx], list[dict[str, Any]]]:
    """Lister making one paginated ``op`` call, returning ``key`` items."""

    def lister(lc: ListCtx) -> list[dict[str, Any]]:
        return [i for i in lc.paginate(op, key) if isinstance(i, dict)]

    lister.__doc__ = f"One paginated {op} call for the account."
    return lister


def _paged(op: str, key: str, field: str) -> Renderer:
    """Lazy file: one paginated ``op`` with ``field`` = resource key."""

    def render(rc: ResourceCtx) -> Content:
        result: Content = rc.paginate(op, key, **{field: rc.key})
        return result

    return render


def _inline_doc(rc: ResourceCtx, op: str, field: str,
                name: str) -> Callable[[], Content]:
    """Renderer of one inline policy document."""

    def render() -> Content:
        resp = rc.call(op, **{field: rc.key, "PolicyName": name})
        doc: Content = policy_document(resp.get("PolicyDocument"))
        return doc

    return render


def _inline_policies(list_op: str, get_op: str, field: str) -> Entries:
    """``inline-policies/<name>.json`` entries (lazy)."""

    def entries(rc: ResourceCtx) -> dict[str, Callable[[], Content]]:
        names = rc.paginate(list_op, "PolicyNames", **{field: rc.key})
        out: dict[str, Callable[[], Content]] = {}
        for name in names:
            if isinstance(name, str) and name:
                out[f"{name}.json"] = _inline_doc(rc, get_op, field, name)
        return out

    return entries


def _attached_arns(op: str, field: str) -> Values:
    """ARNs of attached customer-managed (same-account) policies."""

    def values(rc: ResourceCtx) -> list[str]:
        attached = rc.paginate(op, "AttachedPolicies", **{field: rc.key})
        account = rc.scope.account.account_id
        out: set[str] = set()
        for policy in attached:
            if not isinstance(policy, dict):
                continue
            arn = parse_arn(policy.get("PolicyArn"))
            if arn is not None and arn.account and arn.account == account:
                out.add(str(policy["PolicyArn"]))
        return sorted(out)

    return values


def _tags(op: str, field: str,
          value: Callable[[ResourceCtx], str]) -> TagFetch:
    """Lazy tag fetcher for a Marker-paginated IAM List*Tags call."""

    def fetch(rc: ResourceCtx) -> dict[str, str]:
        tags: list[Any] = []
        marker: str | None = None
        seen: set[str] = set()
        while True:
            params: dict[str, Any] = {field: value(rc)}
            if marker:
                params["Marker"] = marker
            resp = rc.call(op, **params)
            tags.extend(resp.get("Tags", []) or [])
            marker = resp.get("Marker")
            if not resp.get("IsTruncated") or not marker or \
                    marker in seen:
                break
            seen.add(marker)
        return {str(t["Key"]): str(t.get("Value", ""))
                for t in tags if isinstance(t, dict) and "Key" in t}

    return fetch


def _own_key(rc: ResourceCtx) -> str:
    """The resource key (entity name)."""
    return rc.key


# -- users --


def _user_groups(rc: ResourceCtx) -> list[str]:
    """Names of the groups the user belongs to (ListGroupsForUser)."""
    groups = rc.paginate("list_groups_for_user", "Groups",
                         UserName=rc.key)
    return sorted({str(g["GroupName"]) for g in groups
                   if isinstance(g, dict) and g.get("GroupName")})


USERS = CollectionSpec(
    name="users",
    client="iam",
    lister=_lister("list_users", "Users"),
    key=lambda i: str(i["UserName"]),
    ops=frozenset({"ListUsers", "ListAttachedUserPolicies",
                   "ListUserPolicies", "GetUserPolicy",
                   "ListGroupsForUser", "ListAccessKeys",
                   "ListMFADevices", "ListUserTags"}),
    arn=_arn,
    name_of=lambda i: i.get("UserName"),
    tags=TagSpec(fetch=_tags("list_user_tags", "UserName", _own_key)),
    files=(
        FileSpec("attached-policies.json",
                 _paged("list_attached_user_policies",
                        "AttachedPolicies", "UserName"),
                 lazy=True),
        SubdirSpec("inline-policies",
                   _inline_policies("list_user_policies",
                                    "get_user_policy", "UserName")),
        FileSpec("groups.json",
                 _paged("list_groups_for_user", "Groups", "UserName"),
                 lazy=True),
        FileSpec("access-keys.json",
                 _paged("list_access_keys", "AccessKeyMetadata",
                        "UserName"),
                 lazy=True, redact="iam"),
        FileSpec("mfa-devices.json",
                 _paged("list_mfa_devices", "MFADevices", "UserName"),
                 lazy=True),
    ),
    links=(
        LinkSpec("groups", refs.IAM_GROUPS, _user_groups, many=True),
        LinkSpec("policies", refs.IAM_POLICIES,
                 _attached_arns("list_attached_user_policies",
                                "UserName"),
                 by="arn", many=True),
    ),
    lookup={"arn": lambda i: str(i.get("Arn", "")),
            "name": lambda i: str(i.get("UserName", ""))},
    key_from_arn=name_from_arn,
)


# -- roles --


def _trust_policy(rc: ResourceCtx) -> Content:
    """trust-policy.json: the parsed AssumeRolePolicyDocument."""
    doc: Content = policy_document(rc.item.get("AssumeRolePolicyDocument"))
    return doc


def _principals(document: Any) -> list[str]:
    """``Principal.AWS`` values of every statement."""
    doc = policy_document(document)
    if not isinstance(doc, dict):
        return []
    statements = doc.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return []
    out: list[str] = []
    for statement in statements:
        if not isinstance(statement, dict):
            continue
        principal = statement.get("Principal")
        if not isinstance(principal, dict):
            continue
        aws = principal.get("AWS")
        if isinstance(aws, (str, list)):
            out.extend(as_list(aws))
    return out


def _trusted(kind: str) -> Values:
    """Same-account principals of type ``kind`` (role/user) trusted."""

    def values(rc: ResourceCtx) -> list[str]:
        account = rc.scope.account.account_id
        out: set[str] = set()
        for value in _principals(rc.item.get("AssumeRolePolicyDocument")):
            arn = parse_arn(value)
            if arn is None or arn.service != "iam":
                continue
            if arn.account != account:
                continue
            if arn.resource.startswith(f"{kind}/"):
                out.add(value)
        return sorted(out)

    return values


def _last_used(rc: ResourceCtx) -> Content:
    """last-used.json: RoleLastUsed from GetRole (lazy)."""
    resp = rc.call("get_role", RoleName=rc.key)
    role = resp.get("Role") or {}
    result: Content = role.get("RoleLastUsed") if isinstance(
        role, dict) else None
    return result


ROLES = CollectionSpec(
    name="roles",
    client="iam",
    lister=_lister("list_roles", "Roles"),
    key=lambda i: str(i["RoleName"]),
    ops=frozenset({"ListRoles", "ListAttachedRolePolicies",
                   "ListRolePolicies", "GetRolePolicy",
                   "ListInstanceProfilesForRole", "GetRole",
                   "ListRoleTags"}),
    arn=_arn,
    name_of=lambda i: i.get("RoleName"),
    tags=TagSpec(fetch=_tags("list_role_tags", "RoleName", _own_key)),
    files=(
        FileSpec("trust-policy.json", _trust_policy),
        FileSpec("attached-policies.json",
                 _paged("list_attached_role_policies",
                        "AttachedPolicies", "RoleName"),
                 lazy=True),
        SubdirSpec("inline-policies",
                   _inline_policies("list_role_policies",
                                    "get_role_policy", "RoleName")),
        FileSpec("instance-profiles.json",
                 _paged("list_instance_profiles_for_role",
                        "InstanceProfiles", "RoleName"),
                 lazy=True),
        FileSpec("last-used.json", _last_used, lazy=True),
    ),
    links=(
        LinkSpec("policies", refs.IAM_POLICIES,
                 _attached_arns("list_attached_role_policies",
                                "RoleName"),
                 by="arn", many=True),
        LinkSpec("trusts", refs.IAM_ROLES, _trusted("role"), by="arn",
                 many=True),
        LinkSpec("trusts-users", refs.IAM_USERS, _trusted("user"),
                 by="arn", many=True),
    ),
    lookup={"arn": lambda i: str(i.get("Arn", "")),
            "name": lambda i: str(i.get("RoleName", ""))},
    key_from_arn=name_from_arn,
)


# -- groups --


def _members(rc: ResourceCtx) -> list[str]:
    """User names of the group's members (paginated GetGroup)."""
    users = rc.paginate("get_group", "Users", GroupName=rc.key)
    return sorted({str(u["UserName"]) for u in users
                   if isinstance(u, dict) and u.get("UserName")})


GROUPS = CollectionSpec(
    name="groups",
    client="iam",
    lister=_lister("list_groups", "Groups"),
    key=lambda i: str(i["GroupName"]),
    ops=frozenset({"ListGroups", "ListAttachedGroupPolicies",
                   "ListGroupPolicies", "GetGroupPolicy", "GetGroup"}),
    arn=_arn,
    name_of=lambda i: i.get("GroupName"),
    tags=TagSpec.none(),
    files=(
        FileSpec("attached-policies.json",
                 _paged("list_attached_group_policies",
                        "AttachedPolicies", "GroupName"),
                 lazy=True),
        SubdirSpec("inline-policies",
                   _inline_policies("list_group_policies",
                                    "get_group_policy", "GroupName")),
    ),
    links=(
        LinkSpec("members", refs.IAM_USERS, _members, many=True),
        LinkSpec("policies", refs.IAM_POLICIES,
                 _attached_arns("list_attached_group_policies",
                                "GroupName"),
                 by="arn", many=True),
    ),
    lookup={"arn": lambda i: str(i.get("Arn", "")),
            "name": lambda i: str(i.get("GroupName", ""))},
    key_from_arn=name_from_arn,
)


# -- customer-managed policies --


def _list_policies(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated ListPolicies call (Scope=Local)."""
    return [p for p in lc.paginate("list_policies", "Policies",
                                   Scope="Local")
            if isinstance(p, dict) and p.get("PolicyName")]


def _policy_arn(rc: ResourceCtx) -> str:
    """ARN of the listed policy."""
    return str(rc.item.get("Arn") or "")


def _document(rc: ResourceCtx) -> Content:
    """document.json: the default version's document (lazy)."""
    version = rc.item.get("DefaultVersionId")
    arn = _policy_arn(rc)
    if not version or not arn:
        return None
    resp = rc.call("get_policy_version", PolicyArn=arn,
                   VersionId=str(version))
    policy_version = resp.get("PolicyVersion") or {}
    doc: Content = policy_document(policy_version.get("Document"))
    return doc


def _versions(rc: ResourceCtx) -> Content:
    """versions.json (lazy, paginated ListPolicyVersions)."""
    return rc.paginate("list_policy_versions", "Versions",
                       PolicyArn=_policy_arn(rc))


def _entity_items(rc: ResourceCtx) -> list[Any]:
    """Groups, users and roles the policy is attached to."""
    return rc.paginate("list_entities_for_policy", list(ENTITY_KEYS),
                       PolicyArn=_policy_arn(rc))


def _entities(rc: ResourceCtx) -> Content:
    """entities.json: {PolicyGroups, PolicyUsers, PolicyRoles}."""
    out: dict[str, list[Any]] = {k: [] for k in ENTITY_KEYS}
    for entity in _entity_items(rc):
        if not isinstance(entity, dict):
            continue
        if "GroupName" in entity:
            out["PolicyGroups"].append(entity)
        elif "UserName" in entity:
            out["PolicyUsers"].append(entity)
        elif "RoleName" in entity:
            out["PolicyRoles"].append(entity)
    result: Content = out
    return result


def _entity_names(field: str) -> Values:
    """Names in ``field`` of the policy's attached entities."""

    def values(rc: ResourceCtx) -> list[str]:
        return sorted({str(e[field]) for e in _entity_items(rc)
                       if isinstance(e, dict) and e.get(field)})

    return values


POLICIES = CollectionSpec(
    name="policies",
    client="iam",
    lister=_list_policies,
    key=lambda i: str(i["PolicyName"]),
    ops=frozenset({"ListPolicies", "GetPolicyVersion",
                   "ListPolicyVersions", "ListEntitiesForPolicy",
                   "ListPolicyTags"}),
    arn=_arn,
    name_of=lambda i: i.get("PolicyName"),
    tags=TagSpec(fetch=_tags("list_policy_tags", "PolicyArn",
                             _policy_arn)),
    files=(
        FileSpec("document.json", _document, lazy=True),
        FileSpec("versions.json", _versions, lazy=True),
        FileSpec("entities.json", _entities, lazy=True),
    ),
    links=(
        LinkSpec("attached-to-users", refs.IAM_USERS,
                 _entity_names("UserName"), many=True),
        LinkSpec("attached-to-groups", refs.IAM_GROUPS,
                 _entity_names("GroupName"), many=True),
        LinkSpec("attached-to-roles", refs.IAM_ROLES,
                 _entity_names("RoleName"), many=True),
    ),
    lookup={"arn": lambda i: str(i.get("Arn", "")),
            "name": lambda i: str(i.get("PolicyName", ""))},
    key_from_arn=name_from_arn,
)


SERVICE = ServiceSpec(
    dirname="iam",
    scope="global",
    collections=(
        USERS,
        ROLES,
        GROUPS,
        POLICIES,
    ),
)
