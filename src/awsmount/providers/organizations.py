"""AWS Organizations provider (global, docs/coverage.md).

Collections: accounts, roots and service control policies. Each is
listed with one paginated call, and ``describe.json`` is derived from
it. A policy's ``document.json`` (DescribePolicy) is lazy.

The service is listed "if allowed". ``AWSOrganizationsNotInUseException``
gives an empty directory with no log entry. AccessDenied (for example
in a member account) gives an empty directory plus an ``errors.log``
entry.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from awsmount.providers.base import (
    CollectionSpec,
    FileSpec,
    ListCtx,
    ResourceCtx,
    ServiceSpec,
    TagSpec,
)
from awsmount.providers.common import name_from_arn, parse_json_text
from awsmount.providers.ec2 import field_text
from awsmount.vfs.render import Content

if TYPE_CHECKING:
    from awsmount.session.context import Scope

__all__ = ["ACCOUNTS", "POLICIES", "ROOTS", "SERVICE"]

SCP_FILTER = "SERVICE_CONTROL_POLICY"


def _arn(item: dict[str, Any], scope: Scope) -> str | None:
    """ARN of the listed entity."""
    arn = item.get("Arn")
    return str(arn) if arn else None


# -- accounts --


def _list_accounts(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated ListAccounts call."""
    return [a for a in lc.paginate("list_accounts", "Accounts")
            if isinstance(a, dict) and a.get("Id")]


ACCOUNTS = CollectionSpec(
    name="accounts",
    client="organizations",
    lister=_list_accounts,
    key=lambda i: str(i["Id"]),
    ops=frozenset({"ListAccounts"}),
    arn=_arn,
    name_of=lambda i: i.get("Name"),
    tags=TagSpec.none(),
    files=(
        FileSpec("account-name", field_text("Name")),
        FileSpec("status", field_text("Status")),
    ),
    lookup={"arn": lambda i: str(i.get("Arn", "")),
            "name": lambda i: str(i.get("Name", ""))},
    key_from_arn=name_from_arn,
)


# -- roots --


def _list_roots(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated ListRoots call."""
    return [r for r in lc.paginate("list_roots", "Roots")
            if isinstance(r, dict) and r.get("Id")]


ROOTS = CollectionSpec(
    name="roots",
    client="organizations",
    lister=_list_roots,
    key=lambda i: str(i["Id"]),
    ops=frozenset({"ListRoots"}),
    arn=_arn,
    name_of=lambda i: i.get("Name"),
    tags=TagSpec.none(),
    lookup={"arn": lambda i: str(i.get("Arn", ""))},
    key_from_arn=name_from_arn,
)


# -- service control policies --


def _list_policies(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated ListPolicies call (service control policies)."""
    return [p for p in lc.paginate("list_policies", "Policies",
                                   Filter=SCP_FILTER)
            if isinstance(p, dict) and p.get("Id")]


def _document(rc: ResourceCtx) -> Content:
    """document.json: the parsed policy content (lazy DescribePolicy)."""
    resp = rc.call("describe_policy", PolicyId=rc.key)
    policy = resp.get("Policy") or {}
    content = policy.get("Content") if isinstance(policy, dict) else None
    if content is None:
        return None
    result: Content = parse_json_text(content)
    return result


POLICIES = CollectionSpec(
    name="policies",
    client="organizations",
    lister=_list_policies,
    key=lambda i: str(i["Id"]),
    ops=frozenset({"ListPolicies", "DescribePolicy"}),
    arn=_arn,
    name_of=lambda i: i.get("Name"),
    tags=TagSpec.none(),
    files=(
        FileSpec("document.json", _document, lazy=True),
    ),
    lookup={"arn": lambda i: str(i.get("Arn", "")),
            "name": lambda i: str(i.get("Name", ""))},
    key_from_arn=name_from_arn,
)


SERVICE = ServiceSpec(
    dirname="organizations",
    scope="global",
    collections=(
        ACCOUNTS,
        ROOTS,
        POLICIES,
    ),
)
