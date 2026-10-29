"""AWS Systems Manager Parameter Store provider (docs/coverage.md).

Collection: parameters (names and metadata only). One paginated
``DescribeParameters`` call lists the region. ``describe.json``,
``type`` and ``version`` are derived from it. Tags are lazy.

Parameter values are never fetched. ``GetParameter``,
``GetParameters``, ``GetParametersByPath`` and ``GetParameterHistory``
are denied even with ``--reveal``. The ``ssm`` rule set still redacts
``Value`` defensively.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from awsmount.providers import refs
from awsmount.providers.base import (
    CollectionSpec,
    FileSpec,
    LinkSpec,
    ListCtx,
    ResourceCtx,
    ServiceSpec,
    TagSpec,
)
from awsmount.providers.common import kms_ref, make_arn
from awsmount.providers.ec2 import field_text

if TYPE_CHECKING:
    from awsmount.session.context import Scope

__all__ = ["PARAMETERS", "SERVICE"]

SECURE_STRING = "SecureString"


def _list_parameters(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated DescribeParameters call for the region."""
    return [p for p in lc.paginate("describe_parameters", "Parameters")
            if isinstance(p, dict) and p.get("Name")]


def _parameter_arn(item: dict[str, Any], scope: Scope) -> str | None:
    """ARN as listed, or built from the parameter name."""
    arn = item.get("ARN")
    if arn:
        return str(arn)
    name = item.get("Name")
    if not name:
        return None
    name = str(name)
    if name.startswith("/"):
        resource = f"parameter{name}"
    else:
        resource = f"parameter/{name}"
    return make_arn(scope, "ssm", resource)


def _kms_key(rc: ResourceCtx) -> str | None:
    """KMS key of a SecureString parameter (aliases give no link)."""
    if rc.item.get("Type") != SECURE_STRING:
        return None
    return kms_ref(rc.item.get("KeyId"))


def _tags(rc: ResourceCtx) -> dict[str, str]:
    """Tags from ListTagsForResource (ResourceType=Parameter)."""
    resp = rc.call("list_tags_for_resource", ResourceType="Parameter",
                   ResourceId=rc.key)
    return {str(t["Key"]): str(t.get("Value", ""))
            for t in resp.get("TagList", []) or []
            if isinstance(t, dict) and "Key" in t}


PARAMETERS = CollectionSpec(
    name="parameters",
    client="ssm",
    lister=_list_parameters,
    key=lambda i: str(i["Name"]),
    ops=frozenset({"DescribeParameters", "ListTagsForResource"}),
    arn=_parameter_arn,
    name_of=lambda i: i.get("Name"),
    redact="ssm",
    tags=TagSpec(fetch=_tags),
    files=(
        FileSpec("type", field_text("Type")),
        FileSpec("version", field_text("Version")),
    ),
    links=(
        LinkSpec("kms-key", refs.KMS_KEYS, _kms_key),
    ),
    lookup={"arn": lambda i: str(i.get("ARN", "")),
            "name": lambda i: str(i.get("Name", ""))},
)


SERVICE = ServiceSpec(
    dirname="ssm",
    scope="region",
    collections=(
        PARAMETERS,
    ),
)
