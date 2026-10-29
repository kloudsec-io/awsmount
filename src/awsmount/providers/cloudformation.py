"""CloudFormation provider: stacks and nested stack resources.

``describe.json``, ``parameters.json`` and ``outputs.json`` all use the
``cfn-params`` rule set: parameter and output values whose key looks
secret (``DBPass``, ``AdminPwd``, ``SecretKey``, ``SlackWebhookKey``...)
are redacted unless ``--reveal``. The template is whole-file redacted.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Literal

from awsmount.providers import cfn_types, refs
from awsmount.providers.base import (
    CollectionRef,
    CollectionSpec,
    FileSpec,
    LinkSpec,
    ListCtx,
    ResourceCtx,
    ServiceSpec,
    TagSpec,
)
from awsmount.vfs.render import Content

if TYPE_CHECKING:
    from awsmount.session.context import Scope

__all__ = ["RESOURCES", "SERVICE", "STACKS"]

REDACT_RULE = "cfn-params"


def _list_stacks(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated DescribeStacks call for the region."""
    return list(lc.paginate("describe_stacks", "Stacks"))


def _stack_arn(item: dict[str, Any], _scope: Scope) -> str | None:
    """The StackId is the stack ARN."""
    value = item.get("StackId")
    return str(value) if value else None


def _parameters(rc: ResourceCtx) -> Content:
    """parameters.json: derived; redacted by the ``cfn-params`` rule."""
    return list(rc.item.get("Parameters") or [])


def _outputs(rc: ResourceCtx) -> Content:
    """outputs.json: derived; redacted by the ``cfn-params`` rule."""
    return list(rc.item.get("Outputs") or [])


def _template(rc: ResourceCtx) -> Content:
    """Original template body (lazy: one GetTemplate call)."""
    resp = rc.call("get_template", StackName=rc.key,
                   TemplateStage="Original")
    body = resp.get("TemplateBody")
    if body is None:
        return None
    if isinstance(body, (dict, list, str, bytes)):
        result: Content = body
        return result
    return str(body)


def _list_resources(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated ListStackResources call for the parent stack."""
    if lc.parent is None:
        return []
    return list(lc.paginate("list_stack_resources",
                            "StackResourceSummaries",
                            StackName=lc.parent.key))


def _target_values(ref: CollectionRef, by: str
                   ) -> Callable[[ResourceCtx], str | None]:
    """Physical id when the resource type maps to ``ref`` via ``by``."""

    def values(rc: ResourceCtx) -> str | None:
        rtype = str(rc.item.get("ResourceType") or "")
        if cfn_types.target_of(rtype) != ref:
            return None
        if cfn_types.lookup_by(rtype) != by:
            return None
        physical = rc.item.get("PhysicalResourceId")
        return str(physical) if physical else None

    return values


def _target_links() -> tuple[LinkSpec, ...]:
    """One ``target`` LinkSpec per mapped collection (at most one hits)."""
    pairs: set[tuple[CollectionRef, Literal["key", "arn"]]] = {
        (ref, cfn_types.lookup_by(rtype))
        for rtype, ref in cfn_types.CFN_TYPES.items()}
    return tuple(
        LinkSpec("target", ref, _target_values(ref, by), by=by)
        for ref, by in sorted(pairs))


RESOURCES = CollectionSpec(
    name="resources",
    client="cloudformation",
    lister=_list_resources,
    key=lambda i: str(i.get("LogicalResourceId") or ""),
    ops=frozenset({"ListStackResources"}),
    tags=TagSpec.none(),
    files=(
        FileSpec("type", lambda rc: str(rc.item.get("ResourceType", ""))),
        FileSpec("physical-id",
                 lambda rc: str(rc.item.get("PhysicalResourceId") or "")),
        FileSpec("status",
                 lambda rc: str(rc.item.get("ResourceStatus", ""))),
    ),
    links=_target_links(),
)

STACKS = CollectionSpec(
    name="stacks",
    client="cloudformation",
    lister=_list_stacks,
    key=lambda i: str(i["StackName"]),
    ops=frozenset({"DescribeStacks", "GetTemplate"}),
    arn=_stack_arn,
    name_of=lambda i: i.get("StackName"),
    redact=REDACT_RULE,
    tags=TagSpec(inline="Tags", style="list"),
    files=(
        FileSpec("status", lambda rc: str(rc.item.get("StackStatus", ""))),
        FileSpec("outputs.json", _outputs, redact=REDACT_RULE),
        FileSpec("parameters.json", _parameters, redact=REDACT_RULE),
        FileSpec("template", _template, lazy=True, whole="template"),
    ),
    links=(
        LinkSpec("role", refs.IAM_ROLES,
                 lambda rc: rc.item.get("RoleARN"), by="arn"),
    ),
    children=(RESOURCES,),
)

SERVICE = ServiceSpec(
    dirname="cloudformation",
    scope="region",
    collections=(STACKS,),
)
