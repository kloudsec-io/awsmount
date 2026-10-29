"""AWS Lambda provider: functions (docs/coverage.md).

Functions are listed with one paginated ListFunctions call.
``describe.json`` is derived from that listing and its environment
variable values are redacted (rule ``lambda``). The resource policy,
aliases, event source mappings, function URL configs and tags are lazy
files. Function code is never fetched (GetFunction is denied).
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
from awsmount.providers.common import (
    kms_ref,
    name_from_arn,
    parse_json_text,
    resource_from_arn,
)
from awsmount.providers.ec2 import field_text
from awsmount.vfs.render import Content

if TYPE_CHECKING:
    from awsmount.session.context import Scope

__all__ = ["FUNCTIONS", "SERVICE", "function_key_from_arn"]

LOG_GROUP_PREFIX = "/aws/lambda/"


def function_key_from_arn(arn: str) -> str:
    """Function name from ``...:function:<name>[:<qualifier>]``."""
    parts = resource_from_arn(arn).split(":")
    if len(parts) >= 2 and parts[0] == "function":
        return parts[1]
    return name_from_arn(arn)


def _list_functions(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated ListFunctions call for the region."""
    return [i for i in lc.paginate("list_functions", "Functions")
            if isinstance(i, dict)]


def _strings(value: Any) -> list[str]:
    """Non-empty strings of a list field."""
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, str) and v]


def _vpc_config(rc: ResourceCtx) -> dict[str, Any]:
    """VpcConfig of the function ({} when absent)."""
    config = rc.item.get("VpcConfig")
    return config if isinstance(config, dict) else {}


def _policy(rc: ResourceCtx) -> Content:
    """policy.json: parsed resource policy (lazy GetPolicy)."""
    resp = rc.call("get_policy", FunctionName=rc.key)
    return parse_json_text(resp.get("Policy"))  # type: ignore[no-any-return]


def _aliases(rc: ResourceCtx) -> Content:
    """aliases.json (lazy, paginated ListAliases)."""
    return rc.paginate("list_aliases", "Aliases", FunctionName=rc.key)


def _event_sources(rc: ResourceCtx) -> Content:
    """event-source-mappings.json (lazy ListEventSourceMappings)."""
    return rc.paginate("list_event_source_mappings", "EventSourceMappings",
                       FunctionName=rc.key)


def _url_configs(rc: ResourceCtx) -> Content:
    """url-config.json (lazy, paginated ListFunctionUrlConfigs)."""
    return rc.paginate("list_function_url_configs", "FunctionUrlConfigs",
                       FunctionName=rc.key)


def _tags(rc: ResourceCtx) -> dict[str, str]:
    """Tags from ListTags on the function ARN."""
    arn = rc.item.get("FunctionArn")
    if not arn:
        return {}
    resp = rc.call("list_tags", Resource=str(arn))
    tags = resp.get("Tags") or {}
    return {str(k): str(v) for k, v in tags.items()}


def _log_group(rc: ResourceCtx) -> str | None:
    """Configured log group, defaulting to ``/aws/lambda/<name>``."""
    config = rc.item.get("LoggingConfig")
    if isinstance(config, dict):
        group = config.get("LogGroup")
        if isinstance(group, str) and group:
            return group
    return f"{LOG_GROUP_PREFIX}{rc.key}"


def _arn(item: dict[str, Any], scope: Scope) -> str | None:
    """Function ARN as listed."""
    arn = item.get("FunctionArn")
    return str(arn) if arn else None


FUNCTIONS = CollectionSpec(
    name="functions",
    client="lambda",
    lister=_list_functions,
    key=lambda i: str(i["FunctionName"]),
    ops=frozenset({"ListFunctions", "GetPolicy", "ListAliases",
                   "ListEventSourceMappings", "ListFunctionUrlConfigs",
                   "ListTags"}),
    arn=_arn,
    redact="lambda",
    tags=TagSpec(fetch=_tags),
    files=(
        FileSpec("runtime", field_text("Runtime")),
        FileSpec("policy.json", _policy, lazy=True,
                 not_configured=frozenset({"ResourceNotFoundException"})),
        FileSpec("aliases.json", _aliases, lazy=True),
        FileSpec("event-source-mappings.json", _event_sources, lazy=True),
        FileSpec("url-config.json", _url_configs, lazy=True),
    ),
    links=(
        LinkSpec("role", refs.IAM_ROLES, lambda rc: rc.item.get("Role"),
                 by="arn"),
        LinkSpec("vpc", refs.VPCS,
                 lambda rc: _vpc_config(rc).get("VpcId")),
        LinkSpec("subnets", refs.SUBNETS,
                 lambda rc: _strings(_vpc_config(rc).get("SubnetIds")),
                 many=True),
        LinkSpec("security-groups", refs.SECURITY_GROUPS,
                 lambda rc: _strings(
                     _vpc_config(rc).get("SecurityGroupIds")),
                 many=True),
        LinkSpec("kms-key", refs.KMS_KEYS,
                 lambda rc: kms_ref(rc.item.get("KMSKeyArn"))),
        LinkSpec("log-group", refs.LOG_GROUPS, _log_group),
    ),
    lookup={"arn": lambda i: str(i.get("FunctionArn", "")),
            "name": lambda i: str(i.get("FunctionName", ""))},
    key_from_arn=function_key_from_arn,
)


SERVICE = ServiceSpec(
    dirname="lambda",
    scope="region",
    collections=(FUNCTIONS,),
)
