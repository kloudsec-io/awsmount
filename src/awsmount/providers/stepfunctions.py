"""AWS Step Functions provider: state machines.

ListStateMachines returns names only, so the listing stays one call and
``describe.json`` is lazy (one DescribeStateMachine when read). The
definition is free-form code that may embed credentials, so
``describe.json`` hides the raw ``definition`` string (the ``sfn`` rule
set) and ``definition.json`` shows it parsed, where the usual
secret-looking keys are hidden. Executions, their inputs and outputs and
their history are never read.
"""

from __future__ import annotations

import json
from typing import Any

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
from awsmount.providers.common import name_from_arn
from awsmount.vfs.render import Content

__all__ = ["SERVICE", "STATE_MACHINES"]


def _list_state_machines(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated ListStateMachines call (names and ARNs only)."""
    return [m for m in lc.paginate("list_state_machines", "stateMachines")
            if isinstance(m, dict)]


def _describe(rc: ResourceCtx) -> dict[str, Any]:
    """describe.json (lazy DescribeStateMachine)."""
    return rc.call("describe_state_machine",
                   stateMachineArn=str(rc.item["stateMachineArn"]))


def _definition(rc: ResourceCtx) -> Content:
    """definition.json: the parsed Amazon States Language document."""
    raw = rc.detail().get("definition")
    if not isinstance(raw, str):
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return raw


def _tags(rc: ResourceCtx) -> dict[str, str]:
    """Lazy tags (ListTagsForResource; the keys are lower case)."""
    resp = rc.call("list_tags_for_resource",
                   resourceArn=str(rc.item["stateMachineArn"]))
    out: dict[str, str] = {}
    for tag in resp.get("tags", []) or []:
        if isinstance(tag, dict) and "key" in tag:
            out[str(tag["key"])] = str(tag.get("value", ""))
    return out


def _strings(node: Any, found: list[str]) -> None:
    """Collect every string of a nested JSON value."""
    if isinstance(node, str):
        found.append(node)
    elif isinstance(node, dict):
        for value in node.values():
            _strings(value, found)
    elif isinstance(node, list):
        for value in node:
            _strings(value, found)


def _lambda_functions(rc: ResourceCtx) -> list[str]:
    """Lambda function ARNs named in the definition."""
    raw = rc.detail().get("definition")
    if not isinstance(raw, str):
        return []
    try:
        document = json.loads(raw)
    except ValueError:
        return []
    found: list[str] = []
    _strings(document, found)
    out: list[str] = []
    for value in found:
        if value.startswith("arn:") and ":lambda:" in value \
                and ":function:" in value and value not in out:
            out.append(value)
    return out


def _log_groups(rc: ResourceCtx) -> list[str]:
    config = rc.detail().get("loggingConfiguration")
    if not isinstance(config, dict):
        return []
    out: list[str] = []
    for dest in config.get("destinations") or []:
        group = (dest.get("cloudWatchLogsLogGroup")
                 if isinstance(dest, dict) else None)
        arn = group.get("logGroupArn") if isinstance(group, dict) else None
        if isinstance(arn, str) and arn:
            out.append(arn)
    return out


STATE_MACHINES = CollectionSpec(
    name="state-machines",
    client="stepfunctions",
    lister=_list_state_machines,
    key=lambda i: str(i["name"]),
    ops=frozenset({"ListStateMachines", "DescribeStateMachine",
                   "ListTagsForResource"}),
    arn=lambda i, _scope: (str(i["stateMachineArn"])
                           if i.get("stateMachineArn") else None),
    describe=_describe,
    redact="sfn",
    tags=TagSpec(fetch=_tags),
    files=(
        FileSpec("definition.json", _definition, lazy=True),
    ),
    links=(
        LinkSpec("role", refs.IAM_ROLES,
                 lambda rc: rc.detail().get("roleArn"), by="arn"),
        LinkSpec("lambda-functions", refs.LAMBDA_FUNCTIONS,
                 _lambda_functions, by="arn", many=True),
        LinkSpec("log-groups", refs.LOG_GROUPS, _log_groups, by="arn",
                 many=True),
    ),
    lookup={"arn": lambda i: str(i.get("stateMachineArn", "")),
            "name": lambda i: str(i.get("name", ""))},
    key_from_arn=name_from_arn,
)


SERVICE = ServiceSpec(
    dirname="stepfunctions",
    scope="region",
    collections=(STATE_MACHINES,),
)
