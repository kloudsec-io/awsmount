"""Amazon EventBridge provider: event buses with their rules.

Collections: event-buses, with nested ``rules``. ListEventBuses (not
paginated by botocore, so followed by ``NextToken``) and ListRules return
the full description of each bus and rule, so ``describe.json`` and the
small files are derived from the listings. Tags and ``targets.json`` are
lazy. The targets hold static ``Input`` text and HTTP header and query
values that can carry credentials, so they use the ``eventbridge-targets``
rule set. Events, archives, connections and API destinations are not
covered.
"""

from __future__ import annotations

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
from awsmount.providers.ec2 import field_text
from awsmount.vfs.render import Content

__all__ = ["EVENT_BUSES", "RULES", "SERVICE"]


def _tags_of(arn_field: str) -> Any:
    """Lazy tag fetcher using ListTagsForResource on ``arn_field``."""

    def fetch(rc: ResourceCtx) -> dict[str, str]:
        arn = rc.item.get(arn_field)
        if not arn:
            return {}
        resp = rc.call("list_tags_for_resource", ResourceARN=str(arn))
        out: dict[str, str] = {}
        for tag in resp.get("Tags", []) or []:
            if isinstance(tag, dict) and "Key" in tag:
                out[str(tag["Key"])] = str(tag.get("Value", ""))
        return out

    return fetch


# -- rules (nested under an event bus) --


def _list_rules(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated ListRules call for the parent bus."""
    parent = lc.parent
    if parent is None:
        return []
    return [r for r in lc.paginate("list_rules", "Rules",
                                   EventBusName=parent.key)
            if isinstance(r, dict)]


def _targets(rc: ResourceCtx) -> Content:
    """targets.json (lazy, paginated ListTargetsByRule)."""
    bus = rc.item.get("EventBusName") or (
        rc.parent.key if rc.parent else "default")
    return rc.paginate("list_targets_by_rule", "Targets",
                       Rule=str(rc.item["Name"]), EventBusName=str(bus))


RULES = CollectionSpec(
    name="rules",
    client="events",
    lister=_list_rules,
    key=lambda i: str(i["Name"]),
    ops=frozenset({"ListRules", "ListTargetsByRule",
                   "ListTagsForResource"}),
    arn=lambda i, _scope: str(i["Arn"]) if i.get("Arn") else None,
    tags=TagSpec(fetch=_tags_of("Arn")),
    files=(
        FileSpec("state", field_text("State")),
        FileSpec("schedule", field_text("ScheduleExpression")),
        FileSpec("targets.json", _targets, lazy=True,
                 redact="eventbridge-targets"),
    ),
    links=(
        LinkSpec("role", refs.IAM_ROLES,
                 lambda rc: rc.item.get("RoleArn"), by="arn"),
    ),
    lookup={"arn": lambda i: str(i.get("Arn", "")),
            "name": lambda i: str(i.get("Name", ""))},
)


# -- event buses --


def _list_buses(lc: ListCtx) -> list[dict[str, Any]]:
    """ListEventBuses, following ``NextToken``."""
    buses: list[dict[str, Any]] = []
    token: str | None = None
    while True:
        params = {"NextToken": token} if token else {}
        resp = lc.call("list_event_buses", **params)
        buses += [b for b in resp.get("EventBuses", []) or []
                  if isinstance(b, dict)]
        token = resp.get("NextToken")
        if not token:
            return buses


EVENT_BUSES = CollectionSpec(
    name="event-buses",
    client="events",
    lister=_list_buses,
    key=lambda i: str(i["Name"]),
    ops=frozenset({"ListEventBuses", "ListTagsForResource"}),
    arn=lambda i, _scope: str(i["Arn"]) if i.get("Arn") else None,
    tags=TagSpec(fetch=_tags_of("Arn")),
    children=(RULES,),
    lookup={"arn": lambda i: str(i.get("Arn", "")),
            "name": lambda i: str(i.get("Name", ""))},
)


SERVICE = ServiceSpec(
    dirname="eventbridge",
    scope="region",
    collections=(EVENT_BUSES,),
)
