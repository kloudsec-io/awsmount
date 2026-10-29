"""Amazon API Gateway (REST) provider (docs/coverage.md).

Collection: rest-apis. One paginated ``GetRestApis`` call lists the
region. The directory name is the API name, and the key is the API id.
``describe.json``, ``endpoint-type`` and the inline tags are derived
from the listing. Resources, stages, deployments and authorizers are
lazy. Stage variables are redacted (rule ``apigw-stages``). API keys,
exports and SDKs are never fetched (their operations are denied).
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
from awsmount.providers.common import make_arn, name_from_arn
from awsmount.vfs.render import Content

if TYPE_CHECKING:
    from awsmount.session.context import Scope

__all__ = ["REST_APIS", "SERVICE"]

PAGE_LIMIT = 500


def _list_rest_apis(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated GetRestApis call for the region."""
    return [a for a in lc.paginate("get_rest_apis", "items")
            if isinstance(a, dict) and a.get("id")]


def _display(item: dict[str, Any]) -> str:
    """API name, or the id when unnamed."""
    name = item.get("name")
    return str(name) if name else str(item["id"])


def _api_arn(item: dict[str, Any], scope: Scope) -> str | None:
    """``arn:<p>:apigateway:<region>::/restapis/<id>``."""
    ident = item.get("id")
    if not ident:
        return None
    return make_arn(scope, "apigateway", f"/restapis/{ident}", account="")


def _endpoint_type(rc: ResourceCtx) -> Content:
    """endpoint-type: one endpoint type per line."""
    config = rc.item.get("endpointConfiguration")
    types = config.get("types") if isinstance(config, dict) else None
    return "\n".join(str(t) for t in types or [] if t)


def _resources(rc: ResourceCtx) -> Content:
    """resources.json (lazy, paginated GetResources)."""
    return rc.paginate("get_resources", "items", restApiId=rc.key)


def _stages(rc: ResourceCtx) -> Content:
    """stages.json (lazy GetStages; stage variables redacted)."""
    result: Content = rc.call("get_stages", restApiId=rc.key)
    return result


def _deployments(rc: ResourceCtx) -> Content:
    """deployments.json (lazy, paginated GetDeployments)."""
    return rc.paginate("get_deployments", "items", restApiId=rc.key)


def _authorizers(rc: ResourceCtx) -> Content:
    """authorizers.json (lazy GetAuthorizers, ``position``-paged)."""
    items: list[Any] = []
    position: str | None = None
    seen: set[str] = set()
    while True:
        params: dict[str, Any] = {"restApiId": rc.key,
                                  "limit": PAGE_LIMIT}
        if position:
            params["position"] = position
        resp = rc.call("get_authorizers", **params)
        items.extend(resp.get("items", []) or [])
        position = resp.get("position")
        if not position or position in seen:
            break
        seen.add(position)
    return items


REST_APIS = CollectionSpec(
    name="rest-apis",
    client="apigateway",
    lister=_list_rest_apis,
    key=lambda i: str(i["id"]),
    ops=frozenset({"GetRestApis", "GetResources", "GetStages",
                   "GetDeployments", "GetAuthorizers"}),
    display=_display,
    arn=_api_arn,
    name_of=lambda i: i.get("name"),
    tags=TagSpec(inline="tags", style="map"),
    files=(
        FileSpec("endpoint-type", _endpoint_type),
        FileSpec("resources.json", _resources, lazy=True),
        FileSpec("stages.json", _stages, lazy=True,
                 redact="apigw-stages"),
        FileSpec("deployments.json", _deployments, lazy=True),
        FileSpec("authorizers.json", _authorizers, lazy=True),
    ),
    lookup={"name": lambda i: str(i.get("name", ""))},
    key_from_arn=name_from_arn,
)


SERVICE = ServiceSpec(
    dirname="apigateway",
    scope="region",
    collections=(
        REST_APIS,
    ),
)
