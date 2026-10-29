"""DynamoDB provider: tables (docs/coverage.md).

``ListTables`` only returns names, so the listing is one paginated call
and ``describe.json`` is a lazy ``DescribeTable``. Table items are never
read: no Scan, Query or GetItem operation is in the allow-list.
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

if TYPE_CHECKING:
    from awsmount.session.context import Scope

__all__ = ["SERVICE", "TABLES"]


def _list_tables(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated ListTables call for the region."""
    names = lc.paginate("list_tables", "TableNames")
    return [{"TableName": str(n)} for n in names]


def _table_arn(i: dict[str, Any], s: Scope) -> str | None:
    """Table ARN computed from the scope (no API call)."""
    account = s.account.account_id
    if not account:
        return None
    return (f"arn:{s.partition}:dynamodb:{s.region}:{account}"
            f":table/{i['TableName']}")


def _describe(rc: ResourceCtx) -> dict[str, Any]:
    """Lazy DescribeTable, cached by the context."""
    return rc.call("describe_table", TableName=rc.key)


def _ttl(rc: ResourceCtx) -> dict[str, Any]:
    """ttl.json: DescribeTimeToLive."""
    return rc.call("describe_time_to_live", TableName=rc.key)


def _backups(rc: ResourceCtx) -> dict[str, Any]:
    """continuous-backups.json: DescribeContinuousBackups."""
    return rc.call("describe_continuous_backups", TableName=rc.key)


def _tags(rc: ResourceCtx) -> dict[str, str]:
    """Tags from ListTagsOfResource (paginated)."""
    arn = _table_arn(rc.item, rc.scope)
    if arn is None:
        return {}
    rows = rc.paginate("list_tags_of_resource", "Tags", ResourceArn=arn)
    return {str(r["Key"]): str(r.get("Value", "")) for r in rows
            if isinstance(r, dict) and "Key" in r}


def _kms_key(rc: ResourceCtx) -> str | None:
    """KMS key id of the table, derived from the cached describe.

    The id is extracted from ``KMSMasterKeyArn`` so the link resolves
    by key (id-keyed, no listing call). Keys of another account or
    region, and alias references, are not linked.
    """
    table = rc.detail().get("Table") or {}
    sse = table.get("SSEDescription") or {}
    value = sse.get("KMSMasterKeyArn")
    if not isinstance(value, str) or not value:
        return None
    if not value.startswith("arn:"):
        if value.startswith("alias/") or "/" in value:
            return None
        return value
    parts = value.split(":", 5)
    if len(parts) != 6:
        return None
    region, account, resource = parts[3], parts[4], parts[5]
    if region != rc.scope.region:
        return None
    if account != (rc.scope.account.account_id or ""):
        return None
    if not resource.startswith("key/"):
        return None
    key_id = resource[len("key/"):]
    return key_id or None


def _key_from_arn(arn: str) -> str:
    """Table name from a table (or index/stream) ARN."""
    resource = arn.split(":table/", 1)[-1]
    return resource.split("/", 1)[0]


TABLES = CollectionSpec(
    name="tables",
    client="dynamodb",
    lister=_list_tables,
    key=lambda i: str(i["TableName"]),
    ops=frozenset({"ListTables", "DescribeTable", "DescribeTimeToLive",
                   "DescribeContinuousBackups", "ListTagsOfResource"}),
    arn=_table_arn,
    describe=_describe,
    tags=TagSpec(fetch=_tags),
    files=(
        FileSpec("ttl.json", _ttl, lazy=True),
        FileSpec("continuous-backups.json", _backups, lazy=True),
    ),
    links=(
        LinkSpec("kms-key", refs.KMS_KEYS, _kms_key),
    ),
    key_from_arn=_key_from_arn,
)

SERVICE = ServiceSpec(dirname="dynamodb", scope="region",
                      collections=(TABLES,))
