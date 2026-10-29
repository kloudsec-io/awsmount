"""Canonical JSON/text serialisation (ARCHITECTURE: Nodes and rendering)."""

from __future__ import annotations

import base64
import json
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Any, TypeAlias

__all__ = [
    "Content",
    "JSONValue",
    "JSON_CONTENT_TYPE",
    "TEXT_CONTENT_TYPE",
    "canonical_json",
    "content_type_for",
    "render",
    "stabilize",
    "strip_metadata",
    "to_json_text",
]

JSONValue: TypeAlias = (
    dict[str, Any] | list[Any] | str | int | float | bool | None
)
Content: TypeAlias = bytes | JSONValue

JSON_CONTENT_TYPE = "application/json"
TEXT_CONTENT_TYPE = "text/plain; charset=utf-8"
METADATA_KEY = "ResponseMetadata"


def _default(obj: Any) -> Any:
    """Convert non-JSON types produced by boto3."""
    if isinstance(obj, datetime):
        if obj.tzinfo is None:
            obj = obj.replace(tzinfo=timezone.utc)
        return obj.isoformat()
    if isinstance(obj, date):
        return obj.isoformat()
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return base64.b64encode(bytes(obj)).decode("ascii")
    if isinstance(obj, Decimal):
        if obj.is_finite() and obj == obj.to_integral_value():
            return int(obj)
        return float(obj)
    if isinstance(obj, (set, frozenset)):
        try:
            return sorted(obj)
        except TypeError:
            return sorted(obj, key=repr)
    raise TypeError(f"Object of type {type(obj).__name__} "
                    "is not JSON serializable")


def strip_metadata(obj: Any) -> Any:
    """Remove ``ResponseMetadata`` from a response or list of pages."""
    if isinstance(obj, dict):
        return {k: v for k, v in obj.items() if k != METADATA_KEY}
    if isinstance(obj, list):
        return [strip_metadata(x) if isinstance(x, dict) else x
                for x in obj]
    return obj


# Lists whose order carries no meaning, but which AWS does not return in a
# stable order from one call to the next (seen on a real account: two
# route-table associations swapped between two exports). They are sorted so
# that snapshots, ``diff -r`` and ``git diff`` stay quiet. Every other list
# keeps the API order, because for many of them it matters (Lambda layer
# precedence, CloudFront cache behaviors, policy conditions...).
# field name -> identifier fields to sort dict elements by (first present
# in every element); with none present, elements sort by their JSON text.
UNORDERED_LISTS: dict[str, tuple[str, ...]] = {
    "Associations": ("RouteTableAssociationId", "NetworkAclAssociationId",
                     "AssociationId"),
    "Tags": ("Key",),
    "TagList": ("Key",),
    "SecurityGroups": ("GroupId", "SecurityGroupId"),
    "VpcSecurityGroups": ("VpcSecurityGroupId",),
    "Groups": ("GroupId",),
    "NetworkInterfaces": ("NetworkInterfaceId",),
    "BlockDeviceMappings": ("DeviceName",),
    "IpPermissions": (),
    "IpPermissionsEgress": (),
    "SubnetIds": (),
    "SecurityGroupIds": (),
}


def _sort_key(item: Any, fields: tuple[str, ...]) -> tuple[int, str]:
    """Total order over list elements (ids first, JSON text otherwise)."""
    if isinstance(item, dict):
        for name in fields:
            value = item.get(name)
            if isinstance(value, str):
                return (0, value)
    if isinstance(item, str):
        return (0, item)
    return (1, canonical_json(item))


def stabilize(obj: Any) -> Any:
    """Return ``obj`` with the known-unordered lists in a stable order."""
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for key, value in obj.items():
            value = stabilize(value)
            fields = UNORDERED_LISTS.get(key) if isinstance(key, str) \
                else None
            if fields is not None and isinstance(value, list):
                value = sorted(value, key=lambda x: _sort_key(x, fields))
            out[key] = value
        return out
    if isinstance(obj, list):
        return [stabilize(x) for x in obj]
    return obj


def to_json_text(obj: Any) -> str:
    """Pretty, sorted, deterministic JSON text with a final newline."""
    return json.dumps(stabilize(obj), indent=2, sort_keys=True,
                      ensure_ascii=False, default=_default) + "\n"


def canonical_json(obj: Any) -> str:
    """Compact deterministic JSON, used for cache keys."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=_default)


def render(content: Content) -> bytes:
    """Render node content into the bytes served to readers."""
    if isinstance(content, bytes):
        return content
    if isinstance(content, (bytearray, memoryview)):
        return bytes(content)
    if isinstance(content, str):
        text = content if content.endswith("\n") else content + "\n"
        return text.encode("utf-8", "surrogateescape")
    return to_json_text(strip_metadata(content)).encode("utf-8")


def content_type_for(name: str) -> str:
    """Return the MIME type for a file name."""
    if name.endswith(".json"):
        return JSON_CONTENT_TYPE
    return TEXT_CONTENT_TYPE
