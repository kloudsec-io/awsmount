"""ARN/id helpers shared by providers."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, TypeVar

if TYPE_CHECKING:
    from awsmount.session.context import Scope

__all__ = [
    "Arn",
    "as_list",
    "chunks",
    "get_path",
    "is_arn",
    "kms_key_from_arn",
    "kms_ref",
    "make_arn",
    "name_from_arn",
    "parse_arn",
    "parse_json_text",
    "resource_from_arn",
]

T = TypeVar("T")


@dataclass(frozen=True)
class Arn:
    """Parsed ARN components."""

    partition: str
    service: str
    region: str
    account: str
    resource: str

    @property
    def resource_id(self) -> str:
        """Last segment of the resource part."""
        return _last_segment(self.resource)


def _last_segment(resource: str) -> str:
    for sep in ("/", ":"):
        if sep in resource:
            resource = resource.rsplit(sep, 1)[-1]
    return resource


def parse_arn(value: Any) -> Arn | None:
    """Parse ``value`` as an ARN; None if it is not one."""
    if not isinstance(value, str) or not value.startswith("arn:"):
        return None
    parts = value.split(":", 5)
    if len(parts) != 6:
        return None
    return Arn(parts[1], parts[2], parts[3], parts[4], parts[5])


def is_arn(value: Any) -> bool:
    """True when ``value`` looks like an ARN."""
    return parse_arn(value) is not None


def resource_from_arn(arn: str) -> str:
    """Resource part of an ARN (input unchanged if not an ARN)."""
    parsed = parse_arn(arn)
    return parsed.resource if parsed is not None else arn


def name_from_arn(arn: str) -> str:
    """Last ``/`` or ``:`` segment of an ARN's resource part."""
    parsed = parse_arn(arn)
    if parsed is None:
        return _last_segment(arn)
    return parsed.resource_id


def kms_key_from_arn(arn: str) -> str:
    """Key id from ``arn:...:kms:...:key/<id>``."""
    resource = resource_from_arn(arn)
    if resource.startswith("key/"):
        return resource[len("key/"):]
    return _last_segment(resource)


def kms_ref(value: str | None) -> str | None:
    """Link value for a KMS key reference (ARN or key id).

    Alias references and non-key ARNs give None (no link).
    """
    if not value:
        return None
    if value.startswith("alias/"):
        return None
    parsed = parse_arn(value)
    if parsed is None:
        return value
    if parsed.service == "kms" and parsed.resource.startswith("key/"):
        return value
    return None


def make_arn(scope: Scope, service: str, resource: str, *,
             region: str | None = None, account: str | None = None,
             regional: bool = True) -> str:
    """Build an ARN in the scope's partition/account/region."""
    acct = account if account is not None else (
        scope.account.account_id or "")
    reg = (region if region is not None else scope.region) if regional \
        else ""
    return f"arn:{scope.partition}:{service}:{reg}:{acct}:{resource}"


def chunks(seq: Sequence[T], size: int) -> Iterator[list[T]]:
    """Split ``seq`` into lists of at most ``size`` items."""
    if size < 1:
        raise ValueError("size must be >= 1")
    for start in range(0, len(seq), size):
        yield list(seq[start:start + size])


def parse_json_text(value: Any) -> Any:
    """Parse JSON text (e.g. a policy document); other values unchanged."""
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", "replace")
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value


def get_path(data: Any, dotted: str, default: Any = None) -> Any:
    """Look up ``a.b.c`` in nested dicts."""
    cur = data
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def as_list(value: str | Iterable[str] | None) -> list[str]:
    """Normalise a link value into a list of non-empty strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    return [v for v in value if isinstance(v, str) and v]


def drop_dead(items: list[dict[str, Any]],
              state_of: Callable[[dict[str, Any]], Any],
              dead: frozenset[str]) -> list[dict[str, Any]]:
    """Remove resources AWS still reports in a terminal state.

    AWS keeps returning terminated instances, deleted NAT gateways,
    Transit Gateways, endpoints and peering connections for up to an
    hour after deletion. They no longer exist for any practical purpose,
    so they are not shown as directories.
    """
    return [i for i in items if str(state_of(i) or "").lower() not in dead]
