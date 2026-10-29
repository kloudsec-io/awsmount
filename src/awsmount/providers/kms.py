"""KMS provider (docs/coverage.md).

Collections: keys and aliases. ``ListKeys`` returns ids only, so the
key listing is one paginated call and ``describe.json`` (DescribeKey)
is lazy, as are policy.json, rotation.json and the tags. Aliases are
fully derived from one paginated ``ListAliases`` call, which also
feeds each key's ``links/aliases/``. No cryptographic operation is
ever made.
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
from awsmount.providers.common import kms_key_from_arn, parse_json_text
from awsmount.vfs.render import Content

if TYPE_CHECKING:
    from awsmount.session.context import Scope

__all__ = ["ALIASES", "KEYS", "SERVICE"]

ALIAS_PREFIX = "alias/"


def _alias_key(item: dict[str, Any]) -> str:
    """Alias name without the ``alias/`` prefix."""
    name = str(item.get("AliasName", ""))
    if name.startswith(ALIAS_PREFIX):
        return name[len(ALIAS_PREFIX):]
    return name


def _alias_key_from_arn(arn: str) -> str:
    """Alias key from ``arn:...:alias/<name>``."""
    marker = ":" + ALIAS_PREFIX
    if marker in arn:
        return arn.split(marker, 1)[1]
    return arn


# -- keys --


def _list_keys(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated ListKeys call for the region."""
    return [k for k in lc.paginate("list_keys", "Keys")
            if isinstance(k, dict) and k.get("KeyId")]


def _describe_key(rc: ResourceCtx) -> dict[str, Any]:
    """describe.json of a key (lazy DescribeKey)."""
    return rc.call("describe_key", KeyId=rc.key)


def _key_policy(rc: ResourceCtx) -> Content:
    """policy.json: the parsed default key policy."""
    resp = rc.call("get_key_policy", KeyId=rc.key, PolicyName="default")
    policy = resp.get("Policy")
    if not policy:
        return None
    return parse_json_text(policy)  # type: ignore[no-any-return]


def _rotation(rc: ResourceCtx) -> Content:
    """rotation.json: key rotation status."""
    return rc.call("get_key_rotation_status", KeyId=rc.key)


def _key_tags(rc: ResourceCtx) -> dict[str, str]:
    """Tags of a key from ListResourceTags (Marker-paginated).

    Stops when a marker repeats or a truncated page brings no tags, so
    a misbehaving endpoint cannot make the (cached) loop spin forever.
    """
    tags: list[Any] = []
    marker: str | None = None
    seen: set[str] = set()
    while True:
        params: dict[str, Any] = {"KeyId": rc.key}
        if marker:
            params["Marker"] = marker
        resp = rc.call("list_resource_tags", **params)
        page = resp.get("Tags", []) or []
        tags.extend(page)
        marker = resp.get("NextMarker")
        if not resp.get("Truncated") or not marker or marker in seen \
                or not page:
            break
        seen.add(marker)
    return {str(t["TagKey"]): str(t.get("TagValue", ""))
            for t in tags if isinstance(t, dict) and "TagKey" in t}


def _key_aliases(rc: ResourceCtx) -> list[str]:
    """Aliases pointing at this key (from the cached alias listing)."""
    aliases = rc.paginate("list_aliases", "Aliases")
    return sorted(_alias_key(a) for a in aliases
                  if isinstance(a, dict)
                  and a.get("TargetKeyId") == rc.key)


def _key_arn(item: dict[str, Any], scope: Scope) -> str | None:
    """ARN of a key as listed."""
    arn = item.get("KeyArn")
    return str(arn) if arn else None


KEYS = CollectionSpec(
    name="keys",
    client="kms",
    lister=_list_keys,
    key=lambda i: str(i["KeyId"]),
    ops=frozenset({"ListKeys", "DescribeKey", "GetKeyPolicy",
                   "GetKeyRotationStatus", "ListResourceTags",
                   "ListAliases"}),
    arn=_key_arn,
    describe=_describe_key,
    tags=TagSpec(fetch=_key_tags),
    files=(
        FileSpec("policy.json", _key_policy, lazy=True),
        FileSpec("rotation.json", _rotation, lazy=True,
                 not_configured=frozenset(
                     {"UnsupportedOperationException"})),
    ),
    links=(
        LinkSpec("aliases", refs.KMS_ALIASES, _key_aliases, many=True),
    ),
    lookup={"arn": lambda i: str(i.get("KeyArn", ""))},
    key_from_arn=kms_key_from_arn,
)


# -- aliases --


def _list_aliases(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated ListAliases call for the region."""
    return [a for a in lc.paginate("list_aliases", "Aliases")
            if isinstance(a, dict) and a.get("AliasName")]


def _alias_arn(item: dict[str, Any], scope: Scope) -> str | None:
    """ARN of an alias as listed."""
    arn = item.get("AliasArn")
    return str(arn) if arn else None


ALIASES = CollectionSpec(
    name="aliases",
    client="kms",
    lister=_list_aliases,
    key=_alias_key,
    ops=frozenset({"ListAliases"}),
    arn=_alias_arn,
    tags=TagSpec.none(),
    links=(
        LinkSpec("target-key", refs.KMS_KEYS,
                 lambda rc: rc.item.get("TargetKeyId")),
    ),
    lookup={"arn": lambda i: str(i.get("AliasArn", "")),
            "name": lambda i: str(i.get("AliasName", ""))},
    key_from_arn=_alias_key_from_arn,
)


SERVICE = ServiceSpec(
    dirname="kms",
    scope="region",
    collections=(
        KEYS,
        ALIASES,
    ),
)
