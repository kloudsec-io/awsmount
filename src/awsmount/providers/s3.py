"""S3 provider (docs/coverage.md).

Collection: buckets. ``ListBuckets`` is a global call: it is made once
in the account's global region and cached, then filtered per region by
``BucketRegion``. When an endpoint omits ``BucketRegion``,
``GetBucketLocation`` is called once per bucket (cached, budgeted).
``describe.json`` is derived from the listing; policy, encryption,
public-access-block, versioning and tags are lazy files. Object bodies
are never read. Object keys are listed only with ``--s3-objects N``
(N > 0); otherwise ``objects/`` is empty and ``objects-listing.json``
is ``null`` and no listing call is made.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from awsmount.errors import UpstreamError
from awsmount.providers.base import (
    CollectionSpec,
    FileSpec,
    ListCtx,
    ResourceCtx,
    ServiceSpec,
    SubdirSpec,
    TagSpec,
)
from awsmount.providers.common import (
    make_arn,
    parse_json_text,
    resource_from_arn,
)
from awsmount.vfs.render import Content

if TYPE_CHECKING:
    from awsmount.session.context import Scope

__all__ = ["BUCKETS", "SERVICE", "bucket_from_arn"]

DEFAULT_LOCATION = "us-east-1"
LOCATION_ALIASES = {"EU": "eu-west-1"}
NOT_PAGEABLE = "OperationNotPageableError"
MAX_KEYS_PER_PAGE = 1000
OBJECT_FIELDS = ("Key", "Size", "ETag", "LastModified", "StorageClass")


# -- listing --


def _global_scope(lc: ListCtx) -> Scope:
    """Scope of the account's global region (shared ListBuckets cache)."""
    return dataclasses.replace(lc.scope,
                               region=lc.scope.account.global_region)


def _all_buckets(lc: ListCtx) -> list[dict[str, Any]]:
    """One ListBuckets for the account, cached across regions.

    Falls back to a single unpaginated call on botocore versions that
    lack the ListBuckets paginator.
    """
    scope = _global_scope(lc)
    client = lc.spec.client
    try:
        items = lc.ctx.paginate(scope, client, "list_buckets", "Buckets")
    except UpstreamError as exc:
        if exc.code != NOT_PAGEABLE:
            raise
        resp = lc.ctx.call(scope, client, "list_buckets")
        items = list(resp.get("Buckets", []) or [])
    return [b for b in items if isinstance(b, dict) and b.get("Name")]


def _location(lc: ListCtx, name: str) -> str | None:
    """Bucket region from GetBucketLocation (None if it fails)."""
    scope = _global_scope(lc)
    try:
        resp = lc.ctx.call(scope, lc.spec.client, "get_bucket_location",
                           Bucket=name)
    except UpstreamError as exc:
        lc.ctx.errors.record(lc.scope, lc.spec.client,
                             "get_bucket_location", exc)
        return None
    loc = resp.get("LocationConstraint")
    if not loc:
        return DEFAULT_LOCATION
    return LOCATION_ALIASES.get(str(loc), str(loc))


def _list_buckets(lc: ListCtx) -> list[dict[str, Any]]:
    """Buckets of the account located in this scope's region."""
    out: list[dict[str, Any]] = []
    for bucket in _all_buckets(lc):
        region = bucket.get("BucketRegion")
        if not region:
            region = _location(lc, str(bucket["Name"]))
        if region == lc.scope.region:
            out.append(bucket)
    return out


# -- lazy files --


def _region(rc: ResourceCtx) -> Content:
    """region: the region the bucket was listed in."""
    return rc.scope.region


def _policy(rc: ResourceCtx) -> Content:
    """policy.json: the parsed bucket policy."""
    resp = rc.call("get_bucket_policy", Bucket=rc.key)
    return parse_json_text(resp.get("Policy"))  # type: ignore[no-any-return]


def _encryption(rc: ResourceCtx) -> Content:
    """encryption.json: the server-side encryption configuration."""
    resp = rc.call("get_bucket_encryption", Bucket=rc.key)
    return resp.get("ServerSideEncryptionConfiguration")


def _public_access_block(rc: ResourceCtx) -> Content:
    """public-access-block.json: the bucket's public access block."""
    resp = rc.call("get_public_access_block", Bucket=rc.key)
    return resp.get("PublicAccessBlockConfiguration")


def _versioning(rc: ResourceCtx) -> Content:
    """versioning.json: Status/MFADelete ({} if never enabled)."""
    return rc.call("get_bucket_versioning", Bucket=rc.key)


def _objects(rc: ResourceCtx) -> list[dict[str, Any]]:
    """First ``--s3-objects`` keys (metadata only), ListObjectsV2.

    Stops when a continuation token repeats or a truncated page brings
    no keys, so a misbehaving endpoint cannot make the (cached) loop
    spin forever.
    """
    limit = int(rc.ctx.config.s3_objects)
    out: list[dict[str, Any]] = []
    token: str | None = None
    seen: set[str] = set()
    while len(out) < limit:
        params: dict[str, Any] = {
            "Bucket": rc.key,
            "MaxKeys": min(MAX_KEYS_PER_PAGE, limit - len(out)),
        }
        if token:
            params["ContinuationToken"] = token
        resp = rc.call("list_objects_v2", **params)
        added = 0
        for obj in resp.get("Contents", []) or []:
            if isinstance(obj, dict) and "Key" in obj:
                out.append({f: obj.get(f) for f in OBJECT_FIELDS})
                added += 1
        token = resp.get("NextContinuationToken")
        if not resp.get("IsTruncated") or not token or token in seen \
                or added == 0:
            break
        seen.add(token)
    return out[:limit]


def _objects_listing(rc: ResourceCtx) -> Content:
    """objects-listing.json: null unless ``--s3-objects N`` > 0."""
    if rc.ctx.config.s3_objects <= 0:
        return None
    return _objects(rc)


def _const(value: Content) -> Callable[[], Content]:
    def render() -> Content:
        return value
    return render


def _object_entries(rc: ResourceCtx
                    ) -> dict[str, Callable[[], Content]]:
    """objects/<escaped key>.json, one per listed object."""
    if rc.ctx.config.s3_objects <= 0:
        return {}
    return {f"{obj['Key']}.json": _const(obj) for obj in _objects(rc)}


def _bucket_tags(rc: ResourceCtx) -> dict[str, str]:
    """Tags from GetBucketTagging (NoSuchTagSet gives no tags)."""
    try:
        resp = rc.call("get_bucket_tagging", Bucket=rc.key)
    except UpstreamError as exc:
        if exc.code == "NoSuchTagSet":
            return {}
        raise
    return {str(t["Key"]): str(t.get("Value", ""))
            for t in resp.get("TagSet", []) or []
            if isinstance(t, dict) and "Key" in t}


# -- identity --


def _bucket_arn(item: dict[str, Any], scope: Scope) -> str | None:
    """``arn:<partition>:s3:::<bucket>``."""
    name = item.get("Name")
    if not name:
        return None
    return make_arn(scope, "s3", str(name), account="", regional=False)


def bucket_from_arn(arn: str) -> str:
    """Bucket name from a bucket or object ARN."""
    return resource_from_arn(arn).split("/", 1)[0]


BUCKETS = CollectionSpec(
    name="buckets",
    client="s3",
    lister=_list_buckets,
    key=lambda i: str(i["Name"]),
    ops=frozenset({"ListBuckets", "GetBucketLocation", "GetBucketPolicy",
                   "GetBucketEncryption", "GetPublicAccessBlock",
                   "GetBucketVersioning", "GetBucketTagging",
                   "ListObjectsV2"}),
    # display == key: links to buckets of other (or unmounted) regions
    # are omitted instead of dangling.
    display=lambda i: str(i["Name"]),
    arn=_bucket_arn,
    tags=TagSpec(fetch=_bucket_tags),
    files=(
        FileSpec("region", _region),
        FileSpec("policy.json", _policy, lazy=True,
                 not_configured=frozenset({"NoSuchBucketPolicy"})),
        FileSpec("encryption.json", _encryption, lazy=True,
                 not_configured=frozenset(
                     {"ServerSideEncryptionConfigurationNotFoundError"})),
        FileSpec("public-access-block.json", _public_access_block,
                 lazy=True,
                 not_configured=frozenset(
                     {"NoSuchPublicAccessBlockConfiguration"})),
        FileSpec("versioning.json", _versioning, lazy=True),
        FileSpec("objects-listing.json", _objects_listing, lazy=True),
        SubdirSpec("objects", _object_entries, lazy=False),
    ),
    lookup={"name": lambda i: str(i.get("Name", ""))},
    key_from_arn=bucket_from_arn,
)


SERVICE = ServiceSpec(
    dirname="s3",
    scope="region",
    collections=(
        BUCKETS,
    ),
)
