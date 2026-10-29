"""Amazon CloudFront provider (global, docs/coverage.md).

Collection: distributions. One paginated ``ListDistributions`` call
lists the account. ``describe.json``, ``domain-name``, ``status`` and
``aliases`` are derived from that listing. ``config.json``
(GetDistributionConfig) and the tags are lazy. Origin custom header
values (often shared secrets) are redacted (rule ``cloudfront``).

The ``certificate`` link goes to the ACM certificate in its own region
(us-east-1 for CloudFront). ``origins-s3/`` links to the buckets behind
S3 origin domains. Both are omitted when the target is not mounted.
"""

from __future__ import annotations

import re
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
from awsmount.providers.common import name_from_arn
from awsmount.providers.ec2 import field_text
from awsmount.vfs.render import Content

if TYPE_CHECKING:
    from awsmount.session.context import Scope

__all__ = ["DISTRIBUTIONS", "SERVICE", "s3_origin"]

_S3_BUCKET = re.compile(r"^(?P<bucket>.+?)\.s3[.-]")
_S3_REGION = re.compile(
    r"\.s3[.-](?:website[.-]|dualstack\.)?"
    r"(?P<region>[a-z]{2}(?:-[a-z]+)+-\d+)\.")


def s3_origin(domain: str) -> tuple[str, str] | None:
    """``(bucket, region)`` of an S3 origin domain; region may be ''."""
    match = _S3_BUCKET.match(domain)
    if match is None:
        return None
    region_match = _S3_REGION.search(domain)
    region = region_match.group("region") if region_match else ""
    return match.group("bucket"), region


def _list_distributions(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated ListDistributions call for the account."""
    return [d for d in lc.paginate("list_distributions",
                                   "DistributionList.Items")
            if isinstance(d, dict) and d.get("Id")]


def _distribution_arn(item: dict[str, Any], scope: Scope) -> str | None:
    """ARN of the distribution as listed."""
    arn = item.get("ARN")
    return str(arn) if arn else None


def _aliases(rc: ResourceCtx) -> Content:
    """aliases: one CNAME per line."""
    aliases = rc.item.get("Aliases") or {}
    items = aliases.get("Items") if isinstance(aliases, dict) else None
    return "\n".join(str(a) for a in items or [] if a)


def _config(rc: ResourceCtx) -> Content:
    """config.json (lazy GetDistributionConfig)."""
    resp = rc.call("get_distribution_config", Id=rc.key)
    result: Content = resp.get("DistributionConfig")
    return result


def _certificate(rc: ResourceCtx) -> str | None:
    """ACM certificate ARN of the viewer certificate, if any."""
    viewer = rc.item.get("ViewerCertificate") or {}
    if not isinstance(viewer, dict):
        return None
    arn = viewer.get("ACMCertificateArn")
    return str(arn) if arn else None


def _origin_buckets(rc: ResourceCtx) -> list[str]:
    """Pseudo-ARNs of the S3 buckets behind S3 origin domains.

    The region parsed from the domain (if any) routes the link to the
    right region directory; without one the global region is used.
    """
    origins = rc.item.get("Origins") or {}
    items = origins.get("Items") if isinstance(origins, dict) else None
    out: set[str] = set()
    for origin in items or []:
        if not isinstance(origin, dict):
            continue
        domain = origin.get("DomainName")
        if not isinstance(domain, str):
            continue
        parsed = s3_origin(domain)
        if parsed is None:
            continue
        bucket, region = parsed
        account = (rc.scope.account.account_id or "") if region else ""
        out.add(f"arn:{rc.scope.partition}:s3:{region}:{account}:{bucket}")
    return sorted(out)


def _tags(rc: ResourceCtx) -> dict[str, str]:
    """Tags from ListTagsForResource (``Tags.Items``)."""
    arn = rc.item.get("ARN")
    if not arn:
        return {}
    resp = rc.call("list_tags_for_resource", Resource=str(arn))
    tags = resp.get("Tags") or {}
    items = tags.get("Items") if isinstance(tags, dict) else None
    return {str(t["Key"]): str(t.get("Value", ""))
            for t in items or []
            if isinstance(t, dict) and "Key" in t}


DISTRIBUTIONS = CollectionSpec(
    name="distributions",
    client="cloudfront",
    lister=_list_distributions,
    key=lambda i: str(i["Id"]),
    ops=frozenset({"ListDistributions", "GetDistributionConfig",
                   "ListTagsForResource"}),
    arn=_distribution_arn,
    redact="cloudfront",
    tags=TagSpec(fetch=_tags),
    files=(
        FileSpec("domain-name", field_text("DomainName")),
        FileSpec("status", field_text("Status")),
        FileSpec("aliases", _aliases),
        FileSpec("config.json", _config, lazy=True, redact="cloudfront"),
    ),
    links=(
        LinkSpec("certificate", refs.ACM_CERTIFICATES, _certificate,
                 by="arn"),
        LinkSpec("origins-s3", refs.S3_BUCKETS, _origin_buckets,
                 by="arn", many=True),
    ),
    lookup={"arn": lambda i: str(i.get("ARN", ""))},
    key_from_arn=name_from_arn,
)


SERVICE = ServiceSpec(
    dirname="cloudfront",
    scope="global",
    collections=(
        DISTRIBUTIONS,
    ),
)
