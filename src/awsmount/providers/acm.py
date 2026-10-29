"""AWS Certificate Manager provider (docs/coverage.md).

Collection: certificates. One paginated ``ListCertificates`` call
lists every key type of the region. The directory name is the domain
name, and the key is the certificate id (the last ARN segment).
``describe.json`` and ``status`` are derived from the listing.
``details.json`` (DescribeCertificate) and the tags are lazy. Private
keys are never exported (``ExportCertificate`` is denied).
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
from awsmount.providers.common import name_from_arn
from awsmount.providers.ec2 import field_text
from awsmount.vfs.render import Content

if TYPE_CHECKING:
    from awsmount.session.context import Scope

__all__ = ["CERTIFICATES", "KEY_TYPES", "SERVICE"]

KEY_TYPES = (
    "RSA_1024",
    "RSA_2048",
    "RSA_3072",
    "RSA_4096",
    "EC_prime256v1",
    "EC_secp384r1",
    "EC_secp521r1",
)


def _list_certificates(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated ListCertificates call including all key types."""
    items = lc.paginate("list_certificates", "CertificateSummaryList",
                        Includes={"keyTypes": list(KEY_TYPES)})
    return [c for c in items
            if isinstance(c, dict) and c.get("CertificateArn")]


def _cert_key(item: dict[str, Any]) -> str:
    """Certificate id: the last segment of the ARN."""
    return name_from_arn(str(item["CertificateArn"]))


def _display(item: dict[str, Any]) -> str:
    """Domain name, or the certificate id when absent."""
    domain = item.get("DomainName")
    return str(domain) if domain else _cert_key(item)


def _cert_arn(item: dict[str, Any], scope: Scope) -> str | None:
    """ARN of the certificate as listed."""
    arn = item.get("CertificateArn")
    return str(arn) if arn else None


def _details(rc: ResourceCtx) -> Content:
    """details.json (lazy DescribeCertificate)."""
    resp = rc.call("describe_certificate",
                   CertificateArn=str(rc.item["CertificateArn"]))
    result: Content = resp.get("Certificate")
    return result


def _tags(rc: ResourceCtx) -> dict[str, str]:
    """Tags from ListTagsForCertificate."""
    resp = rc.call("list_tags_for_certificate",
                   CertificateArn=str(rc.item["CertificateArn"]))
    return {str(t["Key"]): str(t.get("Value", ""))
            for t in resp.get("Tags", []) or []
            if isinstance(t, dict) and "Key" in t}


CERTIFICATES = CollectionSpec(
    name="certificates",
    client="acm",
    lister=_list_certificates,
    key=_cert_key,
    ops=frozenset({"ListCertificates", "DescribeCertificate",
                   "ListTagsForCertificate"}),
    display=_display,
    arn=_cert_arn,
    name_of=lambda i: i.get("DomainName"),
    tags=TagSpec(fetch=_tags),
    files=(
        FileSpec("status", field_text("Status")),
        FileSpec("details.json", _details, lazy=True),
    ),
    lookup={"arn": lambda i: str(i.get("CertificateArn", "")),
            "name": lambda i: str(i.get("DomainName", ""))},
    key_from_arn=name_from_arn,
)


SERVICE = ServiceSpec(
    dirname="acm",
    scope="region",
    collections=(
        CERTIFICATES,
    ),
)
