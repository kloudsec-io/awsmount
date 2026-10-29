"""AWS Secrets Manager provider (docs/coverage.md).

Collection: secrets (metadata only). One paginated ``ListSecrets``
call lists the region. ``describe.json``, ``rotation-enabled`` and the
tags are derived from it. ``policy.json`` (GetResourcePolicy) is lazy.

Secret values are never fetched. ``GetSecretValue`` and
``BatchGetSecretValue`` are denied even with ``--reveal``. The
``secrets`` rule set still redacts ``SecretString``/``SecretBinary``
defensively.
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
from awsmount.providers.common import kms_ref, parse_json_text
from awsmount.vfs.render import Content

if TYPE_CHECKING:
    from awsmount.session.context import Scope

__all__ = ["SECRETS", "SERVICE"]


def _list_secrets(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated ListSecrets call for the region (metadata only)."""
    return [s for s in lc.paginate("list_secrets", "SecretList")
            if isinstance(s, dict) and s.get("Name")]


def _secret_arn(item: dict[str, Any], scope: Scope) -> str | None:
    """ARN of the secret as listed."""
    arn = item.get("ARN")
    return str(arn) if arn else None


def _rotation_enabled(rc: ResourceCtx) -> Content:
    """rotation-enabled: ``true`` or ``false``."""
    return "true" if rc.item.get("RotationEnabled") else "false"


def _policy(rc: ResourceCtx) -> Content:
    """policy.json: the parsed resource policy (null when absent)."""
    secret = str(rc.item.get("ARN") or rc.key)
    resp = rc.call("get_resource_policy", SecretId=secret)
    policy = resp.get("ResourcePolicy")
    if not policy:
        return None
    result: Content = parse_json_text(policy)
    return result


def _kms_key(rc: ResourceCtx) -> str | None:
    """KMS key protecting the secret (aliases give no link)."""
    return kms_ref(rc.item.get("KmsKeyId"))


def _rotation_lambda(rc: ResourceCtx) -> str | None:
    """ARN of the rotation Lambda function, if any."""
    value = rc.item.get("RotationLambdaARN")
    return str(value) if value else None


SECRETS = CollectionSpec(
    name="secrets",
    client="secretsmanager",
    lister=_list_secrets,
    key=lambda i: str(i["Name"]),
    ops=frozenset({"ListSecrets", "GetResourcePolicy"}),
    arn=_secret_arn,
    name_of=lambda i: i.get("Name"),
    redact="secrets",
    tags=TagSpec(inline="Tags", style="list"),
    files=(
        FileSpec("rotation-enabled", _rotation_enabled),
        FileSpec("policy.json", _policy, lazy=True),
    ),
    links=(
        LinkSpec("kms-key", refs.KMS_KEYS, _kms_key),
        LinkSpec("rotation-lambda", refs.LAMBDA_FUNCTIONS,
                 _rotation_lambda, by="arn"),
    ),
    lookup={"arn": lambda i: str(i.get("ARN", "")),
            "name": lambda i: str(i.get("Name", ""))},
)


SERVICE = ServiceSpec(
    dirname="secretsmanager",
    scope="region",
    collections=(
        SECRETS,
    ),
)
