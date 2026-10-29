"""Amazon ECR provider: repositories.

One paginated DescribeRepositories call lists the repositories. The
repository policy and the lifecycle policy are lazy files (an empty
answer when none is configured). Tags are lazy. Images, layers and
authorization tokens are never read: image metadata can be huge, and
``GetAuthorizationToken`` is on the deny list.
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
from awsmount.providers.common import kms_ref, parse_json_text
from awsmount.providers.ec2 import field_text
from awsmount.vfs.render import Content

__all__ = ["REPOSITORIES", "SERVICE"]


def _list_repositories(lc: ListCtx) -> list[dict[str, Any]]:
    """One paginated DescribeRepositories call."""
    return [r for r in lc.paginate("describe_repositories", "repositories")
            if isinstance(r, dict)]


def _policy(rc: ResourceCtx) -> Content:
    """policy.json (lazy GetRepositoryPolicy)."""
    resp = rc.call("get_repository_policy",
                   repositoryName=str(rc.item["repositoryName"]))
    return parse_json_text(resp.get("policyText"))


def _lifecycle(rc: ResourceCtx) -> Content:
    """lifecycle-policy.json (lazy GetLifecyclePolicy)."""
    resp = rc.call("get_lifecycle_policy",
                   repositoryName=str(rc.item["repositoryName"]))
    return parse_json_text(resp.get("lifecyclePolicyText"))


def _tags(rc: ResourceCtx) -> dict[str, str]:
    """Lazy tags (ListTagsForResource on the repository ARN)."""
    arn = rc.item.get("repositoryArn")
    if not arn:
        return {}
    resp = rc.call("list_tags_for_resource", resourceArn=str(arn))
    out: dict[str, str] = {}
    for tag in resp.get("tags", []) or []:
        if isinstance(tag, dict) and "Key" in tag:
            out[str(tag["Key"])] = str(tag.get("Value", ""))
    return out


def _kms_key(rc: ResourceCtx) -> str | None:
    config = rc.item.get("encryptionConfiguration")
    if not isinstance(config, dict):
        return None
    return kms_ref(config.get("kmsKey"))


REPOSITORIES = CollectionSpec(
    name="repositories",
    client="ecr",
    lister=_list_repositories,
    key=lambda i: str(i["repositoryName"]),
    ops=frozenset({"DescribeRepositories", "GetRepositoryPolicy",
                   "GetLifecyclePolicy", "ListTagsForResource"}),
    arn=lambda i, _scope: (str(i["repositoryArn"])
                           if i.get("repositoryArn") else None),
    tags=TagSpec(fetch=_tags),
    files=(
        FileSpec("uri", field_text("repositoryUri")),
        FileSpec("policy.json", _policy, lazy=True,
                 not_configured=frozenset(
                     {"RepositoryPolicyNotFoundException"})),
        FileSpec("lifecycle-policy.json", _lifecycle, lazy=True,
                 not_configured=frozenset(
                     {"LifecyclePolicyNotFoundException"})),
    ),
    links=(
        LinkSpec("kms-key", refs.KMS_KEYS, _kms_key, by="arn"),
    ),
    lookup={"arn": lambda i: str(i.get("repositoryArn", "")),
            "name": lambda i: str(i.get("repositoryName", ""))},
)


SERVICE = ServiceSpec(
    dirname="ecr",
    scope="region",
    collections=(REPOSITORIES,),
)
