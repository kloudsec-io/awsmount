"""Session of ``awsmount secrets`` (ARCHITECTURE: awsmount secrets).

This is the only session that may read secret values. It has its own
empty provider registry, so no other service is in the tree, and its
client allow-list holds exactly the four operations the tree uses plus
the three harmless bootstrap calls every session has. The two value
reads (``GetSecretValue``, ``GetParameter``) are the only operations
allowed to bypass ``DENIED_OPS``, and only here.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

import boto3

from awsmount.config import Config
from awsmount.errors import AwsMountError
from awsmount.providers import ProviderRegistry
from awsmount.secrets.store import ValueStore
from awsmount.secrets.tree import build_vfs
from awsmount.session.accounts import AccountInfo
from awsmount.session.context import Context, Scope
from awsmount.session.progress import clear_line

if TYPE_CHECKING:
    from awsmount.vfs.resolver import VFS

__all__ = [
    "DEFAULT_TTL",
    "LIST_OPS",
    "SecretsError",
    "SecretsSession",
    "USER_AGENT_SUFFIX",
    "VALUE_OPS",
    "build_session",
    "harden_process",
    "resolve_region",
]

USER_AGENT_SUFFIX = "awsmount-secrets"
"""Added to the user agent: CloudTrail then shows which reads are ours."""
DEFAULT_TTL = 300.0
"""Seconds a value is kept in memory (the AWS extension's default)."""
VALUE_OPS: frozenset[tuple[str, str]] = frozenset({
    ("secretsmanager", "GetSecretValue"),
    ("ssm", "GetParameter"),
})
"""The only value reads in awsmount; allowed past DENIED_OPS here only."""
LIST_OPS: frozenset[tuple[str, str]] = frozenset({
    ("secretsmanager", "ListSecrets"),
    ("ssm", "DescribeParameters"),
})
"""Metadata listings: they return no value."""


class SecretsError(AwsMountError):
    """The secrets session cannot start (credentials, region)."""


def resolve_region(profile: str | None, region: str | None) -> str:
    """The one region to mount; never guessed.

    A default such as us-east-1 would silently show the wrong secrets,
    so without ``--region`` the profile or environment region is used,
    and without either the session refuses to start.
    """
    if region:
        problem = Config._region_problem(region)
        if problem is not None or region == "all":
            raise SecretsError(
                f"--region needs one region name, got {region!r}")
        return region
    try:
        configured = boto3.Session(profile_name=profile).region_name
    except Exception as exc:
        raise SecretsError(str(exc)) from exc
    if not configured:
        raise SecretsError(
            "no region: pass --region, or set one in the profile or "
            "AWS_DEFAULT_REGION")
    return str(configured)


def harden_process() -> None:
    """Forbid core dumps of this process (they would hold cached values)."""
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, ValueError, OSError):
        pass


def _identity(ctx: Context, profile: str | None, region: str
              ) -> AccountInfo:
    """Who the credentials are: one ``sts:GetCallerIdentity`` call.

    The normal account resolution also lists account aliases and regions,
    which a least-privilege identity may not be allowed to do.
    """
    probe = AccountInfo(
        profile=profile, account_id=None, aliases=(), partition="aws",
        dirname="", regions=(region,), global_region=region,
        identity=None, error=None)
    try:
        identity = ctx.call(Scope(probe, region, False), "sts",
                            "get_caller_identity")
    except AwsMountError as exc:
        raise SecretsError(f"cannot use these credentials: {exc}") from exc
    account = identity.get("Account")
    if not account:
        raise SecretsError("cannot use these credentials: no account id")
    arn = str(identity.get("Arn", ""))
    partition = arn.split(":")[1] if arn.startswith("arn:") else "aws"
    return replace(probe, account_id=str(account), partition=partition,
                   dirname=str(account), identity=identity)


@dataclass
class SecretsSession:
    """Everything one ``awsmount secrets`` command runs on."""

    ctx: Context
    vfs: VFS
    store: ValueStore
    account: AccountInfo
    region: str

    def close(self) -> None:
        """Stop the reaper and overwrite every held value."""
        self.store.close()


def build_session(config: Config) -> SecretsSession:
    """Resolve the identity and build the tree; no secret is read."""
    if len(config.profiles) != 1:
        raise SecretsError("awsmount secrets mounts one profile")
    if len(config.regions) != 1 or config.all_regions:
        raise SecretsError("awsmount secrets mounts one region")
    ctx = Context.from_config(
        config, registry=ProviderRegistry(()),
        extra_ops=VALUE_OPS | LIST_OPS, value_ops=VALUE_OPS,
        user_agent_suffix=USER_AGENT_SUFFIX)
    region = config.regions[0]
    info = _identity(ctx, config.profiles[0], region)
    store = ValueStore(config.ttl)
    scope = Scope(info, region, False)
    return SecretsSession(ctx=ctx, vfs=build_vfs(ctx, scope, store),
                          store=store, account=info, region=region)


def banner(session: SecretsSession, ttl: float) -> str:
    """The warning printed before a secrets mount or shell."""
    who = session.account.profile or "default"
    kept = (f"kept in memory for {ttl:g} s" if ttl > 0
            else "not cached")
    return (f"awsmount: WARNING: this serves secret VALUES (profile "
            f"{who}, account {session.account.account_id}, region "
            f"{session.region}). Any process of yours that reads the "
            f"files gets them; values are {kept}.")


def echo_banner(session: SecretsSession, ttl: float) -> None:
    """Print :func:`banner` to stderr."""
    clear_line()
    sys.stderr.write(banner(session, ttl) + "\n")
