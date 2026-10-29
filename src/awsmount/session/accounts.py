"""Account and region resolution per profile.

See ARCHITECTURE: Accounts and regions.
"""

from __future__ import annotations

import sys
import threading
import time
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

from awsmount.errors import AwsMountError, BudgetExceeded
from awsmount.session.context import Scope
from awsmount.session.progress import clear_line
from awsmount.vfs.path import escape_name

if TYPE_CHECKING:
    from awsmount.session.context import Context

__all__ = [
    "AccountDirectory",
    "AccountInfo",
    "DEFAULT_REGION",
    "GLOBAL_REGIONS",
    "global_region_for",
]

DEFAULT_REGION = "us-east-1"
GLOBAL_REGIONS = {
    "aws": "us-east-1",
    "aws-cn": "cn-north-1",
    "aws-us-gov": "us-gov-west-1",
}


def global_region_for(partition: str, regions: tuple[str, ...]) -> str:
    """Region used for global services in ``partition``."""
    if partition in GLOBAL_REGIONS:
        return GLOBAL_REGIONS[partition]
    return regions[0] if regions else DEFAULT_REGION


@dataclass(frozen=True)
class AccountInfo:
    """One mounted account (or a failed profile)."""

    profile: str | None
    account_id: str | None
    aliases: tuple[str, ...]
    partition: str
    dirname: str
    regions: tuple[str, ...]
    global_region: str
    identity: dict[str, Any] | None
    error: str | None


def _profile_label(profile: str | None) -> str:
    return profile or "default"


class AccountDirectory:
    """Resolves every configured profile.

    Successful resolutions are fixed for the session. When a profile
    failed (transient network error, throttling, expired token...), the
    whole set is resolved again once ``negative_ttl`` has elapsed.
    ``BudgetExceeded`` is never turned into a failed account; it
    propagates. :meth:`reset` forgets everything (shell ``refresh``).
    """

    def __init__(self, ctx: Context) -> None:
        self._ctx = ctx
        self._lock = threading.Lock()
        self._accounts: list[AccountInfo] | None = None
        self._retry_at: float | None = None
        self._failures: dict[str, str] = {}
        self._announced: set[tuple[str, str]] = set()

    def _due(self) -> bool:
        return (self._retry_at is not None
                and time.monotonic() >= self._retry_at)

    def accounts(self) -> list[AccountInfo]:
        """Resolved accounts (failed profiles are retried later)."""
        with self._lock:
            if self._accounts is None or self._due():
                try:
                    infos = self._resolve_all()
                except BudgetExceeded:
                    if self._accounts is None:
                        raise
                    return list(self._accounts)
                self._accounts = infos
                if any(i.error is not None for i in infos):
                    self._retry_at = (time.monotonic()
                                      + float(self._ctx.config.negative_ttl))
                else:
                    self._retry_at = None
            return list(self._accounts)

    def reset(self) -> None:
        """Forget resolved accounts; the next access resolves again."""
        with self._lock:
            self._accounts = None
            self._retry_at = None
            self._failures.clear()
            self._announced.clear()

    def failures(self) -> dict[str, str]:
        """Profiles that could not be resolved in this session.

        Maps the profile label to its error. A profile stays listed even
        when a later retry succeeds, because what was shown before the
        retry may have been incomplete. Nothing is resolved by this call.
        """
        with self._lock:
            return dict(self._failures)

    def _note_failure(self, label: str, error: str) -> None:
        """Remember a failed profile and say so once on stderr.

        A failed profile is an account directory with only ``_meta/``, so
        without this a mistyped profile or an expired token would look like
        an empty account, and a search over it like "nothing found".
        """
        text = " ".join(error.split())[:300]
        self._failures[label] = text
        if (label, text) in self._announced:
            return
        self._announced.add((label, text))
        clear_line()
        sys.stderr.write(f"awsmount: profile {label}: {text.rstrip('. ')}; "
                         "nothing is shown for it\n")
        sys.stderr.flush()

    def by_id(self, account_id: str) -> AccountInfo | None:
        """Mounted account with this id, if any."""
        for info in self.accounts():
            if info.account_id == account_id:
                return info
        return None

    def _resolve_all(self) -> list[AccountInfo]:
        infos: list[AccountInfo] = []
        seen: dict[str, str] = {}
        used: set[str] = set()
        for profile in self._ctx.config.profiles:
            info = self._resolve(profile)
            label = _profile_label(profile)
            if info.error is not None:
                self._note_failure(label, info.error)
            if info.account_id is not None:
                first = seen.get(info.account_id)
                if first is not None:
                    self._ctx.errors.record(
                        None, "awsmount", "accounts",
                        AwsMountError(
                            f"profile {label} resolves to account "
                            f"{info.account_id}, already mounted via "
                            f"profile {first}; skipped"),
                        account=info.account_id)
                    continue
                seen[info.account_id] = label
            if info.dirname.casefold() in used:
                suffix = escape_name(info.account_id or label)
                info = replace(info, dirname=f"{info.dirname}~{suffix}")
            used.add(info.dirname.casefold())
            infos.append(info)
        return infos

    def _failed(self, profile: str | None, error: str,
                region: str) -> AccountInfo:
        label = _profile_label(profile)
        return AccountInfo(
            profile=profile, account_id=None, aliases=(), partition="aws",
            dirname=escape_name(f"profile-{label}"), regions=(region,),
            global_region=region, identity=None, error=error)

    def _resolve(self, profile: str | None) -> AccountInfo:
        ctx = self._ctx
        config = ctx.config
        label = _profile_label(profile)
        try:
            default_region = (ctx.clients.session(profile).region_name
                              or DEFAULT_REGION)
        except Exception as exc:
            ctx.errors.record(None, "sts", "session", exc,
                              account=f"profile:{label}")
            return self._failed(profile, str(exc), DEFAULT_REGION)
        explicit = tuple(dict.fromkeys(
            r for r in config.regions if r != "all"))
        boot_region = explicit[0] if explicit else default_region
        provisional = self._failed(profile, "", boot_region)
        provisional = replace(provisional, error=None)
        boot = Scope(provisional, boot_region, False)
        try:
            identity = ctx.call(boot, "sts", "get_caller_identity")
        except BudgetExceeded:
            raise
        except AwsMountError as exc:
            ctx.errors.record(boot, "sts", "get_caller_identity", exc)
            return self._failed(profile, str(exc), boot_region)
        account_id = identity.get("Account")
        arn = str(identity.get("Arn", ""))
        partition = arn.split(":")[1] if arn.startswith("arn:") else "aws"
        known = replace(provisional, account_id=account_id,
                        partition=partition, identity=identity)
        global_region = global_region_for(partition, (boot_region,))
        gscope = Scope(replace(known, global_region=global_region),
                       global_region, True)
        aliases: tuple[str, ...] = ()
        try:
            resp = ctx.call(gscope, "iam", "list_account_aliases")
            aliases = tuple(str(a) for a in resp.get("AccountAliases", []))
        except BudgetExceeded:
            raise
        except AwsMountError as exc:
            ctx.errors.record(gscope, "iam", "list_account_aliases", exc)
        regions = self._regions(Scope(known, boot_region, False),
                                explicit, default_region)
        dirname = escape_name(aliases[0] if aliases else
                              account_id or f"profile-{label}")
        return replace(known, aliases=aliases, dirname=dirname,
                       regions=regions,
                       global_region=global_region_for(partition, regions))

    def _regions(self, scope: Scope, explicit: tuple[str, ...],
                 default_region: str) -> tuple[str, ...]:
        ctx = self._ctx
        if not ctx.config.all_regions:
            return explicit or (default_region,)
        try:
            resp = ctx.call(scope, "ec2", "describe_regions",
                            AllRegions=False)
            names = {str(r["RegionName"]) for r in resp.get("Regions", [])
                     if "RegionName" in r}
        except BudgetExceeded:
            raise
        except AwsMountError as exc:
            ctx.errors.record(scope, "ec2", "describe_regions", exc)
            names = {default_region}
        return tuple(sorted(names | set(explicit))) or (default_region,)
