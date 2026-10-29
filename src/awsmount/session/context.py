"""Context and Scope: the only state of a session.

See ARCHITECTURE: Context and API calls.
"""

from __future__ import annotations

import sys
import time
from collections.abc import Hashable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, cast

from awsmount.errors import AwsMountError, BudgetExceeded, PermissionDenied
from awsmount.errors import UpstreamError
from awsmount.session.budget import ApiBudget
from awsmount.session.cache import TTLCache
from awsmount.session.clients import ClientFactory
from awsmount.session.errorlog import ErrorKind, ErrorLog, classify
from awsmount.session.errorlog import error_code
from awsmount.session.limiter import Limiter
from awsmount.session.progress import Progress, clear_line
from awsmount.session.redact import RedactionPolicy
from awsmount.vfs.render import canonical_json, strip_metadata

if TYPE_CHECKING:
    from awsmount.config import Config
    from awsmount.providers import ProviderRegistry
    from awsmount.session.accounts import AccountDirectory, AccountInfo
    from awsmount.tree.links import LinkResolver, ReferencedByIndex

__all__ = ["Context", "Scope"]


@dataclass(frozen=True)
class Scope:
    """Where a call goes: one account and one region."""

    account: AccountInfo
    region: str
    is_global: bool

    @property
    def partition(self) -> str:
        """AWS partition of the account."""
        return self.account.partition


def _dig(page: Any, path: str) -> list[Any]:
    cur: Any = page
    for part in path.split("."):
        if not isinstance(cur, dict):
            return []
        cur = cur.get(part)
    if cur is None:
        return []
    if isinstance(cur, list):
        return cur
    return [cur]


def _stderr_echo(line: str) -> None:
    clear_line()
    sys.stderr.write(f"[awsmount] error {line}\n")


@dataclass(eq=False)
class Context:
    """Everything a session needs; built from a Config."""

    config: Config
    cache: TTLCache
    budget: ApiBudget
    limiter: Limiter
    clients: ClientFactory
    redaction: RedactionPolicy
    errors: ErrorLog
    progress: Progress
    accounts: AccountDirectory = field(init=False, repr=False)
    registry: ProviderRegistry
    links: LinkResolver = field(init=False, repr=False)
    refindex: ReferencedByIndex = field(init=False, repr=False)
    started_at: float

    def __post_init__(self) -> None:
        from awsmount.session.accounts import AccountDirectory
        from awsmount.tree.links import LinkResolver, ReferencedByIndex

        self.accounts = AccountDirectory(self)
        self.links = LinkResolver(self)
        self.refindex = ReferencedByIndex(self)

    @classmethod
    def from_config(cls, config: Config, *,
                    registry: ProviderRegistry | None = None,
                    extra_ops: Iterable[tuple[str, str]] = (),
                    value_ops: Iterable[tuple[str, str]] = (),
                    user_agent_suffix: str = "") -> Context:
        """Build every component from ``config``.

        ``registry``, ``extra_ops`` and ``value_ops`` exist for
        ``awsmount secrets``, the only session that serves secret values:
        it passes its own (empty) registry, the ``(client, Op)`` pairs it
        needs, and the subset of them allowed to read a value, and a
        suffix for the user agent (so CloudTrail can tell its reads apart).
        """
        from awsmount.providers import ProviderRegistry

        if registry is None:
            registry = ProviderRegistry()
        errors = ErrorLog(echo=_stderr_echo if config.verbose else None)

        def exhausted(message: str) -> None:
            errors.record(None, "awsmount", "budget",
                          BudgetExceeded(message))
            clear_line()
            sys.stderr.write(f"awsmount: {message}\n")

        budget = ApiBudget(config.max_api_calls, config.budget_window,
                           on_exhausted=exhausted)
        progress = Progress(config.verbose, sys.stderr, budget)
        clients = ClientFactory(
            config, budget, progress,
            registry.allowed_pairs() | frozenset(extra_ops),
            value_ops=value_ops, user_agent_suffix=user_agent_suffix)
        return cls(
            config=config,
            cache=TTLCache(config.ttl, negative_ttl=config.negative_ttl),
            budget=budget,
            limiter=Limiter(config.concurrency, config.global_concurrency),
            clients=clients,
            redaction=RedactionPolicy(config.reveal),
            errors=errors,
            progress=progress,
            registry=registry,
            started_at=time.time(),
        )

    @staticmethod
    def _translate(client: str, op: str,
                   exc: BaseException) -> UpstreamError:
        kind = classify(exc)
        code = error_code(exc)
        message = f"{client}:{op}: {code}: {exc}"
        if kind is ErrorKind.ACCESS_DENIED:
            return PermissionDenied(message, code=code, kind=kind.value,
                                    service=client, op=op)
        return UpstreamError(message, code=code, kind=kind.value,
                             service=client, op=op)

    def call(self, scope: Scope, client: str, op: str,
             **params: Any) -> dict[str, Any]:
        """One cached, limited, budgeted API call (``op`` snake_case)."""
        key = (scope.account.profile, scope.region, client, op,
               canonical_json(params))

        def load() -> dict[str, Any]:
            with self.limiter.slot(client):
                api = self.clients.get(scope.account.profile, scope.region,
                                       client)
                try:
                    response = getattr(api, op)(**params)
                except AwsMountError:
                    raise
                except Exception as exc:
                    raise self._translate(client, op, exc) from exc
            return cast("dict[str, Any]", strip_metadata(response))

        return self.cache.get_or_load(key, load)

    def call_uncached(self, scope: Scope, client: str, op: str,
                      **params: Any) -> dict[str, Any]:
        """One limited, budgeted API call whose response is not cached.

        For responses that hold secret values: the TTL cache keeps
        immutable objects that cannot be wiped.
        """
        with self.limiter.slot(client):
            api = self.clients.get(scope.account.profile, scope.region,
                                   client)
            try:
                response = getattr(api, op)(**params)
            except AwsMountError:
                raise
            except Exception as exc:
                raise self._translate(client, op, exc) from exc
        return cast("dict[str, Any]", strip_metadata(response))

    def paginate(self, scope: Scope, client: str, op: str,
                 result_key: str | Sequence[str],
                 **params: Any) -> list[Any]:
        """Iterate a paginator, concatenating ``result_key`` values."""
        keys = [result_key] if isinstance(result_key, str) else list(
            result_key)
        key = (scope.account.profile, scope.region, client, op,
               canonical_json(params), "paginate", tuple(keys))

        def load() -> list[Any]:
            items: list[Any] = []
            with self.limiter.slot(client):
                api = self.clients.get(scope.account.profile, scope.region,
                                       client)
                try:
                    paginator = api.get_paginator(op)
                    for page in paginator.paginate(**params):
                        clean = strip_metadata(page)
                        for path in keys:
                            items.extend(_dig(clean, path))
                except AwsMountError:
                    raise
                except Exception as exc:
                    raise self._translate(client, op, exc) from exc
            return items

        return self.cache.get_or_load(key, load)

    def fetched_at(self, key: Hashable) -> float:
        """Wall-clock fetch time of a cache entry (session start if none)."""
        value = self.cache.fetched_at(key)
        return value if value is not None else self.started_at
