"""boto3 client factory and the read-only guard.

See ARCHITECTURE: Read-only guard.

The allow-list is client-scoped: an operation declared by a provider
passes the guard only for the boto3 client that declared it
(``(client, Op)`` pairs taken from ``CollectionSpec.client`` and
``CollectionSpec.ops``). An op that is safe for one service therefore
never passes for another service that happens to have an operation of
the same name.

The three bootstrap operations (``BOOTSTRAP_OPS``) are the exception.
The rule is ``allowed_ops ∪ BOOTSTRAP_OPS``, so they
pass on any client. They are harmless metadata reads, and the prefix
and ``DENIED_OPS`` checks still apply to them.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

import boto3
from botocore.config import Config as BotoConfig

from awsmount import __version__
from awsmount.errors import ForbiddenOperation

if TYPE_CHECKING:
    from botocore.client import BaseClient

    from awsmount.config import Config
    from awsmount.session.budget import ApiBudget
    from awsmount.session.progress import Progress

__all__ = [
    "BOOTSTRAP_OPS",
    "BOOTSTRAP_PAIRS",
    "ClientFactory",
    "DENIED_OPS",
    "READ_PREFIXES",
    "is_read_only_op",
]

DENIED_OPS: frozenset[str] = frozenset({
    "GetSecretValue", "BatchGetSecretValue", "GetParameter",
    "GetParameters", "GetParametersByPath", "GetParameterHistory",
    "GetObject", "GetObjectTorrent", "SelectObjectContent",
    "GetObjectAttributes", "Decrypt", "GenerateDataKey",
    "GenerateDataKeyWithoutPlaintext", "GetPasswordData",
    "GetAuthorizationToken", "GetSessionToken", "GetFederationToken",
    "GetFunction", "GetLayerVersion", "ExportCertificate", "GetLogEvents",
    "FilterLogEvents", "GetQueryResults", "GetConsoleOutput",
    "GetConsoleScreenshot", "GetLaunchTemplateData", "GetApiKey",
    "GetApiKeys", "GetExport", "GetSdk",
})
BOOTSTRAP_OPS: frozenset[str] = frozenset({
    "GetCallerIdentity", "ListAccountAliases", "DescribeRegions"})
BOOTSTRAP_PAIRS: frozenset[tuple[str, str]] = frozenset({
    ("sts", "GetCallerIdentity"),
    ("iam", "ListAccountAliases"),
    ("ec2", "DescribeRegions"),
})
"""Bootstrap operations paired with the client that normally uses it."""
READ_PREFIXES = ("Describe", "List", "Get", "Search", "Lookup")


def is_read_only_op(name: str) -> bool:
    """True when a model op name passes the prefix and deny checks."""
    return name.startswith(READ_PREFIXES) and name not in DENIED_OPS


def _split_allow(entries: Iterable[str | tuple[str, str]]
                 ) -> tuple[set[tuple[str, str]], set[str]]:
    """Split allow-list entries into scoped pairs and bare names.

    ``(client, Op)`` tuples and ``"client:Op"`` strings are scoped. A
    bare ``"Op"`` string is accepted for backward compatibility and
    allows that op on every client; the session never passes one.
    """
    pairs: set[tuple[str, str]] = set()
    names: set[str] = set()
    for entry in entries:
        if isinstance(entry, tuple):
            if len(entry) != 2:
                raise ValueError(f"invalid allow-list entry {entry!r}")
            pairs.add((str(entry[0]), str(entry[1])))
        elif isinstance(entry, str):
            client, sep, op = entry.partition(":")
            if sep and client and op:
                pairs.add((client, op))
            else:
                names.add(entry)
        else:
            raise TypeError(f"invalid allow-list entry {entry!r}")
    return pairs, names


class ClientFactory:
    """Memoised boto3 sessions/clients with a before-call guard."""

    def __init__(self, config: Config, budget: ApiBudget,
                 progress: Progress,
                 allowed_ops: Iterable[str | tuple[str, str]],
                 *, value_ops: Iterable[tuple[str, str]] = (),
                 user_agent_suffix: str = "") -> None:
        self._config = config
        self._budget = budget
        self._progress = progress
        pairs, names = _split_allow(allowed_ops)
        self._pairs = frozenset(pairs) | BOOTSTRAP_PAIRS
        self._names = frozenset(names)
        # ``(client, Op)`` pairs that may read a secret value although the
        # op is in DENIED_OPS. Only ``awsmount secrets`` passes any; every
        # other session keeps this empty, so DENIED_OPS holds for it.
        self._user_agent = f"awsmount/{__version__}" + (
            f" {user_agent_suffix}" if user_agent_suffix else "")
        self._value_pairs = frozenset(value_ops)
        for pair in self._value_pairs:
            if pair not in self._pairs:
                raise ValueError(
                    f"value op {pair} is not in the allow-list")
        self._lock = threading.RLock()
        self._sessions: dict[str | None, boto3.Session] = {}
        self._clients: dict[tuple[str | None, str, str], BaseClient] = {}

    @property
    def allowed_ops(self) -> frozenset[str]:
        """Every op name the guard lets through for some client."""
        return (frozenset(op for _client, op in self._pairs)
                | self._names | BOOTSTRAP_OPS)

    @property
    def allowed_pairs(self) -> frozenset[tuple[str, str]]:
        """Client-scoped ``(client, Op)`` pairs of the allow-list."""
        return self._pairs

    def is_allowed(self, service: str, name: str) -> bool:
        """True when ``service:name`` passes every guard check."""
        if (service, name) in self._value_pairs:
            return True
        if not is_read_only_op(name):
            return False
        if name in BOOTSTRAP_OPS:
            return True
        return (service, name) in self._pairs or name in self._names

    def session(self, profile: str | None) -> boto3.Session:
        """Return (creating once) the session for ``profile``."""
        with self._lock:
            sess = self._sessions.get(profile)
            if sess is None:
                sess = boto3.Session(profile_name=profile)
                self._sessions[profile] = sess
            return sess

    def botocore_config(self, service: str) -> BotoConfig:
        """botocore Config used for every client."""
        cfg = self._config
        kwargs: dict[str, Any] = {
            "retries": {"mode": "adaptive",
                        "max_attempts": cfg.max_attempts},
            "connect_timeout": cfg.connect_timeout,
            "read_timeout": cfg.read_timeout,
            "max_pool_connections": max(10, cfg.concurrency * 2),
            "user_agent_extra": self._user_agent,
        }
        if cfg.endpoint_url and service == "s3":
            kwargs["s3"] = {"addressing_style": "path"}
        return BotoConfig(**kwargs)

    def get(self, profile: str | None, region: str,
            service: str) -> BaseClient:
        """Return the guarded client for ``(profile, region, service)``."""
        key = (profile, region, service)
        with self._lock:
            client = self._clients.get(key)
            if client is not None:
                return client
            sess = self.session(profile)
            kwargs: dict[str, Any] = {
                "region_name": region,
                "config": self.botocore_config(service),
            }
            if self._config.endpoint_url:
                kwargs["endpoint_url"] = self._config.endpoint_url
            client = sess.client(service, **kwargs)
            self._install_guard(client, service)
            self._clients[key] = client
            return client

    def _install_guard(self, client: BaseClient, service: str) -> None:
        def hook(model: Any, **kwargs: Any) -> None:
            self._guard(service, model)

        client.meta.events.register("before-call.*.*", hook)

    def _guard(self, service: str, model: Any) -> None:
        name = str(model.name)
        if not self.is_allowed(service, name):
            raise ForbiddenOperation(
                f"refusing non-allow-listed operation {service}:{name}")
        label = f"{service}:{name}"
        self._budget.charge(label)
        self._progress.tick(label)
