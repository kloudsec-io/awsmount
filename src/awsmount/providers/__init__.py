"""Provider registry (ARCHITECTURE: Providers).

``ALL`` is the explicit tuple of shipped services (one ``SERVICE`` per
provider module). :class:`ProviderRegistry` indexes them by scope,
service directory and collection name, derives the read-only API
allow-list and validates the specs.

The provider modules import session, tree and helper modules which in
turn may import this package (for example to reach
:class:`ProviderRegistry`). To keep the package importable without
circular-import failures, the provider modules are loaded lazily: the
first access to ``ALL`` (or the first default ``ProviderRegistry()``)
imports them, in the fixed order below, and caches the result.

Validation is two-phase: the complete reference index (every service,
every nested collection) is built first, and only then are link
targets and referenced-by sources resolved against it. This keeps the
result independent of the order of ``ALL`` and of which boto3 client
a referencing collection uses.
"""

from __future__ import annotations

import importlib
import threading
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from awsmount.providers.base import (
    CollectionRef,
    CollectionSpec,
    FileSpec,
    Scoping,
    ServiceSpec,
)

if TYPE_CHECKING:
    ALL: tuple[ServiceSpec, ...]

__all__ = ["ALL", "Layout", "ProviderRegistry", "PROVIDER_MODULES",
           "layout_of"]

PROVIDER_MODULES: tuple[str, ...] = (
    "ec2",
    "vpc",
    "elbv2",
    "lambda_",
    "rds",
    "ecs",
    "eks",
    "autoscaling",
    "s3",
    "dynamodb",
    "sqs",
    "sns",
    "kms",
    "logs",
    "cloudwatch",
    "ecr",
    "stepfunctions",
    "redshift",
    "eventbridge",
    "cloudformation",
    "secretsmanager",
    "ssm",
    "acm",
    "route53",
    "iam",
    "cloudfront",
    "apigateway",
    "organizations",
)
"""Provider module names, in registration order (one SERVICE each)."""

_READ_PREFIXES = ("Describe", "List", "Get", "Search", "Lookup")

_ALL_LOCK = threading.RLock()
_ALL_CACHE: list[tuple[ServiceSpec, ...]] = []


def _load_all() -> tuple[ServiceSpec, ...]:
    """Import every provider module once and return their SERVICEs."""
    if _ALL_CACHE:
        return _ALL_CACHE[0]
    with _ALL_LOCK:
        if _ALL_CACHE:
            return _ALL_CACHE[0]
        services: list[ServiceSpec] = []
        for name in PROVIDER_MODULES:
            module = importlib.import_module(f"{__name__}.{name}")
            service = getattr(module, "SERVICE")
            if not isinstance(service, ServiceSpec):
                raise TypeError(
                    f"{module.__name__}.SERVICE is not a ServiceSpec")
            services.append(service)
        result = tuple(services)
        _ALL_CACHE.append(result)
        return result


def __getattr__(name: str) -> object:
    """Lazily provide ``ALL`` (module-level attribute hook)."""
    if name == "ALL":
        return _load_all()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def _walk_specs(prefix: str, specs: Sequence[CollectionSpec]
                ) -> Iterator[tuple[str, CollectionSpec]]:
    """Yield ``(collection path, spec)`` pre-order, nested as a/b."""
    for spec in specs:
        path = f"{prefix}/{spec.name}" if prefix else spec.name
        yield path, spec
        yield from _walk_specs(path, spec.children)


@dataclass(frozen=True)
class Layout:
    """What a resource directory of one collection contains.

    ``files`` and ``links`` are display names: a trailing ``/`` marks a
    directory, ``*`` a lazy entry (an API call on first read) and ``?`` an
    entry that exists only when the resource has a value for it.
    """

    service: str
    collection: str
    scope: str
    files: tuple[str, ...]
    links: tuple[str, ...]


def layout_of(ref: CollectionRef, spec: CollectionSpec) -> Layout:
    """The entries of a resource directory, derived from its spec."""
    files = ["describe.json*" if spec.describe is not None
             else "describe.json"]
    if spec.arn is not None:
        files.append("arn")
    if spec.name_of is not None:
        files.append("name")
    elif spec.tags.inline is not None:
        files.append("name?")
    if spec.tags.active:
        star = "*" if spec.tags.fetch is not None else ""
        files += [f"tags.json{star}", f"tags/{star}"]
    for entry in spec.files:
        mark = "*" if entry.lazy else ""
        slash = "/" if not isinstance(entry, FileSpec) else ""
        files.append(f"{entry.name}{slash}{mark}")
    if spec.links:
        files.append("links/")
    if spec.referenced_by:
        files.append("referenced-by/")
    files += [f"{child.name}/" for child in spec.children]
    links: list[str] = []
    for link in spec.links:
        name = f"{link.name}/" if link.many else link.name
        if name not in links:
            links.append(name)
    return Layout(ref.service, ref.collection, ref.scope, tuple(files),
                  tuple(links))


class ProviderRegistry:
    """Index of services and collections, with spec validation."""

    def __init__(self, services: Iterable[ServiceSpec] | None = None
                 ) -> None:
        self._services: tuple[ServiceSpec, ...] = tuple(
            _load_all() if services is None else services)
        self._by_service: dict[tuple[str, str], ServiceSpec] = {}
        self._by_ref: dict[CollectionRef, CollectionSpec] = {}
        self._ref_of: dict[int, CollectionRef] = {}
        self._order: list[tuple[CollectionRef, CollectionSpec]] = []
        self._dup_services: list[str] = []
        self._dup_refs: list[str] = []
        for svc in self._services:
            skey = (svc.scope, svc.dirname)
            if skey in self._by_service:
                self._dup_services.append(
                    f"duplicate service {svc.scope}/{svc.dirname}")
                continue
            self._by_service[skey] = svc
            for path, spec in _walk_specs("", svc.collections):
                ref = CollectionRef(svc.scope, svc.dirname, path)
                if ref in self._by_ref:
                    self._dup_refs.append(f"duplicate collection {ref}")
                    continue
                self._by_ref[ref] = spec
                self._ref_of[id(spec)] = ref
                self._order.append((ref, spec))

    def services(self, scope: Scoping | None = None
                 ) -> list[ServiceSpec]:
        """Registered services, optionally restricted to one scope."""
        return [s for s in self._by_service.values()
                if scope is None or s.scope == scope]

    def dirnames(self) -> frozenset[str]:
        """Every registered service directory name."""
        return frozenset(s.dirname for s in self._by_service.values())

    def service(self, scope: Scoping, dirname: str) -> ServiceSpec | None:
        """The service called ``dirname`` in ``scope``, or None."""
        return self._by_service.get((scope, dirname))

    def collection(self, ref: CollectionRef) -> CollectionSpec | None:
        """The collection addressed by ``ref`` (nested as a/b), or None."""
        return self._by_ref.get(CollectionRef(*ref))

    def ref_of(self, spec: CollectionSpec) -> CollectionRef | None:
        """The reference of a registered spec, or None."""
        return self._ref_of.get(id(spec))

    def iter_collections(
            self) -> Iterator[tuple[CollectionRef, CollectionSpec]]:
        """Every collection (nested included) in registration order."""
        return iter(list(self._order))

    def allowed_ops(self) -> frozenset[str]:
        """Union of every collection's ``ops`` names (informational).

        The read-only guard uses :meth:`allowed_pairs`, which binds each
        op to the client that declared it.
        """
        ops: set[str] = set()
        for _ref, spec in self._order:
            ops |= set(spec.ops)
        return frozenset(ops)

    def allowed_pairs(self) -> frozenset[tuple[str, str]]:
        """Client-scoped allow-list: ``(spec.client, Op)`` pairs."""
        pairs: set[tuple[str, str]] = set()
        for _ref, spec in self._order:
            pairs.update((spec.client, op) for op in spec.ops)
        return frozenset(pairs)

    def summary(self) -> list[tuple[str, str, str]]:
        """``(service, collection, scope)`` per resource type."""
        return [(ref.service, ref.collection, ref.scope)
                for ref, _spec in self._order]

    def layouts(self) -> list[Layout]:
        """One :class:`Layout` per resource type, in registration order."""
        return [layout_of(ref, spec) for ref, spec in self._order]

    def validate(self) -> list[str]:
        """Return a list of problems; empty when every spec is sound."""
        from awsmount.session.clients import DENIED_OPS

        problems: list[str] = list(self._dup_services) + list(
            self._dup_refs)
        for ref, spec in self._order:
            if not spec.name or "/" in spec.name:
                problems.append(f"{ref}: invalid collection name")
            if not spec.client:
                problems.append(f"{ref}: empty client")
            if not spec.ops:
                problems.append(f"{ref}: ops is empty")
            for op in sorted(spec.ops):
                if not op.startswith(_READ_PREFIXES):
                    problems.append(f"{ref}: op {op} is not a read op")
                if op in DENIED_OPS:
                    problems.append(f"{ref}: op {op} is denied")
            # Alternatives (same link name, different target collection;
            # the first that resolves wins) are legitimate: a flow log
            # attaches to a VPC, a subnet or an ENI. The same name AND the
            # same target twice is a mistake.
            by_name: dict[str, list[CollectionRef]] = {}
            for link in spec.links:
                by_name.setdefault(link.name, []).append(link.target)
            for link_name, targets in sorted(by_name.items()):
                if len(targets) != len(set(targets)):
                    problems.append(
                        f"{ref}: duplicate link names ({link_name})")
            for link in spec.links:
                target = CollectionRef(*link.target)
                if target not in self._by_ref:
                    problems.append(
                        f"{ref}: link {link.name} targets unknown "
                        f"{target}")
            for source in spec.referenced_by:
                src = CollectionRef(*source.source)
                if src not in self._by_ref:
                    problems.append(
                        f"{ref}: referenced-by source unknown {src}")
                elif src.scope != ref.scope:
                    problems.append(
                        f"{ref}: referenced-by source {src} is in "
                        "another scope")
        return problems
