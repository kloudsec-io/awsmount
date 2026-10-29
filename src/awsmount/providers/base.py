"""Provider plugin protocol (ARCHITECTURE: Providers)."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, NamedTuple

from awsmount.vfs.render import Content

if TYPE_CHECKING:
    from awsmount.session.context import Context, Scope

__all__ = [
    "CollectionRef",
    "CollectionSpec",
    "FileSpec",
    "LinkSpec",
    "ListCtx",
    "RefSource",
    "ResourceCtx",
    "Scoping",
    "ServiceSpec",
    "SubdirSpec",
    "TagSpec",
]

Scoping = Literal["region", "global"]


class CollectionRef(NamedTuple):
    """Address of a collection: scope, service dir, collection name."""

    scope: Scoping
    service: str
    collection: str


@dataclass(frozen=True)
class ListCtx:
    """Arguments of a collection lister."""

    ctx: Context
    scope: Scope
    spec: CollectionSpec
    parent: ResourceCtx | None

    def call(self, op: str, **p: Any) -> dict[str, Any]:
        """Cached call on the collection's client."""
        return self.ctx.call(self.scope, self.spec.client, op, **p)

    def paginate(self, op: str, key: str | Sequence[str],
                 **p: Any) -> list[Any]:
        """Cached paginated call on the collection's client."""
        return self.ctx.paginate(self.scope, self.spec.client, op, key, **p)


@dataclass(frozen=True)
class ResourceCtx:
    """One listed resource, passed to file renderers and links."""

    ctx: Context
    scope: Scope
    spec: CollectionSpec
    item: dict[str, Any]
    key: str
    dirname: str
    path: str
    parent: ResourceCtx | None

    def call(self, op: str, **p: Any) -> dict[str, Any]:
        """Cached call on the collection's client."""
        return self.ctx.call(self.scope, self.spec.client, op, **p)

    def paginate(self, op: str, key: str | Sequence[str],
                 **p: Any) -> list[Any]:
        """Cached paginated call on the collection's client."""
        return self.ctx.paginate(self.scope, self.spec.client, op, key, **p)

    def detail(self) -> dict[str, Any]:
        """``spec.describe(self)`` if set (cached calls), else the item."""
        if self.spec.describe is not None:
            return self.spec.describe(self)
        return self.item


@dataclass(frozen=True)
class FileSpec:
    """An extra file in each resource directory."""

    name: str
    render: Callable[[ResourceCtx], Content]
    lazy: bool = False
    redact: str | None = None
    whole: str | None = None
    not_configured: frozenset[str] = frozenset()


@dataclass(frozen=True)
class SubdirSpec:
    """A lazy directory of files."""

    name: str
    entries: Callable[[ResourceCtx], Mapping[str, Callable[[], Content]]]
    lazy: bool = True
    redact: str | None = None


@dataclass(frozen=True)
class LinkSpec:
    """Relationship rendered as symlink(s) under ``links/``."""

    name: str
    target: CollectionRef
    values: Callable[[ResourceCtx], str | Iterable[str] | None]
    by: Literal["key", "arn", "name"] = "key"
    many: bool = False


@dataclass(frozen=True)
class RefSource:
    """A collection whose items reference the owning collection."""

    source: CollectionRef
    values: Callable[[dict[str, Any]], Iterable[str]]


@dataclass(frozen=True)
class TagSpec:
    """Where tags come from; no inline field and no fetch = no tags."""

    inline: str | None = None
    style: Literal["list", "map"] = "list"
    fetch: Callable[[ResourceCtx], dict[str, str]] | None = None

    @staticmethod
    def none() -> TagSpec:
        """A spec meaning "this collection has no tags"."""
        return TagSpec()

    @property
    def active(self) -> bool:
        """True when tags.json and tags/ are produced."""
        return self.inline is not None or self.fetch is not None


@dataclass(frozen=True)
class CollectionSpec:
    """One resource collection of a service."""

    name: str
    client: str
    lister: Callable[[ListCtx], list[dict[str, Any]]]
    key: Callable[[dict[str, Any]], str]
    ops: frozenset[str]
    display: Callable[[dict[str, Any]], str] | None = None
    arn: Callable[[dict[str, Any], Scope], str | None] | None = None
    name_of: Callable[[dict[str, Any]], str | None] | None = None
    describe: Callable[[ResourceCtx], dict[str, Any]] | None = None
    redact: str | None = None
    tags: TagSpec = TagSpec()
    files: tuple[FileSpec | SubdirSpec, ...] = ()
    links: tuple[LinkSpec, ...] = ()
    referenced_by: tuple[RefSource, ...] = ()
    children: tuple[CollectionSpec, ...] = ()
    lookup: Mapping[str, Callable[[dict[str, Any]], str]] = field(
        default_factory=dict)
    key_from_arn: Callable[[str], str] | None = None


@dataclass(frozen=True)
class ServiceSpec:
    """A service directory and its collections."""

    dirname: str
    scope: Scoping
    collections: tuple[CollectionSpec, ...]
