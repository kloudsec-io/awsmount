"""CollectionDir and ResourceDir builders.

See ARCHITECTURE: Resource directories.
"""

from __future__ import annotations

from collections.abc import Callable, Hashable
from typing import TYPE_CHECKING, Any

from awsmount.errors import (
    AwsMountError,
    BudgetExceeded,
    PermissionDenied,
    UpstreamError,
)
from awsmount.providers.base import (
    CollectionRef,
    CollectionSpec,
    FileSpec,
    LinkSpec,
    ListCtx,
    ResourceCtx,
    SubdirSpec,
)
from awsmount.providers.common import as_list
from awsmount.session.errorlog import ErrorKind, classify
from awsmount.session.redact import REDACTED
from awsmount.tree.tags import TagsDir, name_tag, resource_tags
from awsmount.vfs.node import Content, DirNode, FileNode, Node, SymlinkNode
from awsmount.vfs.path import (
    assign_names,
    basename,
    join,
    unescape_name,
)

if TYPE_CHECKING:
    from awsmount.session.context import Context, Scope

__all__ = [
    "CollectionDir",
    "LinkDir",
    "ResourceDir",
    "collection_path",
    "guarded_render",
    "listing_key",
    "named_items",
    "scope_path",
]

NamedItem = tuple[str, str, dict[str, Any]]


def scope_path(scope: Scope) -> str:
    """``/<acct>/<region>`` or ``/<acct>/global``."""
    segment = "global" if scope.is_global else scope.region
    return f"/{scope.account.dirname}/{segment}"


def collection_path(scope: Scope, ref: CollectionRef) -> str:
    """Absolute path of a top-level collection directory."""
    return f"{scope_path(scope)}/{ref.service}/{ref.collection}"


def listing_key(scope: Scope, ref: CollectionRef, spec: CollectionSpec,
                parent: ResourceCtx | None = None) -> Hashable:
    """Cache key of a named listing (profile, region, client first)."""
    return (scope.account.profile, scope.region, spec.client,
            "__listing__", f"{ref.service}/{ref.collection}",
            parent.path if parent is not None else "")


def named_items(ctx: Context, scope: Scope, ref: CollectionRef,
                spec: CollectionSpec,
                parent: ResourceCtx | None = None) -> list[NamedItem]:
    """List a collection once per TTL: ``[(key, dirname, item)]``.

    Every collection goes through :func:`assign_names`, so names that
    differ only by case get the deterministic ``~key`` suffix (safe on
    case-insensitive filesystems), including id-keyed collections.
    """

    def load() -> list[NamedItem]:
        items = spec.lister(ListCtx(ctx, scope, spec, parent))
        keyed: list[tuple[str, dict[str, Any]]] = []
        seen: set[str] = set()
        for item in items:
            key = str(spec.key(item))
            if key in seen:
                continue
            seen.add(key)
            keyed.append((key, item))
        display = spec.display
        names = assign_names([
            (k, (display(i) if display is not None else k) or k)
            for k, i in keyed])
        return [(k, names[k], i) for k, i in keyed]

    return ctx.cache.get_or_load(listing_key(scope, ref, spec, parent),
                                 load)


def _op_of(exc: BaseException, default: str) -> str:
    if isinstance(exc, UpstreamError) and exc.op:
        return exc.op
    return default


def _report(ctx: Context, scope: Scope, service: str, op: str,
            exc: BaseException) -> None:
    """Log a listing-style failure unless it is NOT_CONFIGURED."""
    if classify(exc) is ErrorKind.NOT_CONFIGURED:
        return
    ctx.errors.record(scope, service, _op_of(exc, op), exc)


def guarded_render(ctx: Context, scope: Scope, service: str, op: str,
                   fn: Callable[[], Content],
                   not_configured: frozenset[str] = frozenset()
                   ) -> Callable[[], Content]:
    """Wrap a renderer with the lazy-file failure rules of §3.8."""

    def run() -> Content:
        try:
            return fn()
        except BudgetExceeded:
            raise
        except UpstreamError as exc:
            kind = classify(exc)
            if exc.code in not_configured or \
                    kind is ErrorKind.NOT_CONFIGURED:
                return None
            ctx.errors.record(scope, service, _op_of(exc, op), exc)
            if kind is ErrorKind.NOT_FOUND:
                return None
            if kind is ErrorKind.ACCESS_DENIED and \
                    not isinstance(exc, PermissionDenied):
                raise PermissionDenied(str(exc), code=exc.code,
                                       kind=exc.kind, service=exc.service,
                                       op=exc.op) from exc
            raise
        except AwsMountError:
            raise
        except Exception as exc:
            ctx.errors.record(scope, service, op, exc)
            raise UpstreamError(f"{service}:{op}: {exc}", kind="other",
                                service=service, op=op) from exc

    return run


def _const(value: Content) -> Callable[[], Content]:
    def render() -> Content:
        return value
    return render


class LinkDir(DirNode):
    """A directory that holds only symlinks (``links/``, ``referenced-by/``).

    Marked so that ``export --links skip`` can leave it out instead of
    writing an empty skeleton.
    """


class CollectionDir(DirNode):
    """One directory per resource, from one cached list call."""

    def __init__(self, name: str, parent: DirNode, ctx: Context,
                 scope: Scope, ref: CollectionRef, spec: CollectionSpec,
                 parent_rc: ResourceCtx | None = None) -> None:
        self.scope = scope
        self.ref = ref
        self.spec = spec
        self.parent_rc = parent_rc
        super().__init__(name, parent, ctx, self._load)

    def _load(self, node: DirNode) -> list[Node]:
        ctx, scope, spec = self.ctx, self.scope, self.spec
        try:
            named = named_items(ctx, scope, self.ref, spec, self.parent_rc)
        except BudgetExceeded:
            raise
        except Exception as exc:
            _report(ctx, scope, spec.client, "list", exc)
            return []
        fetched = ctx.fetched_at(listing_key(scope, self.ref, spec,
                                             self.parent_rc))
        out: list[Node] = []
        for key, dirname, item in named:
            rc = ResourceCtx(ctx=ctx, scope=scope, spec=spec, item=item,
                             key=key, dirname=dirname,
                             path=join(node.path, dirname),
                             parent=self.parent_rc)
            out.append(ResourceDir(dirname, node, ctx, rc, self.ref,
                                   fetched_at=fetched))
        return out


class ResourceDir(DirNode):
    """Files, links and nested collections of one resource."""

    def __init__(self, name: str, parent: DirNode, ctx: Context,
                 rc: ResourceCtx, ref: CollectionRef, *,
                 fetched_at: float | None = None) -> None:
        self.rc = rc
        self.ref = ref
        super().__init__(name, parent, ctx, self._load,
                         fetched_at=fetched_at)

    # -- helpers -----------------------------------------------------

    def _guard(self, op: str, fn: Callable[[], Content],
               not_configured: frozenset[str] = frozenset()
               ) -> Callable[[], Content]:
        return guarded_render(self.ctx, self.rc.scope, self.rc.spec.client,
                              op, fn, not_configured)

    def _report(self, exc: BaseException, op: str) -> None:
        _report(self.ctx, self.rc.scope, self.rc.spec.client, op, exc)

    def _try(self, op: str, fn: Callable[[], Any]) -> Any:
        try:
            return fn()
        except BudgetExceeded:
            raise
        except Exception as exc:
            self._report(exc, op)
            return None

    def _redact(self, rule: str | None, data: Content) -> Content:
        if isinstance(data, (dict, list)):
            return self.ctx.redaction.json(rule, data)
        return data

    # -- children ----------------------------------------------------

    def _load(self, node: DirNode) -> list[Node]:
        rc, spec, ctx = self.rc, self.rc.spec, self.ctx
        out: list[Node] = [self._describe_node(node)]
        if spec.arn is not None:
            arn_fn = spec.arn
            arn = self._try("arn", lambda: arn_fn(rc.item, rc.scope))
            if arn is not None:
                out.append(FileNode("arn", node, ctx, _const(str(arn)),
                                    lazy=False))
        if spec.name_of is not None:
            name_fn = spec.name_of
            name = self._try("name", lambda: name_fn(rc.item))
        else:
            name = name_tag(spec.tags, rc.item)
        if name is not None:
            out.append(FileNode("name", node, ctx, _const(str(name)),
                                lazy=False))
        if spec.tags.active:
            out.extend(self._tag_nodes(node))
        for entry in spec.files:
            if isinstance(entry, FileSpec):
                out.append(self._file_node(node, entry))
            else:
                out.append(self._subdir_node(node, entry))
        if spec.links:
            out.append(LinkDir("links", node, ctx, self._load_links))
        if spec.referenced_by:
            out.append(LinkDir("referenced-by", node, ctx,
                               self._load_refs))
        for child in spec.children:
            child_ref = CollectionRef(self.ref.scope, self.ref.service,
                                      f"{self.ref.collection}/{child.name}")
            out.append(CollectionDir(child.name, node, ctx, rc.scope,
                                     child_ref, child, parent_rc=rc))
        return out

    def _describe_node(self, node: DirNode) -> FileNode:
        rc = self.rc
        spec = rc.spec

        def render() -> Content:
            return self._redact(spec.redact, rc.detail())

        return FileNode("describe.json", node, self.ctx,
                        self._guard("describe", render),
                        lazy=spec.describe is not None)

    def _tag_nodes(self, node: DirNode) -> list[Node]:
        rc = self.rc
        lazy = rc.spec.tags.fetch is not None

        def render() -> Content:
            return resource_tags(rc)

        def fetch() -> dict[str, str]:
            return resource_tags(rc)

        def on_error(exc: BaseException) -> None:
            self._report(exc, "tags")

        return [
            FileNode("tags.json", node, self.ctx,
                     self._guard("tags", render), lazy=lazy),
            TagsDir("tags", node, self.ctx, fetch, on_error),
        ]

    def _file_node(self, node: DirNode, fs: FileSpec) -> FileNode:
        ctx, rc = self.ctx, self.rc
        if fs.whole is not None and ctx.redaction.whole_file(fs.whole):
            return FileNode(fs.name, node, ctx, _const(REDACTED),
                            lazy=False)

        def render() -> Content:
            data = fs.render(rc)
            if fs.whole is not None and isinstance(data, (str, bytes)):
                data = ctx.redaction.text(fs.whole, data)
            return self._redact(fs.redact, data)

        return FileNode(fs.name, node, ctx,
                        self._guard(fs.name, render, fs.not_configured),
                        lazy=fs.lazy)

    def _subdir_node(self, node: DirNode, sd: SubdirSpec) -> DirNode:
        rc, ctx = self.rc, self.ctx

        def load(sub: DirNode) -> list[Node]:
            try:
                entries = dict(sd.entries(rc))
            except BudgetExceeded:
                raise
            except Exception as exc:
                self._report(exc, sd.name)
                return []
            names = assign_names([(k, k) for k in entries])
            out: list[Node] = []
            for key, fn in entries.items():
                out.append(FileNode(
                    names[key], sub, ctx,
                    self._guard(sd.name, self._entry_render(sd, fn)),
                    lazy=sd.lazy))
            return out

        return DirNode(sd.name, node, ctx, load)

    def _entry_render(self, sd: SubdirSpec, fn: Callable[[], Content]
                      ) -> Callable[[], Content]:
        def render() -> Content:
            return self._redact(sd.redact, fn())
        return render

    # -- links -------------------------------------------------------

    def _link_values(self, ls: LinkSpec) -> list[str]:
        raw = self._try(f"links/{ls.name}", lambda: ls.values(self.rc))
        return list(dict.fromkeys(as_list(raw)))

    def _resolve_link(self, ls: LinkSpec, value: str) -> str | None:
        try:
            return self.ctx.links.dirpath(self.rc.scope, ls.target, value,
                                          ls.by)
        except BudgetExceeded:
            raise
        except AwsMountError:
            return None

    def _load_links(self, node: DirNode) -> list[Node]:
        out: list[Node] = []
        taken: set[str] = set()
        for ls in self.rc.spec.links:
            if ls.name in taken:
                continue  # alternative specs: the first that resolved wins
            values = self._link_values(ls)
            if ls.many:
                taken.add(ls.name)
                out.append(DirNode(ls.name, node, self.ctx,
                                   self._many_loader(ls, values)))
                continue
            for value in values[:1]:
                target = self._resolve_link(ls, value)
                if target is not None:
                    taken.add(ls.name)
                    out.append(SymlinkNode(
                        ls.name, node, self.ctx,
                        self.ctx.links.relative(node.path, target)))
        return out

    def _many_loader(self, ls: LinkSpec, values: list[str]
                     ) -> Callable[[DirNode], list[Node]]:
        def load(sub: DirNode) -> list[Node]:
            targets: list[str] = []
            for value in values:
                target = self._resolve_link(ls, value)
                if target is not None and target not in targets:
                    targets.append(target)
            names = assign_names([(t, unescape_name(basename(t)))
                                  for t in targets])
            return [SymlinkNode(names[t], sub, self.ctx,
                                self.ctx.links.relative(sub.path, t))
                    for t in targets]
        return load

    def _load_refs(self, node: DirNode) -> list[Node]:
        try:
            entries = self.ctx.refindex.entries(self.rc.scope, self.ref,
                                                self.rc.key)
        except BudgetExceeded:
            raise
        except Exception as exc:
            self._report(exc, "referenced-by")
            return []
        out: list[Node] = []
        seen: set[str] = set()
        for name, target in entries:
            if name in seen:
                continue
            seen.add(name)
            out.append(SymlinkNode(name, node, self.ctx,
                                   self.ctx.links.relative(node.path,
                                                           target)))
        return out
