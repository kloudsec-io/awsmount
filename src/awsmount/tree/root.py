"""Root, account, region, global, service and _meta dirs.

See ARCHITECTURE: Overview.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from typing import TYPE_CHECKING

from awsmount.providers.base import CollectionRef, ServiceSpec
from awsmount.session.accounts import AccountInfo
from awsmount.session.context import Scope
from awsmount.session.errorlog import label_for
from awsmount.tree.collection import CollectionDir
from awsmount.vfs.node import Content, DirNode, FileNode, Node
from awsmount.vfs.resolver import VFS

if TYPE_CHECKING:
    from awsmount.session.context import Context

__all__ = [
    "AccountDir",
    "GlobalDir",
    "MetaDir",
    "RegionDir",
    "RootDir",
    "ServiceDir",
    "build_vfs",
]


def _const(value: Content) -> Callable[[], Content]:
    def render() -> Content:
        return value
    return render


class RootDir(DirNode):
    """``/``: one directory per resolved account.

    The listing expires (after ``negative_ttl`` while a profile failed,
    otherwise after ``ttl``) so that a profile that failed transiently
    is retried. Unchanged accounts keep their AccountDir object.
    """

    def __init__(self, ctx: Context) -> None:
        self._dirs: dict[str, AccountDir] = {}
        self._failures = False
        super().__init__("", None, ctx, self._load)

    def _ttl(self) -> float:
        ttl = float(self.ctx.config.ttl)
        if self._failures:
            return min(ttl, float(self.ctx.config.negative_ttl))
        return ttl

    def mtime(self) -> float:
        """Session start time (the root is structural)."""
        return float(self.ctx.started_at)

    def _load(self, node: DirNode) -> list[Node]:
        infos = self.ctx.accounts.accounts()
        self._failures = any(i.error is not None for i in infos)
        dirs: dict[str, AccountDir] = {}
        for info in infos:
            old = self._dirs.get(info.dirname)
            if old is not None and old.info == info:
                dirs[info.dirname] = old
            else:
                dirs[info.dirname] = AccountDir(info, node, self.ctx)
        self._dirs = dirs
        return list(dirs.values())


class AccountDir(DirNode):
    """``/<acct>``: regions, ``global`` and ``_meta``."""

    def __init__(self, info: AccountInfo, parent: DirNode,
                 ctx: Context) -> None:
        self.info = info
        super().__init__(info.dirname, parent, ctx, self._load,
                         static=True)

    def _load(self, node: DirNode) -> list[Node]:
        info = self.info
        out: list[Node] = [MetaDir(info, node, self.ctx)]
        if info.error is not None or info.account_id is None:
            return out
        for region in info.regions:
            out.append(RegionDir(region, node, self.ctx,
                                 Scope(info, region, False)))
        out.append(GlobalDir(node, self.ctx,
                             Scope(info, info.global_region, True)))
        return out


def _service_dirs(node: DirNode, ctx: Context, scope: Scope,
                  services: list[ServiceSpec]) -> list[Node]:
    return [ServiceDir(svc, node, ctx, scope) for svc in services
            if ctx.config.service_enabled(svc.dirname)]


class RegionDir(DirNode):
    """``/<acct>/<region>``: regional services."""

    def __init__(self, region: str, parent: DirNode, ctx: Context,
                 scope: Scope) -> None:
        self.scope = scope
        super().__init__(region, parent, ctx, self._load, static=True)

    def _load(self, node: DirNode) -> list[Node]:
        return _service_dirs(node, self.ctx, self.scope,
                             self.ctx.registry.services("region"))


class GlobalDir(DirNode):
    """``/<acct>/global``: global services."""

    def __init__(self, parent: DirNode, ctx: Context, scope: Scope) -> None:
        self.scope = scope
        super().__init__("global", parent, ctx, self._load, static=True)

    def _load(self, node: DirNode) -> list[Node]:
        return _service_dirs(node, self.ctx, self.scope,
                             self.ctx.registry.services("global"))


class ServiceDir(DirNode):
    """``.../<service>``: one CollectionDir per collection."""

    def __init__(self, service: ServiceSpec, parent: DirNode, ctx: Context,
                 scope: Scope) -> None:
        self.service = service
        self.scope = scope
        super().__init__(service.dirname, parent, ctx, self._load,
                         static=True)

    def _load(self, node: DirNode) -> list[Node]:
        svc = self.service
        return [CollectionDir(spec.name, node, self.ctx, self.scope,
                              CollectionRef(svc.scope, svc.dirname,
                                            spec.name), spec)
                for spec in svc.collections]


class MetaDir(DirNode):
    """``/<acct>/_meta``: account, identity, errors.log, stats."""

    def __init__(self, info: AccountInfo, parent: DirNode,
                 ctx: Context) -> None:
        self.info = info
        super().__init__("_meta", parent, ctx, self._load, static=True)

    def _account_json(self) -> Content:
        info = self.info
        data: dict[str, object] = {
            "AccountId": info.account_id,
            "Aliases": list(info.aliases),
            "Profile": info.profile,
            "Partition": info.partition,
            "Regions": list(info.regions),
            "GlobalRegion": info.global_region,
        }
        if info.error is not None:
            data["Error"] = info.error
        return data

    def _errors(self) -> Content:
        return self.ctx.errors.render(label_for(self.info),
                                      include_unscoped=True)

    def _stats(self) -> Content:
        ctx = self.ctx
        return {
            "api_calls_used": ctx.budget.used(),
            "budget": ctx.budget.limit or "unlimited",
            "window": ctx.config.budget_window,
            "cache": dataclasses.asdict(ctx.cache.stats()),
        }

    def _load(self, node: DirNode) -> list[Node]:
        ctx = self.ctx
        return [
            FileNode("account.json", node, ctx, self._account_json,
                     lazy=False),
            FileNode("identity.json", node, ctx,
                     _const(self.info.identity), lazy=False),
            FileNode("errors.log", node, ctx, self._errors, lazy=False,
                     volatile=True),
            FileNode("stats.json", node, ctx, self._stats, lazy=False,
                     volatile=True),
        ]


def build_vfs(ctx: Context) -> VFS:
    """Build the whole lazy tree for ``ctx``."""
    return VFS(RootDir(ctx))
