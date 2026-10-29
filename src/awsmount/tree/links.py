"""Relationship symlinks and the referenced-by index.

See ARCHITECTURE: Links and referenced-by.
"""

from __future__ import annotations

import posixpath
from typing import TYPE_CHECKING, Any

from awsmount.errors import AwsMountError, BudgetExceeded
from awsmount.providers.base import CollectionRef, CollectionSpec
from awsmount.providers.common import Arn, parse_arn
from awsmount.session.context import Scope
from awsmount.tree.collection import collection_path, named_items
from awsmount.vfs.path import escape_name

if TYPE_CHECKING:
    from awsmount.session.context import Context

__all__ = ["LinkResolver", "ReferencedByIndex"]


def _mounted(ctx: Context, ref: CollectionRef) -> bool:
    if "/" in ref.collection:
        return False
    if ctx.registry.service(ref.scope, ref.service) is None:
        return False
    return ctx.config.service_enabled(ref.service)


class LinkResolver:
    """Turns link values into absolute VFS directory paths."""

    def __init__(self, ctx: Context) -> None:
        self._ctx = ctx

    @staticmethod
    def relative(from_dir: str, target: str) -> str:
        """Relative POSIX path from directory ``from_dir`` to ``target``."""
        return posixpath.relpath(target, from_dir)

    def dirpath(self, scope: Scope, ref: CollectionRef, value: str,
                by: str = "key") -> str | None:
        """Absolute path of the target resource dir, or None if absent.

        The target must exist in the (cached) listing of its collection,
        so links are never dangling. Listing failures of the target
        collection propagate as ``AwsMountError``; callers omit the link.
        """
        if not value:
            return None
        ctx = self._ctx
        spec = ctx.registry.collection(ref)
        if spec is None or not _mounted(ctx, ref):
            return None
        arn = parse_arn(value)
        target_scope = self._target_scope(scope, ref, arn)
        if target_scope is None:
            return None
        if arn is not None and by == "key":
            by = "arn"
        key = self._key(target_scope, ref, spec, value, by)
        if key is None:
            return None
        dirname = self._dirname(target_scope, ref, spec, key)
        if dirname is None:
            return None
        return f"{collection_path(target_scope, ref)}/{dirname}"

    def _target_scope(self, scope: Scope, ref: CollectionRef,
                      arn: Arn | None) -> Scope | None:
        account = scope.account
        region: str | None = None
        if arn is not None:
            if arn.account and arn.account != account.account_id:
                other = self._ctx.accounts.by_id(arn.account)
                if other is None or other.error is not None:
                    return None
                account = other
            region = arn.region or None
        if ref.scope == "global":
            return Scope(account, account.global_region, True)
        if region is None:
            region = scope.region
        if region not in account.regions:
            return None
        return Scope(account, region, False)

    def _key(self, scope: Scope, ref: CollectionRef, spec: CollectionSpec,
             value: str, by: str) -> str | None:
        if by == "arn":
            if spec.key_from_arn is not None:
                try:
                    return spec.key_from_arn(value)
                except Exception:
                    return None
            return self._lookup(scope, ref, spec, "arn", value)
        if by == "name":
            return self._lookup(scope, ref, spec, "name", value)
        return value

    @staticmethod
    def _field(spec: CollectionSpec, field_name: str,
               item: dict[str, Any], key: str, scope: Scope) -> Any:
        try:
            fn = spec.lookup.get(field_name)
            if fn is not None:
                return fn(item)
            if field_name == "arn" and spec.arn is not None:
                return spec.arn(item, scope)
            if field_name == "name":
                if spec.name_of is not None:
                    return spec.name_of(item)
                if spec.display is not None:
                    return spec.display(item)
                return key
        except Exception:
            return None
        return None

    def _lookup(self, scope: Scope, ref: CollectionRef,
                spec: CollectionSpec, field_name: str,
                value: str) -> str | None:
        for key, _dirname, item in named_items(self._ctx, scope, ref, spec):
            if self._field(spec, field_name, item, key, scope) == value:
                return key
        return None

    def _dirname(self, scope: Scope, ref: CollectionRef,
                 spec: CollectionSpec, key: str) -> str | None:
        """Dirname of ``key`` in the listing; None when it is absent."""
        for item_key, dirname, _item in named_items(self._ctx, scope, ref,
                                                    spec):
            if item_key == key:
                return dirname
        return None


class ReferencedByIndex:
    """Reverse index: who references a given resource."""

    def __init__(self, ctx: Context) -> None:
        self._ctx = ctx

    def entries(self, scope: Scope, target: CollectionRef,
                key: str) -> list[tuple[str, str]]:
        """``(link name, absolute target path)`` for sources of ``key``."""
        ctx = self._ctx
        spec = ctx.registry.collection(target)
        if spec is None or not spec.referenced_by:
            return []
        cache_key = (scope.account.profile, scope.region, spec.client,
                     "__refindex__", f"{target.service}/{target.collection}")
        index = ctx.cache.get_or_load(cache_key,
                                      lambda: self._build(scope, spec))
        return list(index.get(key, ()))

    def _build(self, scope: Scope, spec: CollectionSpec
               ) -> dict[str, list[tuple[str, str]]]:
        ctx = self._ctx
        mapping: dict[str, list[tuple[str, str]]] = {}
        for source in spec.referenced_by:
            ref = source.source
            src_spec = ctx.registry.collection(ref)
            if src_spec is None or not _mounted(ctx, ref):
                continue
            try:
                named = named_items(ctx, scope, ref, src_spec)
            except BudgetExceeded:
                raise
            except AwsMountError:
                continue
            base = collection_path(scope, ref)
            for _key, dirname, item in named:
                try:
                    values = set(source.values(item))
                except Exception:
                    continue
                name = escape_name(f"{ref.service}-{ref.collection}-"
                                   f"{dirname}")
                for value in values:
                    if not isinstance(value, str) or not value:
                        continue
                    mapping.setdefault(value, []).append(
                        (name, f"{base}/{dirname}"))
        return {k: sorted(v) for k, v in mapping.items()}
