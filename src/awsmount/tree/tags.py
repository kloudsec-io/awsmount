"""Tag normalisation and the ``tags/`` directory."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any

from awsmount.errors import BudgetExceeded
from awsmount.providers.base import ResourceCtx, TagSpec
from awsmount.vfs.node import Content, DirNode, FileNode, Node
from awsmount.vfs.path import assign_names

if TYPE_CHECKING:
    from awsmount.session.context import Context

__all__ = [
    "TagsDir",
    "inline_tags",
    "name_tag",
    "normalise_tags",
    "resource_tags",
]


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def normalise_tags(raw: Any, style: str = "list") -> dict[str, str]:
    """Return ``{Key: Value}`` sorted, from list or map shapes."""
    out: dict[str, str] = {}
    if raw is None:
        return out
    if isinstance(raw, Mapping):
        for key, value in raw.items():
            out[str(key)] = _text(value)
    elif isinstance(raw, list):
        for entry in raw:
            if not isinstance(entry, Mapping):
                continue
            key = entry.get("Key", entry.get("key"))
            if key is None:
                continue
            out[str(key)] = _text(entry.get("Value", entry.get("value")))
    return dict(sorted(out.items()))


def inline_tags(spec: TagSpec, item: Mapping[str, Any]
                ) -> dict[str, str] | None:
    """Tags carried in the listed item, or None if not inline."""
    if spec.inline is None:
        return None
    return normalise_tags(item.get(spec.inline), spec.style)


def resource_tags(rc: ResourceCtx) -> dict[str, str]:
    """Tags of a resource (lazy ``fetch`` wins over inline)."""
    spec = rc.spec.tags
    if spec.fetch is not None:
        return normalise_tags(spec.fetch(rc), "map")
    return inline_tags(spec, rc.item) or {}


def name_tag(spec: TagSpec, item: Mapping[str, Any]) -> str | None:
    """Inline ``Name`` tag value (never makes an API call)."""
    tags = inline_tags(spec, item)
    if not tags:
        return None
    return tags.get("Name")


def _const(value: str) -> Callable[[], Content]:
    def render() -> Content:
        return value
    return render


class TagsDir(DirNode):
    """``tags/<escaped Key>`` files, one per tag."""

    def __init__(self, name: str, parent: DirNode, ctx: Context,
                 fetch: Callable[[], dict[str, str]],
                 on_error: Callable[[BaseException], None]) -> None:
        self._fetch = fetch
        self._on_error = on_error
        super().__init__(name, parent, ctx, self._load)

    def _load(self, node: DirNode) -> list[Node]:
        try:
            tags = self._fetch()
        except BudgetExceeded:
            raise
        except Exception as exc:
            self._on_error(exc)
            return []
        names = assign_names([(k, k) for k in tags])
        return [FileNode(names[k], node, self.ctx, _const(v), lazy=False)
                for k, v in tags.items()]
