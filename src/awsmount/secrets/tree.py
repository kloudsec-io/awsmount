"""The ``awsmount secrets`` tree (ARCHITECTURE: awsmount secrets).

::

    /
      secretsmanager/<name>/value
                           /describe.json
                           /versions/<stage>
      ssm/<path>/<to>/<parameter>
          ssm/<path>/<to>/<dir>/@value     (a name that is also a prefix)

Listing never reads a value: Secrets Manager is listed with
``ListSecrets`` and Parameter Store with ``DescribeParameters``. A value
is fetched, uncached by the generic TTL cache, the first time its file is
read, and then lives in the :class:`ValueStore` for the TTL.
"""

from __future__ import annotations

import hashlib
import stat as _stat
import sys
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any

from awsmount.errors import NotFound, PermissionDenied, UpstreamError
from awsmount.secrets.store import ValueStore
from awsmount.session.context import Scope
from awsmount.session.progress import clear_line
from awsmount.vfs.node import Content, DirNode, FileNode, Node
from awsmount.vfs.path import assign_names
from awsmount.vfs.resolver import VFS
from awsmount.vfs.stat import Stat

if TYPE_CHECKING:
    from awsmount.session.context import Context

__all__ = [
    "PENDING_STAGE",
    "SecretValueFile",
    "SecretsRoot",
    "SecretsManagerDir",
    "SsmRootDir",
    "build_vfs",
]

PENDING_STAGE = "AWSPENDING"
"""Never shown: it can be an in-flight rotation value."""
CURRENT_STAGE = "AWSCURRENT"
VALUE_FILE = "value"
DIR_VALUE_FILE = "@value"


FILE_MODE = _stat.S_IFREG | 0o400
DIR_MODE = _stat.S_IFDIR | 0o500


class PrivateDir(DirNode):
    """A directory only its owner can enter."""

    def stat(self) -> Stat:
        """Directory stat with mode 0500."""
        return replace(super().stat(), mode=DIR_MODE)


class SecretValueFile(FileNode):
    """A file whose content is a secret value.

    The value is fetched on first read and kept in the
    :class:`ValueStore` (never in the generic render cache) so that it
    can be overwritten when it expires.
    """

    def __init__(self, name: str, parent: DirNode, ctx: Context,
                 fetch: Callable[[], bytes], store: ValueStore,
                 key: tuple[Any, ...]) -> None:
        super().__init__(name, parent, ctx, fetch, lazy=True)
        self._fetch = fetch
        self._store = store
        self._key = key
        self._fetching = threading.Lock()

    @property
    def is_rendered(self) -> bool:
        """True while the value is held in memory."""
        return self._store.size(self._key) is not None

    def invalidate(self) -> None:
        """Wipe the held value so the next read fetches it again."""
        self._store.discard(self._key)

    def content(self) -> bytes:
        """The value; fetched once per TTL, single flight."""
        data = self._store.get(self._key)
        if data is not None:
            return data
        with self._fetching:
            data = self._store.get(self._key)
            if data is not None:
                return data
            refused = self._store.denied(self._key)
            if refused is not None:
                raise refused
            try:
                data = self._fetch()
            except PermissionDenied as exc:
                self._store.put_denied(self._key, exc,
                                       float(self.ctx.config.negative_ttl))
                raise
            self._store.put(self._key, data)
            return data

    def known_size(self) -> int | None:
        """Length of the held value (None when not held)."""
        return self._store.size(self._key)

    def mtime(self) -> float:
        """Fetch time of the held value, else the parent's time."""
        fetched = self._store.fetched_at(self._key)
        return fetched if fetched is not None else super().mtime()

    def stat(self, *, render: bool = True) -> Stat:
        """File stat with mode 0400 (the owner only)."""
        return replace(super().stat(render=render), mode=FILE_MODE)


class Sources:
    """What the tree nodes share: session context, scope and value store."""

    def __init__(self, ctx: Context, scope: Scope,
                 store: ValueStore) -> None:
        self.ctx = ctx
        self.scope = scope
        self.store = store

    def _log(self, kind: str, name: str) -> None:
        """With --verbose, say which value is being fetched (never it)."""
        if self.ctx.config.verbose:
            clear_line()
            sys.stderr.write(f"[awsmount] read value {kind} {name}\n")
            sys.stderr.flush()

    def _read(self, client: str, op: str, label: str,
              **params: Any) -> dict[str, Any]:
        """One uncached value read; a vanished value is ENOENT."""
        try:
            return self.ctx.call_uncached(self.scope, client, op, **params)
        except UpstreamError as exc:
            if exc.kind == "not-found":
                raise NotFound(f"{label}: {exc.code}") from exc
            raise

    def secret_fetch(self, secret_id: str, stage: str | None
                     ) -> Callable[[], bytes]:
        """Reader of one Secrets Manager value (current or a stage)."""
        def fetch() -> bytes:
            self._log("secretsmanager", f"{secret_id} {stage or ''}".strip())
            params: dict[str, Any] = {"SecretId": secret_id}
            if stage is not None:
                params["VersionStage"] = stage
            resp = self._read("secretsmanager", "get_secret_value",
                              secret_id, **params)
            text = resp.get("SecretString")
            if text is not None:
                return str(text).encode("utf-8")
            blob = resp.get("SecretBinary")
            return bytes(blob) if blob is not None else b""
        return fetch

    def parameter_fetch(self, name: str) -> Callable[[], bytes]:
        """Reader of one decrypted Parameter Store value."""
        def fetch() -> bytes:
            self._log("ssm", name)
            resp = self._read("ssm", "get_parameter", name, Name=name,
                              WithDecryption=True)
            value = (resp.get("Parameter") or {}).get("Value")
            return str(value if value is not None else "").encode("utf-8")
        return fetch


class SecretsRoot(PrivateDir):
    """``/``: the two services."""

    def __init__(self, ctx: Context, src: Sources) -> None:
        self._src = src
        super().__init__("", None, ctx, self._load, static=True)

    def _load(self, node: DirNode) -> list[Node]:
        return [SecretsManagerDir(node, self.ctx, self._src),
                SsmRootDir(node, self.ctx, self._src)]


def _names(items: Iterable[tuple[str, str]]) -> dict[str, str]:
    """Unique directory names for ``(key, display)`` pairs."""
    return assign_names(list(items))


def _short(text: str) -> str:
    """Short stable tag that tells apart names differing only in case."""
    return hashlib.blake2b(text.encode("utf-8", "surrogatepass"),
                           digest_size=3).hexdigest()


def _secret_tag(item: dict[str, Any]) -> str:
    """Tag of a listed secret: the random suffix of its ARN."""
    arn = str(item.get("ARN") or "")
    tail = arn.rsplit("-", 1)[-1] if "-" in arn else ""
    return tail if len(tail) == 6 else _short(str(item["Name"]))


class SecretsManagerDir(PrivateDir):
    """``/secretsmanager``: one directory per secret."""

    def __init__(self, parent: DirNode, ctx: Context,
                 src: Sources) -> None:
        self._src = src
        super().__init__("secretsmanager", parent, ctx, self._load)

    def _load(self, node: DirNode) -> list[Node]:
        src = self._src
        items = [s for s in src.ctx.paginate(
            src.scope, "secretsmanager", "list_secrets", "SecretList")
            if isinstance(s, dict) and s.get("Name")]
        tags = {str(i["Name"]): _secret_tag(i) for i in items}
        names = _names((tag, name) for name, tag in tags.items())
        return [SecretDir(names[tags[str(i["Name"])]], node, self.ctx,
                          src, i) for i in items]


def _stages(item: dict[str, Any]) -> list[str]:
    """Staging labels of the listed versions, ``AWSPENDING`` excluded."""
    found: set[str] = set()
    for stages in (item.get("SecretVersionsToStages") or {}).values():
        found.update(str(s) for s in stages or ())
    found.discard(PENDING_STAGE)
    return sorted(found)


class SecretDir(PrivateDir):
    """``/secretsmanager/<name>``: ``value``, ``describe.json``, versions."""

    def __init__(self, dirname: str, parent: DirNode, ctx: Context,
                 src: Sources, item: dict[str, Any]) -> None:
        self._src = src
        self._item = item
        super().__init__(dirname, parent, ctx, self._load, static=True)

    def _load(self, node: DirNode) -> list[Node]:
        src, item = self._src, self._item
        secret_id = str(item.get("ARN") or item["Name"])
        key = ("secretsmanager", secret_id)
        stages = _stages(item)
        out: list[Node] = [
            FileNode("describe.json", node, self.ctx,
                     lambda: _describe(item), lazy=False)]
        if not item.get("SecretVersionsToStages") or CURRENT_STAGE in stages:
            out.append(SecretValueFile(
                VALUE_FILE, node, self.ctx,
                src.secret_fetch(secret_id, None), src.store, key + (None,)))
        out.append(VersionsDir(node, self.ctx, src, secret_id, stages))
        return out


def _describe(item: dict[str, Any]) -> Content:
    """The listing entry (metadata only; no value is part of it)."""
    return dict(item)


class VersionsDir(PrivateDir):
    """``.../versions``: one file per existing staging label."""

    def __init__(self, parent: DirNode, ctx: Context, src: Sources,
                 secret_id: str, stages: list[str]) -> None:
        self._src = src
        self._secret_id = secret_id
        self._stages = stages
        super().__init__("versions", parent, ctx, self._load, static=True)

    def _load(self, node: DirNode) -> list[Node]:
        src = self._src
        names = _names((s, s) for s in self._stages)
        return [SecretValueFile(
            names[stage], node, self.ctx,
            src.secret_fetch(self._secret_id, stage), src.store,
            ("secretsmanager", self._secret_id, stage))
            for stage in self._stages]


@dataclass
class _Trie:
    """Parameter names as a tree of path components."""

    param: dict[str, Any] | None = None
    children: dict[str, _Trie] = field(default_factory=dict)


def _build_trie(params: Iterable[dict[str, Any]]) -> _Trie:
    """Nest parameters by path.

    A name without a leading ``/`` and the same name with one would
    land in the same place; the first level keeps them apart.
    """
    root = _Trie()
    for param in params:
        name = str(param["Name"])
        parts = [p for p in name.split("/") if p]
        if not parts:
            continue
        marker = "/" if name.startswith("/") else ""
        node = root
        for depth, part in enumerate(parts):
            key = f"{marker}{part}" if depth == 0 else part
            node = node.children.setdefault(key, _Trie())
        node.param = param
    return root


def _display(key: str) -> str:
    """Component text of a trie key (the first level may carry ``/``)."""
    return key.lstrip("/") if key.startswith("/") else key


class SsmRootDir(PrivateDir):
    """``/ssm``: every parameter, nested by path."""

    def __init__(self, parent: DirNode, ctx: Context,
                 src: Sources) -> None:
        self._src = src
        super().__init__("ssm", parent, ctx, self._load)

    def _load(self, node: DirNode) -> list[Node]:
        src = self._src
        params = [p for p in src.ctx.paginate(
            src.scope, "ssm", "describe_parameters", "Parameters")
            if isinstance(p, dict) and p.get("Name")]
        return _trie_nodes(_build_trie(params), node, self.ctx, src)


def _trie_nodes(trie: _Trie, parent: DirNode, ctx: Context,
                src: Sources) -> list[Node]:
    tags = {k: _short(k) for k in trie.children}
    names = _names((tags[k], _display(k)) for k in trie.children)
    out: list[Node] = []
    for key, child in trie.children.items():
        name = names[tags[key]]
        if child.children:
            out.append(SsmDir(name, parent, ctx, src, child))
        elif child.param is not None:
            out.append(_parameter_file(name, parent, ctx, src, child.param))
    return out


def _parameter_file(name: str, parent: DirNode, ctx: Context,
                    src: Sources, param: dict[str, Any]
                    ) -> SecretValueFile:
    pname = str(param["Name"])
    return SecretValueFile(name, parent, ctx, src.parameter_fetch(pname),
                           src.store, ("ssm", pname))


class SsmDir(PrivateDir):
    """A parameter path prefix; ``@value`` when the prefix is a parameter."""

    def __init__(self, name: str, parent: DirNode, ctx: Context,
                 src: Sources, trie: _Trie) -> None:
        self._src = src
        self._trie = trie
        super().__init__(name, parent, ctx, self._load, static=True)

    def _load(self, node: DirNode) -> list[Node]:
        out = _trie_nodes(self._trie, node, self.ctx, self._src)
        if self._trie.param is not None:
            out.append(_parameter_file(DIR_VALUE_FILE, node, self.ctx,
                                       self._src, self._trie.param))
        return out


def build_vfs(ctx: Context, scope: Scope, store: ValueStore) -> VFS:
    """The secrets tree for ``scope``; nothing is fetched yet."""
    return VFS(SecretsRoot(ctx, Sources(ctx, scope, store)))
