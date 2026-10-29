"""Shared fixtures: config, a fake in-memory AWS backend and provider.

Nothing here talks to AWS. A fake backend stands in for boto3 clients
behind the *real* Context machinery (TTL cache, limiter, budget, error
log, redaction, link resolution). Tests therefore exercise the
production call path end to end, and only the network is simulated.

Fake service layout (regional service dir ``fake``)::

    fake/widgets/<Id>/      id-keyed; derived, lazy and whole-redacted
                            files; inline tags; link to a gadget
    fake/gadgets/<Name>/    display-named (collision rule applies);
                            referenced-by from widgets
"""

from __future__ import annotations

import base64
import threading
import types
from collections.abc import Callable, Iterator, Mapping
from typing import Any

import pytest
from botocore.exceptions import ClientError

from awsmount.config import Config
from awsmount.providers import ProviderRegistry
from awsmount.providers.base import (
    CollectionRef,
    CollectionSpec,
    FileSpec,
    LinkSpec,
    ListCtx,
    RefSource,
    ResourceCtx,
    ServiceSpec,
    TagSpec,
)
from awsmount.session.accounts import AccountInfo
from awsmount.session.context import Context, Scope
from awsmount.tree.root import build_vfs
from awsmount.vfs.node import Content, DirNode, FileNode, Node, SymlinkNode
from awsmount.vfs.resolver import VFS

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"
STARTED_AT = 1_700_000_000.0
USER_DATA = b"#!/bin/sh\necho hello\n"
BASE = f"/{ACCOUNT_ID}/{REGION}/fake"
BOOTSTRAP_SERVICES = frozenset({"sts", "iam"})

WIDGETS_REF = CollectionRef("region", "fake", "widgets")
GADGETS_REF = CollectionRef("region", "fake", "gadgets")

Handler = Callable[..., Any]
TreeSpec = Mapping[str, Any]


# ---------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------


class FakeClock:
    """Manually advanced clock usable as ``clock``/``wallclock``."""

    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        """Move the clock forward by ``seconds``."""
        self.now += seconds


def client_error(code: str, op: str = "Operation",
                 message: str = "simulated failure") -> ClientError:
    """Build a botocore ``ClientError`` with the given error code."""
    return ClientError(
        {"Error": {"Code": code, "Message": message},
         "ResponseMetadata": {"HTTPStatusCode": 400}}, op)


def failing(code: str, op: str = "Operation") -> Handler:
    """Handler raising a fresh ``ClientError(code)`` on every call."""

    def handler(**_params: Any) -> Any:
        raise client_error(code, op)

    return handler


def _pages_of(items: list[dict[str, Any]], key: str,
              size: int) -> list[dict[str, Any]]:
    meta = {"RequestId": "req", "HTTPStatusCode": 200}
    if not items:
        return [{key: [], "ResponseMetadata": dict(meta)}]
    return [{key: items[i:i + size], "ResponseMetadata": dict(meta)}
            for i in range(0, len(items), size)]


def default_widgets() -> list[dict[str, Any]]:
    """Seed widgets: w-1 has secrets and tags, w-3 links nowhere."""
    return [
        {"Id": "w-1", "GadgetId": "g-1", "Color": "red",
         "Environment": {"Variables": {"DB_PASSWORD": "hunter2",
                                       "MODE": "prod"}},
         "Tags": [{"Key": "Name", "Value": "first"},
                  {"Key": "ApiToken", "Value": "tag-value-kept"},
                  {"Key": "team/owner", "Value": "ops"}]},
        {"Id": "w-2", "GadgetId": "g-2", "Color": "blue", "Tags": []},
        {"Id": "w-3", "GadgetId": "g-9", "Color": "green"},
    ]


def default_gadgets() -> list[dict[str, Any]]:
    """Seed gadgets: ``alpha``/``Alpha`` collide case-insensitively."""
    return [
        {"GadgetId": "g-1", "Name": "alpha"},
        {"GadgetId": "g-2", "Name": "beta"},
        {"GadgetId": "g-3", "Name": "Alpha"},
    ]


# ---------------------------------------------------------------------
# fake AWS backend
# ---------------------------------------------------------------------


class FakeBackend:
    """In-memory AWS stand-in; records every call and every page.

    Like the real read-only guard, each call (and each page of a
    paginated call) is charged to the budget *before* it is "sent".
    """

    def __init__(self) -> None:
        self.budget: Any = None
        self.page_size = 100
        self.widgets: list[dict[str, Any]] = default_widgets()
        self.gadgets: list[dict[str, Any]] = default_gadgets()
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self._lock = threading.Lock()
        self._handlers: dict[tuple[str, str], Handler] = {}
        self._pagers: dict[tuple[str, str], Handler] = {}
        self._seed()

    def _seed(self) -> None:
        self.on("sts", "get_caller_identity", self._identity)
        self.on("iam", "list_account_aliases",
                lambda **_p: {"AccountAliases": [], "IsTruncated": False,
                              "ResponseMetadata": {"RequestId": "a"}})
        self.on_pages("fake", "list_widgets",
                      lambda **_p: _pages_of(self.widgets, "Widgets",
                                             self.page_size))
        self.on_pages("fake", "list_gadgets",
                      lambda **_p: _pages_of(self.gadgets, "Gadgets",
                                             self.page_size))
        self.on("fake", "get_widget_details", self._details)
        self.on("fake", "get_widget_user_data", self._user_data)

    @staticmethod
    def _identity(**_params: Any) -> dict[str, Any]:
        return {"UserId": "AIDAFAKE", "Account": ACCOUNT_ID,
                "Arn": f"arn:aws:iam::{ACCOUNT_ID}:user/tester",
                "ResponseMetadata": {"RequestId": "id",
                                     "HTTPStatusCode": 200}}

    @staticmethod
    def _details(**params: Any) -> dict[str, Any]:
        return {"Id": params.get("Id"), "Size": 3, "Owner": "team",
                "ResponseMetadata": {"RequestId": "d"}}

    @staticmethod
    def _user_data(**params: Any) -> dict[str, Any]:
        encoded = base64.b64encode(USER_DATA).decode("ascii")
        return {"Id": params.get("Id"), "UserData": {"Value": encoded},
                "ResponseMetadata": {"RequestId": "u"}}

    def on(self, service: str, op: str, handler: Handler) -> None:
        """Register (or replace) a plain call handler."""
        self._handlers[(service, op)] = handler

    def on_pages(self, service: str, op: str, handler: Handler) -> None:
        """Register (or replace) a handler returning a list of pages."""
        self._pagers[(service, op)] = handler

    def handler(self, service: str, op: str) -> Handler | None:
        """Plain handler for ``service.op`` (None if unknown)."""
        return self._handlers.get((service, op))

    def pager(self, service: str, op: str) -> Handler | None:
        """Page handler for ``service.op`` (None if not pageable)."""
        return self._pagers.get((service, op))

    def record(self, service: str, op: str,
               params: Mapping[str, Any]) -> None:
        """Charge the budget, then log the call as sent."""
        if self.budget is not None:
            self.budget.charge(f"{service}:{op}")
        with self._lock:
            self.calls.append((service, op, dict(params)))

    def count(self, service: str | None = None,
              op: str | None = None) -> int:
        """Number of calls/pages matching ``service`` and ``op``."""
        with self._lock:
            return sum(1 for s, o, _p in self.calls
                       if (service is None or s == service)
                       and (op is None or o == op))

    def api_calls(self) -> int:
        """Calls excluding per-profile identity bootstrap (sts/iam)."""
        with self._lock:
            return sum(1 for s, _o, _p in self.calls
                       if s not in BOOTSTRAP_SERVICES)


class FakePaginator:
    """Paginator returning the backend's pages one by one."""

    def __init__(self, backend: FakeBackend, service: str,
                 op: str) -> None:
        self._backend = backend
        self._service = service
        self._op = op

    def paginate(self, **params: Any) -> Iterator[dict[str, Any]]:
        """Yield pages, charging one budget unit per page."""
        pager = self._backend.pager(self._service, self._op)
        if pager is None:
            raise AttributeError(
                f"{self._service}.{self._op} is not pageable")
        for page in pager(**params):
            self._backend.record(self._service, self._op, params)
            yield page


class FakeClient:
    """Duck-typed boto3 client backed by :class:`FakeBackend`."""

    def __init__(self, backend: FakeBackend, service: str) -> None:
        self._backend = backend
        self._service = service

    def __getattr__(self, op: str) -> Callable[..., Any]:
        if op.startswith("_"):
            raise AttributeError(op)
        handler = self._backend.handler(self._service, op)
        if handler is None:
            raise AttributeError(f"{self._service} has no operation {op}")
        backend, service = self._backend, self._service

        def method(**params: Any) -> Any:
            backend.record(service, op, params)
            return handler(**params)

        return method

    def get_paginator(self, op: str) -> FakePaginator:
        """Return a paginator for ``op``."""
        return FakePaginator(self._backend, self._service, op)


class FakeSession:
    """Stand-in for ``boto3.Session`` (only ``region_name`` is used)."""

    def __init__(self, region_name: str | None) -> None:
        self.region_name = region_name


class FakeClients:
    """Replacement for ``ClientFactory`` producing fake clients."""

    def __init__(self, backend: FakeBackend,
                 region: str | None = REGION) -> None:
        self._backend = backend
        self._region = region

    def session(self, profile: str | None) -> FakeSession:
        """Session for ``profile``."""
        return FakeSession(self._region)

    def get(self, profile: str | None, region: str,
            service: str) -> FakeClient:
        """Client for ``(profile, region, service)``."""
        return FakeClient(self._backend, service)


# ---------------------------------------------------------------------
# fake provider
# ---------------------------------------------------------------------


def _list_widgets(lc: ListCtx) -> list[dict[str, Any]]:
    return lc.paginate("list_widgets", "Widgets")


def _list_gadgets(lc: ListCtx) -> list[dict[str, Any]]:
    return lc.paginate("list_gadgets", "Gadgets")


def _widget_arn(item: dict[str, Any], scope: Scope) -> str:
    return (f"arn:{scope.partition}:fake:{scope.region}:"
            f"{scope.account.account_id}:widget/{item['Id']}")


def _details(rc: ResourceCtx) -> Content:
    return rc.call("get_widget_details", Id=rc.key)


def _user_data(rc: ResourceCtx) -> Content:
    resp = rc.call("get_widget_user_data", Id=rc.key)
    raw = (resp.get("UserData") or {}).get("Value")
    if not raw:
        return ""
    return base64.b64decode(raw)


def _gadget_of(item: dict[str, Any]) -> list[str]:
    gadget = item.get("GadgetId")
    return [gadget] if gadget else []


WIDGETS = CollectionSpec(
    name="widgets",
    client="fake",
    lister=_list_widgets,
    key=lambda i: str(i["Id"]),
    ops=frozenset({"ListWidgets", "GetWidgetDetails",
                   "GetWidgetUserData"}),
    arn=_widget_arn,
    redact="lambda",
    tags=TagSpec(inline="Tags", style="list"),
    files=(
        FileSpec("color", lambda rc: rc.item.get("Color", "")),
        FileSpec("details.json", _details, lazy=True),
        FileSpec("user-data", _user_data, lazy=True, whole="user-data"),
    ),
    links=(
        LinkSpec("gadget", GADGETS_REF,
                 lambda rc: rc.item.get("GadgetId")),
    ),
)

GADGETS = CollectionSpec(
    name="gadgets",
    client="fake",
    lister=_list_gadgets,
    key=lambda i: str(i["GadgetId"]),
    ops=frozenset({"ListGadgets"}),
    display=lambda i: str(i.get("Name") or ""),
    name_of=lambda i: i.get("Name"),
    tags=TagSpec.none(),
    referenced_by=(RefSource(WIDGETS_REF, _gadget_of),),
)

FAKE_SERVICE = ServiceSpec("fake", "region", (GADGETS, WIDGETS))


def build_context(config: Config, backend: FakeBackend) -> Context:
    """Real ``Context.from_config`` wiring with fake clients/provider."""
    ctx = Context.from_config(config)
    ctx.clients = FakeClients(backend)  # type: ignore[assignment]
    ctx.registry = ProviderRegistry((FAKE_SERVICE,))
    ctx.started_at = STARTED_AT
    backend.budget = ctx.budget
    return ctx


def fake_account(account_id: str = ACCOUNT_ID) -> AccountInfo:
    """A resolved account as AccountDirectory would produce it."""
    return AccountInfo(
        profile=None, account_id=account_id, aliases=(), partition="aws",
        dirname=account_id, regions=(REGION,), global_region=REGION,
        identity={"Account": account_id}, error=None)


# ---------------------------------------------------------------------
# hand-built trees
# ---------------------------------------------------------------------


def _const(value: Content) -> Callable[[], Content]:
    def render() -> Content:
        return value
    return render


def tree_loader(ctx: Context, spec: TreeSpec
                ) -> Callable[[DirNode], list[Node]]:
    """Loader building nodes from a nested spec.

    dict -> directory; str/bytes -> derived file; ``("json", obj)`` ->
    JSON file; ``("link", target)`` -> symlink; ``("lazy", fn)`` -> lazy
    file; ``("dirfn", loader)`` -> directory with a custom loader.
    """

    def load(node: DirNode) -> list[Node]:
        return [_make_node(ctx, node, name, value)
                for name, value in spec.items()]

    return load


def _make_node(ctx: Context, parent: DirNode, name: str,
               value: Any) -> Node:
    if isinstance(value, Mapping):
        return DirNode(name, parent, ctx, tree_loader(ctx, value))
    if isinstance(value, (str, bytes)):
        return FileNode(name, parent, ctx, _const(value), lazy=False)
    kind, payload = value
    if kind == "link":
        return SymlinkNode(name, parent, ctx, payload)
    if kind == "json":
        return FileNode(name, parent, ctx, _const(payload), lazy=False)
    if kind == "lazy":
        return FileNode(name, parent, ctx, payload, lazy=True)
    if kind == "dirfn":
        return DirNode(name, parent, ctx, payload)
    raise ValueError(f"unknown tree entry kind {kind!r}")


# ---------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------


@pytest.fixture
def fake() -> types.SimpleNamespace:
    """Constants of the fake account."""
    return types.SimpleNamespace(
        account_id=ACCOUNT_ID, region=REGION, base=BASE,
        user_data=USER_DATA, started_at=STARTED_AT,
        widgets_ref=WIDGETS_REF, gadgets_ref=GADGETS_REF)


@pytest.fixture
def clock() -> FakeClock:
    """A manual clock starting at t=1000."""
    return FakeClock()


@pytest.fixture
def config() -> Config:
    """Default configuration pinned to one region."""
    return Config(regions=(REGION,))


@pytest.fixture
def backend() -> FakeBackend:
    """A freshly seeded fake AWS backend."""
    return FakeBackend()


@pytest.fixture
def ctx(config: Config, backend: FakeBackend) -> Context:
    """Context wired to the fake backend and the fake provider."""
    return build_context(config, backend)


@pytest.fixture
def make_ctx(backend: FakeBackend) -> Callable[..., Context]:
    """Factory: ``make_ctx(**config_overrides)`` on the shared backend."""

    def factory(**overrides: Any) -> Context:
        overrides.setdefault("regions", (REGION,))
        return build_context(Config(**overrides), backend)

    return factory


@pytest.fixture
def vfs(ctx: Context) -> VFS:
    """The full lazy tree over the fake account."""
    return build_vfs(ctx)


@pytest.fixture
def account() -> AccountInfo:
    """The fake account as an AccountInfo."""
    return fake_account()


@pytest.fixture
def scope(account: AccountInfo) -> Scope:
    """Regional scope of the fake account."""
    return Scope(account, REGION, False)


@pytest.fixture
def make_tree(ctx: Context) -> Callable[..., VFS]:
    """Factory: ``make_tree(spec, context=None)`` -> VFS (static root)."""

    def factory(spec: TreeSpec, context: Context | None = None) -> VFS:
        use = context if context is not None else ctx
        root = DirNode("", None, use, tree_loader(use, spec), static=True)
        return VFS(root)

    return factory


@pytest.fixture
def aws_error() -> Callable[..., ClientError]:
    """Factory building botocore ClientErrors."""
    return client_error


@pytest.fixture
def fail_with() -> Callable[..., Handler]:
    """Factory building backend handlers that raise ClientErrors."""
    return failing
