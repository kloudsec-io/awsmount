"""Registry and spec validation (ARCHITECTURE: Providers).

The collection enumeration and target validation used here are derived
from ``ALL`` inside the test, rather than from registry methods, so
the check does not depend on the code it validates.
"""

from __future__ import annotations

import functools
from collections.abc import Callable, Iterator
from typing import Any

import botocore.session
import pytest

from awsmount.providers import ALL, ProviderRegistry, layout_of, refs
from awsmount.providers.base import (
    CollectionRef,
    CollectionSpec,
    ListCtx,
)
from awsmount.session.clients import (
    BOOTSTRAP_OPS,
    DENIED_OPS,
    READ_PREFIXES,
)
from awsmount.session.context import Scope
from awsmount.vfs.node import DirNode, FileNode
from awsmount.vfs.path import escape_name

# Operations moto answers with "404 Not yet implemented".
# Unsupported ops classify as errors (empty content + errors.log), so
# these log lines are the documented behaviour against moto, not bugs.
MOTO_GAPS = frozenset({
    ("eks", "list_addons"),
    ("lambda", "list_function_url_configs"),
})
MOTO_GAP_MARKER = "Not yet implemented"


def _walk_specs(scope: Any, service: str, prefix: str,
                specs: tuple[CollectionSpec, ...]
                ) -> Iterator[tuple[CollectionRef, CollectionSpec]]:
    """Yield (ref, spec) for specs and nested children ("a/b")."""
    for spec in specs:
        name = f"{prefix}/{spec.name}" if prefix else spec.name
        yield CollectionRef(scope, service, name), spec
        yield from _walk_specs(scope, service, name, spec.children)


def _all_specs() -> dict[CollectionRef, CollectionSpec]:
    """Every registered collection, nested ones included."""
    out: dict[CollectionRef, CollectionSpec] = {}
    for svc in ALL:
        for ref, spec in _walk_specs(svc.scope, svc.dirname, "",
                                     svc.collections):
            out[ref] = spec
    return out


REGISTRY = ProviderRegistry()
SPECS = _all_specs()
REFS = sorted(SPECS)
IDS = [f"{r.scope}/{r.service}/{r.collection}" for r in REFS]
KNOWN_REFS = frozenset(v for v in vars(refs).values()
                       if isinstance(v, CollectionRef))
RESERVED = frozenset({"describe.json", "arn", "name", "tags.json", "tags",
                      "links", "referenced-by"})
BOTOCORE = botocore.session.get_session()


@functools.lru_cache(maxsize=None)
def operations(client: str) -> frozenset[str]:
    """Model operation names of a boto3 service."""
    return frozenset(BOTOCORE.get_service_model(client).operation_names)


def spec_of(ref: CollectionRef) -> CollectionSpec:
    """Registered spec for ``ref`` (fails the test if missing)."""
    spec = SPECS.get(ref)
    assert spec is not None, ref
    if "/" not in ref.collection:
        assert REGISTRY.collection(ref) is spec, ref
    return spec


def registered(ref: CollectionRef) -> bool:
    """True when the service of ``ref`` is part of this build."""
    return REGISTRY.service(ref.scope, ref.service) is not None


def is_moto_gap(line: str) -> bool:
    """True for an errors.log line caused by a known moto gap."""
    fields = line.split("\t")
    if len(fields) < 8:
        return False
    return ((fields[3], fields[4]) in MOTO_GAPS
            and MOTO_GAP_MARKER in fields[7])


def test_registry_has_ec2_and_vpc() -> None:
    """The slice under test is registered."""
    dirs = {(s.scope, s.dirname) for s in ALL}
    assert ("region", "ec2") in dirs
    assert ("region", "vpc") in dirs
    assert REFS, "no collections registered"


def test_service_dirnames_unique() -> None:
    """No two services share (scope, dirname)."""
    keys = [(s.scope, s.dirname) for s in ALL]
    assert len(keys) == len(set(keys))


@pytest.mark.parametrize("service", ALL, ids=[s.dirname for s in ALL])
def test_collection_names_unique(service: Any) -> None:
    """Collection names are unique within a service."""
    names = [c.name for c in service.collections]
    assert len(names) == len(set(names))
    for name in names:
        assert escape_name(name) == name


@pytest.mark.parametrize("ref", REFS, ids=IDS)
def test_client_is_a_boto3_service(ref: CollectionRef) -> None:
    """``spec.client`` names a real boto3 service."""
    assert spec_of(ref).client in BOTOCORE.get_available_services()


@pytest.mark.parametrize("ref", REFS, ids=IDS)
def test_ops_exist_in_botocore_model(ref: CollectionRef) -> None:
    """Every declared op exists in the client's service model."""
    spec = spec_of(ref)
    assert spec.ops, f"{ref}: empty ops"
    missing = sorted(spec.ops - operations(spec.client))
    assert not missing, f"{ref}: not in {spec.client} model: {missing}"


@pytest.mark.parametrize("ref", REFS, ids=IDS)
def test_ops_are_read_only(ref: CollectionRef) -> None:
    """Ops start with a read prefix and are never in DENIED_OPS."""
    for op in sorted(spec_of(ref).ops):
        assert op.startswith(READ_PREFIXES), op
        assert op not in DENIED_OPS, op
        assert "_" not in op and op[0].isupper(), op


def test_allowed_ops_is_union_of_ops() -> None:
    """The guard allow-list is exactly the union of declared ops."""
    union: set[str] = set()
    for ref in REFS:
        union |= spec_of(ref).ops
    assert REGISTRY.allowed_ops() == frozenset(union)
    assert not REGISTRY.allowed_ops() & DENIED_OPS


def test_refs_constants_unique() -> None:
    """No two refs constants point at the same collection."""
    values = [v for v in vars(refs).values()
              if isinstance(v, CollectionRef)]
    assert len(values) == len(set(values))


@pytest.mark.parametrize("ref", REFS, ids=IDS)
def test_registered_ref_scope_matches_service(ref: CollectionRef) -> None:
    """A collection's scope is its service's scope."""
    svc = REGISTRY.service(ref.scope, ref.service)
    assert svc is not None and svc.scope == ref.scope
    if "/" not in ref.collection:
        assert ref in KNOWN_REFS, f"{ref} missing from providers.refs"


@pytest.mark.parametrize("ref", REFS, ids=IDS)
def test_link_and_refsource_targets(ref: CollectionRef) -> None:
    """Targets are refs constants; registered ones must resolve."""
    spec = spec_of(ref)
    targets = [ls.target for ls in spec.links]
    targets += [src.source for src in spec.referenced_by]
    for target in targets:
        assert target in KNOWN_REFS, target
        if registered(target):
            assert REGISTRY.collection(target) is not None, target


def test_unresolved_targets_are_only_pending_providers() -> None:
    """Only targets of not-yet-registered services fail to resolve."""
    for ref in REFS:
        spec = spec_of(ref)
        targets = [ls.target for ls in spec.links]
        targets += [src.source for src in spec.referenced_by]
        for target in targets:
            if REGISTRY.collection(target) is None:
                assert not registered(target), (ref, target)


def test_summary_matches_registered_collections() -> None:
    """summary() covers every top-level registered collection."""
    rows = REGISTRY.summary()
    top = [r for r in REFS if "/" not in r.collection]
    assert len(rows) >= len(top)


@pytest.mark.parametrize("ref", REFS, ids=IDS)
def test_resource_entry_names_unique(ref: CollectionRef) -> None:
    """Files, subdirs and children never clash with each other.

    They also never clash with the fixed entries. Several single
    links may share a name only because they are mutually exclusive
    (e.g. a flow log's ``resource``); ``many`` link dirs must be
    unique.
    """
    spec = spec_of(ref)
    names = [e.name for e in spec.files] + [c.name for c in spec.children]
    assert len(names) == len(set(names)), names
    assert not set(names) & RESERVED, names
    many = [ls.name for ls in spec.links if ls.many]
    single = {ls.name for ls in spec.links if not ls.many}
    assert len(many) == len(set(many)), many
    assert not set(many) & single
    for name in names + many + sorted(single):
        assert escape_name(name) == name, name


@pytest.mark.parametrize("ref", REFS, ids=IDS)
def test_lookup_keys(ref: CollectionRef) -> None:
    """``lookup`` only supports the documented fields."""
    assert set(spec_of(ref).lookup) <= {"arn", "name"}


def test_full_tree_calls_stay_within_declared_ops(
        seed: Any, make_mount: Callable[..., Any],
        op_log: list[tuple[str, str]]) -> None:
    """Walk and read everything (with --reveal); calls ⊆ declared ops.

    Known moto gaps (operations moto answers with "Not yet
    implemented") degrade to ``null`` plus an errors.log entry, as
    designed; every other logged error fails the test.
    """
    m = make_mount(reveal=True)
    for _path, node in m.vfs.walk("/"):
        if isinstance(node, FileNode):
            node.content()
    by_client: dict[str, set[str]] = {}
    for ref in REFS:
        spec = spec_of(ref)
        by_client.setdefault(spec.client, set()).update(spec.ops)
    assert op_log, "no API call was made"
    for service, op in op_log:
        allowed = by_client.get(service, set()) | BOOTSTRAP_OPS
        assert op in allowed, f"undeclared call {service}:{op}"
    called = {op for _s, op in op_log}
    for ref in REFS:
        assert spec_of(ref).ops & called, f"{ref} never listed"
    unexpected = [line for line in
                  m.ctx.errors.render().decode().splitlines()
                  if line.strip() and not is_moto_gap(line)]
    assert unexpected == [], "\n".join(unexpected)


def test_listed_keys_unique(seed: Any,
                            make_mount: Callable[..., Any]) -> None:
    """Each lister yields unique keys; one dir per listed item."""
    m = make_mount()
    info = m.ctx.accounts.accounts()[0]
    scope = Scope(info, m.region, False)
    for ref in REFS:
        if ref.scope != "region" or "/" in ref.collection:
            continue
        spec = spec_of(ref)
        items = spec.lister(ListCtx(m.ctx, scope, spec, None))
        keys = [spec.key(i) for i in items]
        assert len(keys) == len(set(keys)), ref
        assert len(m.ls(m.path(ref.service, ref.collection))) == len(keys)


def _plain(entry: str) -> str:
    """A layout entry without its ``*``, ``?`` and ``/`` markers."""
    return entry.rstrip("*?/")


def _collection_key(parts: list[str]) -> str:
    """``service/collection[/child]`` of ``service/coll/key[/child/key]``."""
    return parts[0] + "/" + "/".join(parts[1::2])


def test_layout_matches_the_real_resource_directories(
        seed: Any, make_mount: Callable[..., Any]) -> None:
    """`awsmount services` lists what a resource directory really holds.

    A directory holding a ``describe.json`` is a resource directory. Its
    collection follows from its path (``service/coll/key``, then
    ``child/key`` for nested ones). Every entry it holds must be declared
    by ``layout_of``, and every declared entry not marked ``?`` must exist.
    """
    m = make_mount(reveal=True)
    declared = {f"{ref.service}/{ref.collection}": layout_of(ref, spec)
                for ref, spec in SPECS.items()}
    seen: set[str] = set()
    for path, node in m.vfs.walk("/"):
        parts = path.strip("/").split("/")[2:]
        if not isinstance(node, DirNode) or len(parts) < 3 \
                or len(parts) % 2 == 0 or "links" in parts \
                or "referenced-by" in parts or "tags" in parts:
            continue
        names = set(node.children())
        if "describe.json" not in names:
            continue
        lay = declared.get(_collection_key(parts))
        assert lay is not None, path
        allowed = {_plain(f) for f in lay.files}
        required = {_plain(f) for f in lay.files if "?" not in f}
        assert names <= allowed, (path, sorted(names - allowed))
        assert required <= names, (path, sorted(required - names))
        seen.add(f"{lay.service}/{lay.collection}")
    assert len(seen) > 20, sorted(seen)
