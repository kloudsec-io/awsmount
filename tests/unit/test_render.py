"""Canonical serialisation (ARCHITECTURE: Nodes and rendering)."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

import pytest

from awsmount.session.context import Context, Scope
from awsmount.vfs.node import FileNode
from awsmount.vfs.render import (
    canonical_json,
    content_type_for,
    render,
    strip_metadata,
)
from awsmount.vfs.resolver import VFS


def test_sorted_keys_indent_two_newline() -> None:
    """JSON: sorted keys, indent 2, final newline."""
    out = render({"b": 1, "a": {"d": 1, "c": 2}})
    assert out == (b'{\n  "a": {\n    "c": 2,\n    "d": 1\n  },\n'
                   b'  "b": 1\n}\n')


def test_list_and_scalars() -> None:
    """Lists and JSON scalars render as JSON."""
    assert render([3, 1]) == b"[\n  3,\n  1\n]\n"
    assert render(None) == b"null\n"
    assert render(True) == b"true\n"
    assert render(5) == b"5\n"
    assert render({}) == b"{}\n"
    assert render([]) == b"[]\n"


def test_non_ascii_kept() -> None:
    """ensure_ascii=False: UTF-8 bytes, not \\u escapes."""
    assert render({"k": "café"}) == '{\n  "k": "café"\n}\n'.encode()


def test_aware_datetime_iso() -> None:
    """Aware datetimes keep their offset."""
    utc = datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert render({"t": utc}) == \
        b'{\n  "t": "2024-01-02T03:04:05+00:00"\n}\n'
    plus2 = datetime(2024, 1, 2, 3, 4, 5,
                     tzinfo=timezone(timedelta(hours=2)))
    assert b"2024-01-02T03:04:05+02:00" in render({"t": plus2})


def test_naive_datetime_is_utc() -> None:
    """Naive datetimes are treated as UTC."""
    naive = datetime(2024, 1, 2, 3, 4, 5)
    assert b'"2024-01-02T03:04:05+00:00"' in render({"t": naive})


def test_date_iso() -> None:
    """Dates render as YYYY-MM-DD."""
    assert b'"2024-01-02"' in render({"d": date(2024, 1, 2)})


def test_bytes_in_json_are_base64() -> None:
    """bytes inside JSON become base64 strings."""
    assert b'"AP8="' in render({"b": b"\x00\xff"})


@pytest.mark.parametrize("value, expected", [
    (Decimal("5"), b"5\n"),
    (Decimal("5.000"), b"5\n"),
    (Decimal("-2"), b"-2\n"),
    (Decimal("1.5"), b"1.5\n"),
])
def test_decimal(value: Decimal, expected: bytes) -> None:
    """Decimal: int if integral, else float."""
    assert render([value]) == b"[\n  " + expected.rstrip(b"\n") + \
        b"\n]\n"


def test_sets_sorted() -> None:
    """set/frozenset become sorted lists."""
    assert render({"s": {"b", "a", "c"}}) == \
        b'{\n  "s": [\n    "a",\n    "b",\n    "c"\n  ]\n}\n'
    assert b'"x",\n    "y"' in render({"s": frozenset({"y", "x"})})


def test_unserialisable_raises() -> None:
    """Unknown objects are a TypeError, not silently str()'d."""
    with pytest.raises(TypeError):
        render({"o": object()})


def test_top_level_bytes_unchanged() -> None:
    """bytes content passes through unchanged (no newline added)."""
    raw = b"\x00raw\xff"
    assert render(raw) == raw
    assert render(b"") == b""


@pytest.mark.parametrize("text, expected", [
    ("abc", b"abc\n"),
    ("abc\n", b"abc\n"),
    ("", b"\n"),
    ("a\nb", b"a\nb\n"),
    ("é", b"\xc3\xa9\n"),
])
def test_text(text: str, expected: bytes) -> None:
    """str gets one trailing newline unless it already has one."""
    assert render(text) == expected


def test_response_metadata_stripped_top_level() -> None:
    """ResponseMetadata is removed from responses."""
    out = render({"ResponseMetadata": {"RequestId": "x"}, "A": 1})
    assert out == b'{\n  "A": 1\n}\n'


def test_response_metadata_stripped_from_pages() -> None:
    """...and from each page of a paginated result."""
    pages = [{"ResponseMetadata": {}, "A": 1}, {"B": 2}]
    assert strip_metadata(pages) == [{"A": 1}, {"B": 2}]
    assert b"ResponseMetadata" not in render(pages)


def test_strip_metadata_does_not_mutate() -> None:
    """Stripping returns a new object."""
    resp = {"ResponseMetadata": {"x": 1}, "A": 1}
    strip_metadata(resp)
    assert "ResponseMetadata" in resp


def test_content_types(make_tree: Any) -> None:
    """.json -> application/json; others text/plain; charset=utf-8."""
    assert content_type_for("describe.json") == "application/json"
    assert content_type_for("arn") == "text/plain; charset=utf-8"
    assert content_type_for("json") == "text/plain; charset=utf-8"
    vfs: VFS = make_tree({"a.json": ("json", {}), "b": "x"})
    a = vfs.resolve("/a.json")
    b = vfs.resolve("/b")
    assert isinstance(a, FileNode) and isinstance(b, FileNode)
    assert a.content_type == "application/json"
    assert b.content_type == "text/plain; charset=utf-8"


def test_canonical_json_order_independent() -> None:
    """canonical_json is deterministic regardless of key order."""
    assert canonical_json({"b": 1, "a": [1, {"d": 2, "c": 3}]}) == \
        canonical_json({"a": [1, {"c": 3, "d": 2}], "b": 1})


def test_context_call_strips_metadata(ctx: Context,
                                      scope: Scope) -> None:
    """Context.call returns the response without ResponseMetadata."""
    resp = ctx.call(scope, "fake", "get_widget_details", Id="w-1")
    assert "ResponseMetadata" not in resp
    assert resp["Id"] == "w-1"


def test_context_paginate_concatenates(ctx: Context, scope: Scope,
                                       backend: Any) -> None:
    """paginate concatenates result_key across pages."""
    backend.page_size = 1
    items = ctx.paginate(scope, "fake", "list_widgets", "Widgets")
    assert [i["Id"] for i in items] == ["w-1", "w-2", "w-3"]
    assert backend.count("fake", "list_widgets") == 3
