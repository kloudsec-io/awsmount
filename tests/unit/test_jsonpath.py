"""Tests for the ``get`` expression evaluator."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from awsmount.adapters.shell.jsonpath import (
    JsonPathError,
    evaluate,
    has_wildcard,
    parse,
)

DATA: dict[str, Any] = {
    "a": {"b": [{"c": 1}, {"c": 2}, {"d": 3}]},
    "list": [10, 20, 30],
    "key with.dots": "dotted",
    "nested": {"x": {"y": "deep"}, "z": {"y": "other"}},
    "nil": None,
    "flag": False,
    "zero": {"0": "string-key"},
}


def test_parse_dotted_and_index() -> None:
    """Keys and indexes become tokens."""
    assert parse("a.b[0].c") == [("key", "a"), ("key", "b"),
                                 ("index", 0), ("key", "c")]


def test_parse_optional_dollar_and_empty() -> None:
    """A leading ``$`` is ignored; empty selects everything."""
    assert parse("$.a") == parse("a") == [("key", "a")]
    assert parse("$") == []
    assert parse("") == []
    assert parse(".a") == [("key", "a")]


def test_parse_quoted_keys() -> None:
    """Bracketed quoted keys may contain dots."""
    assert parse('["key with.dots"]') == [("key", "key with.dots")]
    assert parse("['key with.dots']") == [("key", "key with.dots")]


def test_parse_wildcards_and_negative_index() -> None:
    """``*``, ``[*]`` and negative indexes."""
    assert parse("*") == [("wild", None)]
    assert parse("[*]") == [("wild", None)]
    assert parse("a.*") == [("key", "a"), ("wild", None)]
    assert parse("[-1]") == [("index", -1)]
    assert parse("[ 2 ]") == [("index", 2)]


@pytest.mark.parametrize("expr", ["a..b", "[x]", "[1", '["abc',
                                  '["a"x', "a[1.5]"])
def test_parse_errors(expr: str) -> None:
    """Malformed expressions raise JsonPathError (a ValueError)."""
    with pytest.raises(JsonPathError):
        parse(expr)
    with pytest.raises(ValueError):
        parse(expr)


def test_has_wildcard() -> None:
    """Only wildcard steps make an expression multi-valued."""
    assert has_wildcard("a[*].c")
    assert has_wildcard("*")
    assert not has_wildcard("a.b[0]")
    assert not has_wildcard('["*"]')


def test_evaluate_basic() -> None:
    """Plain paths select one value."""
    assert evaluate(DATA, "a.b[1].c") == [2]
    assert evaluate(DATA, "list[-1]") == [30]
    assert evaluate(DATA, '["key with.dots"]') == ["dotted"]
    assert evaluate(DATA, "") == [DATA]


def test_evaluate_wildcards() -> None:
    """Wildcards fan out over list items and dict values."""
    assert evaluate(DATA, "a.b[*].c") == [1, 2]
    assert evaluate(DATA, "list[*]") == [10, 20, 30]
    assert evaluate(DATA, "nested.*.y") == ["deep", "other"]
    assert evaluate(DATA, "a.b.*.d") == [3]
    assert evaluate({"m": [[1, 2], [3]]}, "m[*][*]") == [1, 2, 3]


def test_evaluate_missing_paths_are_empty() -> None:
    """Misses yield [] rather than raising."""
    assert evaluate(DATA, "nope") == []
    assert evaluate(DATA, "list[3]") == []
    assert evaluate(DATA, "list[-4]") == []
    assert evaluate(DATA, "a[0]") == []
    assert evaluate(DATA, "list.x") == []
    assert evaluate(DATA, "flag.*") == []
    assert evaluate(DATA, "a.b[*].missing") == []


def test_evaluate_falsy_values_are_selected() -> None:
    """None and False are real values."""
    assert evaluate(DATA, "nil") == [None]
    assert evaluate(DATA, "flag") == [False]


def test_numeric_dotted_key_is_a_key() -> None:
    """``a.0`` is a dict key, never a list index."""
    assert evaluate(DATA, "zero.0") == ["string-key"]
    assert evaluate({"l": ["x"]}, "l.0") == []
    assert evaluate({"l": ["x"]}, "l[0]") == ["x"]


def test_evaluate_does_not_mutate() -> None:
    """The input document is left untouched."""
    before = copy.deepcopy(DATA)
    evaluate(DATA, "a.b[*].c")
    evaluate(DATA, "*")
    assert DATA == before


def test_evaluate_on_scalars_and_lists() -> None:
    """Top-level lists and scalars work too."""
    assert evaluate([1, 2], "[0]") == [1]
    assert evaluate("text", "") == ["text"]
    assert evaluate("text", "a") == []
