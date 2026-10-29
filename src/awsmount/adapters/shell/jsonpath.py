"""Tiny JSON path evaluator for the shell ``get`` command.

Supported syntax: ``a.b[0].c``, ``["key with.dots"]``, ``[-1]``,
``[*]`` and ``*`` (wildcards over dict values / list items), and an
optional leading ``$``. An empty expression selects the whole document.
"""

from __future__ import annotations

from typing import Any

__all__ = ["JsonPathError", "Token", "evaluate", "has_wildcard", "parse"]

Token = tuple[str, Any]


class JsonPathError(ValueError):
    """Invalid ``get`` expression."""


def _bracket(text: str, start: int, tokens: list[Token]) -> int:
    """Parse ``[...]`` at ``start``; return the index after ``]``."""
    size = len(text)
    if start + 1 < size and text[start + 1] in "\"'":
        quote = text[start + 1]
        end = text.find(quote, start + 2)
        if end < 0 or end + 1 >= size or text[end + 1] != "]":
            raise JsonPathError("unterminated quoted key")
        tokens.append(("key", text[start + 2:end]))
        return end + 2
    end = text.find("]", start)
    if end < 0:
        raise JsonPathError("missing ']'")
    inner = text[start + 1:end].strip()
    if inner == "*":
        tokens.append(("wild", None))
        return end + 1
    try:
        tokens.append(("index", int(inner)))
    except ValueError as exc:
        raise JsonPathError(f"bad index {inner!r}") from exc
    return end + 1


def parse(expr: str) -> list[Token]:
    """Tokenise an expression into key/index/wild steps."""
    text = expr.strip()
    if text.startswith("$"):
        text = text[1:]
    tokens: list[Token] = []
    index = 0
    size = len(text)
    while index < size:
        char = text[index]
        if char == ".":
            index += 1
            if index < size and text[index] == ".":
                raise JsonPathError(f"empty key in {expr!r}")
            continue
        if char == "[":
            index = _bracket(text, index, tokens)
            continue
        end = index
        while end < size and text[end] not in ".[":
            end += 1
        name = text[index:end]
        if name == "*":
            tokens.append(("wild", None))
        else:
            tokens.append(("key", name))
        index = end
    return tokens


def has_wildcard(expr: str) -> bool:
    """True when the expression may select several values."""
    return any(kind == "wild" for kind, _ in parse(expr))


def evaluate(data: Any, expr: str) -> list[Any]:
    """Return every value selected by ``expr`` in ``data``."""
    values: list[Any] = [data]
    for kind, arg in parse(expr):
        selected: list[Any] = []
        for value in values:
            if kind == "key":
                if isinstance(value, dict) and arg in value:
                    selected.append(value[arg])
            elif kind == "index":
                if isinstance(value, list) and \
                        -len(value) <= arg < len(value):
                    selected.append(value[arg])
            elif isinstance(value, dict):
                selected.extend(value.values())
            elif isinstance(value, list):
                selected.extend(value)
        values = selected
    return values
