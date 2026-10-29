"""Name escaping and path normalisation (ARCHITECTURE: Names and escaping)."""

from __future__ import annotations

import hashlib

import pytest

from awsmount.vfs.path import escape_name, normpath, split, unescape_name

TRICKY = [
    "plain", "a/b", "100%", "%2F", "%25", "/", "//", "a%2Fb/c", ".",
    "..", "...", "._x", ".DS_Store", ".hidden/x", "x.", "a.b", "a..b",
    "tab\tname", "new\nline", "\x01\x1f\x7f", "café", "日本語",
    "emoji 🙂", "spaces are fine", "~tilde", "Icon\r", "-dash",
    "%%%", "%0A", "\x85c1", "trailing/", "\\back\\slash",
]


@pytest.mark.parametrize("raw, expected", [
    ("%", "%25"),
    ("a%b", "a%25b"),
    ("%2F", "%252F"),
    ("%/", "%25%2F"),
    ("/", "%2F"),
    ("a/b/c", "a%2Fb%2Fc"),
    ("\x00x", "%00x"),
    ("\x01", "%01"),
    ("\x1f", "%1F"),
    ("\x7f", "%7F"),
    ("\n", "%0A"),
    ("\t", "%09"),
    ("\r", "%0D"),
    ("\x1b[0m", "%1B[0m"),
    (".", "%2E"),
    ("..", "%2E."),
    ("...", "%2E.."),
    ("._x", "%2E_x"),
    (".DS_Store", "%2EDS_Store"),
    (".a.b", "%2Ea.b"),
    ("", "%00"),
    ("a.b", "a.b"),
    ("a..b", "a..b"),
    ("x.", "x."),
    ("café", "café"),
    ("日本", "日本"),
    ("🙂", "🙂"),
    ("a b", "a b"),
    ("~x", "~x"),
    ("\x85", "\x85"),
    ("back\\slash", "back\\slash"),
])
def test_escape_table(raw: str, expected: str) -> None:
    """Every escaping rule."""
    assert escape_name(raw) == expected


def test_hex_is_uppercase() -> None:
    """Escapes use uppercase hex digits."""
    assert escape_name("\x0a\x0b\x1e") == "%0A%0B%1E"


@pytest.mark.parametrize("raw", TRICKY)
def test_round_trip(raw: str) -> None:
    """unescape(escape(x)) == x for every non-truncated name."""
    assert unescape_name(escape_name(raw)) == raw


@pytest.mark.parametrize("raw", TRICKY + ["." * n for n in range(1, 6)])
def test_never_hidden_never_slash(raw: str) -> None:
    """No escaped name starts with '.', contains '/' or is empty."""
    out = escape_name(raw)
    assert out
    assert not out.startswith(".")
    assert "/" not in out
    assert all(ord(c) >= 0x20 and ord(c) != 0x7F for c in out)


def test_empty_round_trip() -> None:
    """The empty string escapes to %00 and back."""
    assert escape_name("") == "%00"
    assert unescape_name("%00") == ""


def test_unescape_plain_and_dot() -> None:
    """unescape_name leaves plain names alone and restores dots."""
    assert unescape_name("plain-name_1") == "plain-name_1"
    assert unescape_name("%2E.") == ".."
    assert unescape_name("%2EDS_Store") == ".DS_Store"
    assert unescape_name("a%2Fb") == "a/b"
    assert unescape_name("100%25") == "100%"


def test_exactly_255_bytes_not_truncated() -> None:
    """A 255-byte escaped name is kept whole."""
    raw = "a" * 255
    assert escape_name(raw) == raw


def _digest(raw: str) -> str:
    return hashlib.blake2b(raw.encode("utf-8"), digest_size=8).hexdigest()


def test_256_bytes_truncated_with_hash() -> None:
    """Longer names: first 200 bytes + '~' + blake2b(raw, 8)."""
    raw = "a" * 256
    out = escape_name(raw)
    assert out == "a" * 200 + "~" + _digest(raw)
    assert len(out.encode("utf-8")) <= 255


def test_escaping_counts_towards_length() -> None:
    """The 255-byte limit applies to the escaped form."""
    raw = "%" * 100
    out = escape_name(raw)
    assert out.endswith("~" + _digest(raw))
    assert len(out.encode("utf-8")) <= 255
    assert "/" not in out


def test_truncation_on_code_point_boundary_3_bytes() -> None:
    """Multi-byte chars are never split: 66 x 3-byte chars = 198 bytes."""
    raw = "€" * 100
    out = escape_name(raw)
    assert out == "€" * 66 + "~" + _digest(raw)
    out.encode("utf-8")


def test_truncation_on_code_point_boundary_4_bytes() -> None:
    """Exactly 200 bytes of 4-byte chars are kept."""
    raw = "🙂" * 64
    out = escape_name(raw)
    assert out == "🙂" * 50 + "~" + _digest(raw)


def test_truncated_names_are_distinct_and_deterministic() -> None:
    """Same prefix, different tails -> different names; stable."""
    a = escape_name("a" * 300 + "x")
    b = escape_name("a" * 300 + "y")
    assert a != b
    assert a == escape_name("a" * 300 + "x")


def test_truncated_name_keeps_leading_dot_escape() -> None:
    """Leading-dot protection survives truncation."""
    out = escape_name("." + "b" * 300)
    assert out.startswith("%2E")
    assert len(out.encode("utf-8")) <= 255


@pytest.mark.parametrize("path, expected", [
    ("/", "/"),
    ("", "/"),
    ("a/b", "/a/b"),
    ("//a///b//", "/a/b"),
    ("/a/./b/.", "/a/b"),
    ("/./.", "/"),
    ("/a/../b", "/a/../b"),
    ("/..", "/.."),
])
def test_normpath(path: str, expected: str) -> None:
    """Absolute, collapses '//' and '.', keeps '..'."""
    assert normpath(path) == expected


@pytest.mark.parametrize("path, expected", [
    ("/", []),
    ("", []),
    ("/a//b/", ["a", "b"]),
    ("a/./b", ["a", "b"]),
    ("/a/../b", ["a", "..", "b"]),
])
def test_split(path: str, expected: list[str]) -> None:
    """split() returns components; [] for the root."""
    assert split(path) == expected
