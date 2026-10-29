"""Collision-free deterministic naming (ARCHITECTURE: Names and escaping)."""

from __future__ import annotations

import random

from awsmount.vfs.path import assign_names


def _unique_casefold(names: dict[str, str]) -> bool:
    folded = [n.casefold() for n in names.values()]
    return len(folded) == len(set(folded))


def test_empty_input() -> None:
    """No items, no names."""
    assert assign_names([]) == {}


def test_unique_names_are_escaped_display() -> None:
    """A group of one keeps escape_name(display)."""
    out = assign_names([("k1", "web"), ("k2", "db/primary"),
                        ("k3", ".env")])
    assert out == {"k1": "web", "k2": "db%2Fprimary", "k3": "%2Eenv"}


def test_empty_display() -> None:
    """Empty display escapes to %00."""
    assert assign_names([("k", "")]) == {"k": "%00"}


def test_case_insensitive_collision_gets_key_suffix() -> None:
    """Casefold collisions: every member becomes d~key."""
    out = assign_names([("i-1", "Web"), ("i-2", "web"), ("i-3", "db")])
    assert out == {"i-1": "Web~i-1", "i-2": "web~i-2", "i-3": "db"}


def test_exact_duplicates_all_suffixed() -> None:
    """All members of a group are suffixed, not just the later ones."""
    out = assign_names([("a", "x"), ("b", "x"), ("c", "x")])
    assert out == {"a": "x~a", "b": "x~b", "c": "x~c"}


def test_key_in_suffix_is_escaped() -> None:
    """The ~key suffix is itself escaped."""
    out = assign_names([("arn:aws:x/1", "n"), ("arn:aws:x/2", "n")])
    assert out == {"arn:aws:x/1": "n~arn:aws:x%2F1",
                   "arn:aws:x/2": "n~arn:aws:x%2F2"}


def test_escaped_forms_compared_not_raw() -> None:
    """'a/b' and the literal 'a%2Fb' escape differently: no clash."""
    out = assign_names([("k1", "a/b"), ("k2", "a%2Fb")])
    assert out == {"k1": "a%2Fb", "k2": "a%252Fb"}


def test_unicode_casefold_collision() -> None:
    """Full casefolding: STRASSE and straße collide."""
    out = assign_names([("k1", "STRASSE"), ("k2", "straße")])
    assert out == {"k1": "STRASSE~k1", "k2": "straße~k2"}


def test_secondary_suffix_in_sorted_key_order() -> None:
    """Remaining duplicates get ~2 in sorted-key order."""
    out = assign_names([("3", "foo~1"), ("2", "foo"), ("1", "foo")])
    assert out == {"1": "foo~1", "2": "foo~2", "3": "foo~1~2"}


def test_secondary_suffix_skips_taken_names() -> None:
    """A ~N candidate already in use is skipped."""
    out = assign_names([("1", "foo"), ("2", "foo"), ("3", "foo~1"),
                        ("4", "foo~1~2")])
    assert out == {"1": "foo~1", "2": "foo~2", "3": "foo~1~3",
                   "4": "foo~1~2"}
    assert _unique_casefold(out)


def test_keys_differing_only_by_case() -> None:
    """Keys 'A' and 'a' make d~A / d~a collide again; still unique."""
    out = assign_names([("A", "x"), ("a", "x")])
    assert out["A"] == "x~A"
    assert out["a"].startswith("x~a")
    assert _unique_casefold(out)


def test_deterministic_under_shuffle() -> None:
    """Output is independent of input order."""
    items = [(f"id-{i}", name) for i, name in enumerate(
        ["web", "Web", "WEB", "db", "db~id-3", "cache", "x/y", "x%2Fy",
         ".hidden", "", "", "Straße", "STRASSE"])]
    expected = assign_names(items)
    rng = random.Random(42)
    for _ in range(25):
        shuffled = list(items)
        rng.shuffle(shuffled)
        assert assign_names(shuffled) == expected


def test_random_inputs_always_unique_and_safe() -> None:
    """Property check: unique (casefold), never hidden, no '/'."""
    rng = random.Random(1234)
    alphabet = "aAbB/.%~ ß"
    for _round in range(30):
        items = []
        for i in range(60):
            length = rng.randint(0, 4)
            display = "".join(rng.choice(alphabet) for _ in range(length))
            key = rng.choice(["k", "K", "k/", ".k"]) + str(i)
            items.append((key, display))
        out = assign_names(items)
        assert set(out) == {k for k, _ in items}
        assert _unique_casefold(out)
        for name in out.values():
            assert name
            assert "/" not in name
            assert not name.startswith(".")
