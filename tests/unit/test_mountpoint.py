"""Mountpoint checks and the warnings about its parent directory."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from awsmount import platform as p


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fake home directory; ``Path.home()`` points at it."""
    root = tmp_path / "home"
    root.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: root))
    return root


def _parent(base: Path, name: str, mode: int) -> Path:
    directory = base / name
    directory.mkdir()
    os.chmod(directory, mode)
    return directory


def test_group_traversable_home_gets_no_warning(home: Path) -> None:
    """A normal home directory (0750 or 0755) is not a problem."""
    for index, mode in enumerate((0o750, 0o755)):
        parent = _parent(home, f"h{index}", mode)
        check = p.prepare_mountpoint(parent / "aws")
        assert check.warnings == []
        assert check.created


def test_parent_others_can_write_is_a_warning(home: Path) -> None:
    """Another user could replace the mountpoint."""
    parent = _parent(home, "open", 0o777)
    check = p.prepare_mountpoint(parent / "aws")
    assert len(check.warnings) == 1
    assert "can be modified by other users" in check.warnings[0]
    assert "aws" in check.warnings[0]


def test_group_writable_parent_is_a_warning(home: Path) -> None:
    """Group write is enough."""
    parent = _parent(home, "grp", 0o770)
    assert "modified" in p.prepare_mountpoint(parent / "aws").warnings[0]


def test_sticky_parent_is_not_reported_as_modifiable(
        tmp_path: Path, home: Path) -> None:
    """Like /tmp: others cannot rename what they do not own."""
    parent = _parent(tmp_path, "sticky", 0o1777)
    warnings = p.prepare_mountpoint(parent / "aws").warnings
    assert not any("modified" in w for w in warnings)


def test_traversable_parent_outside_home_is_a_warning(
        tmp_path: Path, home: Path) -> None:
    """Outside the home directory, others can reach the mountpoint."""
    parent = _parent(tmp_path, "outside", 0o755)
    warnings = p.prepare_mountpoint(parent / "aws").warnings
    assert len(warnings) == 1
    assert "traversable by other users" in warnings[0]
    assert "inside your home directory" in warnings[0]


def test_private_parent_outside_home_gets_no_warning(
        tmp_path: Path, home: Path) -> None:
    """0700 anywhere is fine."""
    parent = _parent(tmp_path, "private", 0o700)
    assert p.prepare_mountpoint(parent / "aws").warnings == []


def test_existing_mountpoint_directory_is_reused_and_not_removed(
        home: Path) -> None:
    """A directory the user created is not deleted at cleanup."""
    target = home / "aws"
    target.mkdir()
    check = p.prepare_mountpoint(target)
    assert not check.created
    p.cleanup_mountpoint(check)
    assert target.is_dir()


def test_created_mountpoint_is_private_and_removed_at_cleanup(
        home: Path) -> None:
    """A directory awsmount created is 0700 and removed again."""
    check = p.prepare_mountpoint(home / "new")
    assert check.created
    assert stat.S_IMODE((home / "new").stat().st_mode) == 0o700
    p.cleanup_mountpoint(check)
    assert not (home / "new").exists()


def test_non_empty_or_file_mountpoint_is_refused(home: Path) -> None:
    """Only an empty directory can be mounted over."""
    full = home / "full"
    full.mkdir()
    (full / "x").write_text("x")
    with pytest.raises(ValueError, match="not empty"):
        p.prepare_mountpoint(full)
    with pytest.raises(ValueError, match="not a directory"):
        p.prepare_mountpoint(full / "x")
    with pytest.raises(ValueError, match="parent does not exist"):
        p.prepare_mountpoint(home / "missing" / "aws")
