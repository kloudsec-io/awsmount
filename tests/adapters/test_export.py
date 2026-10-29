"""Export adapter tests (ARCHITECTURE: Export)."""

from __future__ import annotations

import errno
import json
import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from awsmount import __version__
from awsmount.adapters.export import (
    MARKER,
    ExportError,
    ExportReport,
    export,
)
from awsmount.errors import NotFound, PermissionDenied
from awsmount.session.context import Context
from awsmount.session.redact import REDACTED
from awsmount.tree.root import build_vfs
from awsmount.vfs.node import DirNode, FileNode, SymlinkNode
from awsmount.vfs.path import split
from awsmount.vfs.resolver import VFS

Snapshot = dict[str, tuple[str, Any]]

B_JSON = '{\n  "k": 1\n}\n'
HAND: dict[str, Any] = {
    "dir": {
        "a.txt": "a",
        "ln": ("link", "sub/b.json"),
        "loop": ("link", "loop"),
        "sub": {"b.json": ("json", {"k": 1})},
    },
}


def _denied() -> Any:
    raise PermissionDenied("simulated AccessDenied")


def fs_snapshot(root: Path) -> Snapshot:
    """Map relative path -> (kind, payload) without following links."""
    out: Snapshot = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            if rel == MARKER:
                continue
            if path.is_symlink():
                out[rel] = ("link", os.readlink(path))
            elif path.is_dir():
                out[rel] = ("dir", None)
            else:
                out[rel] = ("file", path.read_bytes())
    return out


def vfs_snapshot(vfs: VFS, src: str) -> Snapshot:
    """The same mapping computed from the VFS."""
    start = vfs.realpath(src)
    skip = len(split(start))
    out: Snapshot = {}
    for path, node in vfs.walk(start):
        if path == start:
            continue
        rel = "/".join(split(path)[skip:])
        if isinstance(node, DirNode):
            out[rel] = ("dir", None)
        elif isinstance(node, SymlinkNode):
            out[rel] = ("link", node.readlink())
        elif isinstance(node, FileNode):
            out[rel] = ("file", node.content())
    return out


def _marker(dest: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((dest / MARKER).read_text())
    return data


# -- hand-built trees ------------------------------------------------------


def test_hand_tree_counts_and_content(make_tree: Callable[..., VFS],
                                      tmp_path: Path) -> None:
    """Dirs, files and links are written exactly."""
    dest = tmp_path / "out"
    report = export(make_tree(HAND), "/dir", dest)
    assert report == ExportReport(dirs=1, files=2, links=2, errors=[])
    assert (dest / "a.txt").read_bytes() == b"a\n"
    assert (dest / "sub" / "b.json").read_text() == B_JSON
    assert os.readlink(dest / "ln") == "sub/b.json"
    assert (dest / "ln").read_text() == B_JSON
    assert os.readlink(dest / "loop") == "loop"
    marker = _marker(dest)
    assert sorted(marker) == ["reveal", "source", "time", "version"]
    assert marker["source"] == "/dir"
    assert marker["version"] == __version__
    assert marker["reveal"] is False


def test_modes(make_tree: Callable[..., VFS], tmp_path: Path) -> None:
    """Files 0644, dirs 0755."""
    dest = tmp_path / "out"
    export(make_tree(HAND), "/dir", dest)
    assert stat.S_IMODE((dest / "a.txt").stat().st_mode) == 0o644
    assert stat.S_IMODE((dest / "sub").stat().st_mode) == 0o755
    assert stat.S_IMODE((dest / "sub" / "b.json").stat().st_mode) == 0o644


def test_link_modes(make_tree: Callable[..., VFS], tmp_path: Path) -> None:
    """``skip`` omits links; ``file`` writes the target text."""
    vfs = make_tree(HAND)
    skipped = export(vfs, "/dir", tmp_path / "skip", links="skip")
    assert skipped.links == 0
    assert not os.path.lexists(tmp_path / "skip" / "ln")
    as_file = export(vfs, "/dir", tmp_path / "file", links="file")
    assert as_file.links == 2
    target = tmp_path / "file" / "ln"
    assert not target.is_symlink()
    assert target.read_text() == "sub/b.json\n"
    assert (tmp_path / "file" / "loop").read_text() == "loop\n"


def test_per_file_errors_are_reported(make_tree: Callable[..., VFS],
                                      tmp_path: Path,
                                      capsys: pytest.CaptureFixture[str]
                                      ) -> None:
    """A failing file is listed; the rest is written."""
    vfs = make_tree({"d": {"ok.txt": "fine", "bad.txt": ("lazy",
                                                         _denied)}})
    dest = tmp_path / "out"
    report = export(vfs, "/d", dest)
    message = os.strerror(errno.EACCES)
    assert report.errors == [("/d/bad.txt", message)]
    assert report.files == 1
    assert (dest / "ok.txt").read_text() == "fine\n"
    assert not (dest / "bad.txt").exists()
    assert f"export: /d/bad.txt: {message}" in capsys.readouterr().err


def test_destination_rules(make_tree: Callable[..., VFS],
                           tmp_path: Path) -> None:
    """Non-empty dest needs --force or --clean (with marker)."""
    vfs = make_tree(HAND)
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "keep.txt").write_text("mine")
    with pytest.raises(ExportError):
        export(vfs, "/dir", dest)
    with pytest.raises(ExportError):
        export(vfs, "/dir", dest, clean=True)
    assert (dest / "keep.txt").read_text() == "mine"
    export(vfs, "/dir", dest, force=True)
    assert (dest / "keep.txt").read_text() == "mine"
    assert (dest / "a.txt").exists()
    (dest / "stale.txt").write_text("old")
    export(vfs, "/dir", dest, clean=True)
    assert not (dest / "stale.txt").exists()
    assert not (dest / "keep.txt").exists()
    assert (dest / MARKER).is_file()


def test_destination_must_be_a_directory(make_tree: Callable[..., VFS],
                                         tmp_path: Path) -> None:
    """Files and symlinks are refused as destinations."""
    vfs = make_tree(HAND)
    target = tmp_path / "file"
    target.write_text("x")
    with pytest.raises(ExportError):
        export(vfs, "/dir", target)
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(ExportError):
        export(vfs, "/dir", link)
    assert list(real.iterdir()) == []


def test_missing_source_creates_nothing(make_tree: Callable[..., VFS],
                                        tmp_path: Path) -> None:
    """The source is resolved before the destination is touched."""
    dest = tmp_path / "out"
    with pytest.raises(NotFound):
        export(make_tree(HAND), "/nope", dest)
    assert not dest.exists()


def test_invalid_arguments(make_tree: Callable[..., VFS],
                           tmp_path: Path) -> None:
    """Bad link modes and job counts raise ValueError."""
    vfs = make_tree(HAND)
    with pytest.raises(ValueError):
        export(vfs, "/dir", tmp_path / "a", links="bogus")  # type: ignore
    with pytest.raises(ValueError):
        export(vfs, "/dir", tmp_path / "b", jobs=0)


# -- fake account ----------------------------------------------------------


def test_tree_equals_vfs(vfs: VFS, fake: Any, tmp_path: Path) -> None:
    """Every node is exported with identical content/targets."""
    dest = tmp_path / "out"
    report = export(vfs, fake.base, dest)
    assert report.errors == []
    expected = vfs_snapshot(vfs, fake.base)
    assert fs_snapshot(dest) == expected
    kinds = [kind for kind, _ in expected.values()]
    assert report.dirs == kinds.count("dir")
    assert report.files == kinds.count("file")
    assert report.links == kinds.count("link")
    assert _marker(dest)["source"] == fake.base


def test_exported_links_resolve_inside_export(vfs: VFS, fake: Any,
                                              tmp_path: Path) -> None:
    """Relative links work in the real filesystem."""
    dest = tmp_path / "out"
    export(vfs, fake.base, dest)
    link = dest / "widgets" / "w-1" / "links" / "gadget"
    assert os.readlink(link) == "../../../gadgets/alpha~g-1"
    assert (link / "name").read_text() == "alpha\n"
    back = dest / "gadgets" / "alpha~g-1" / "referenced-by"
    assert ((back / "fake-widgets-w-1" / "color").read_text()
            == "red\n")


def test_redaction_is_honoured(vfs: VFS, backend: Any, fake: Any,
                               tmp_path: Path) -> None:
    """Exported bytes are the served (redacted) bytes."""
    dest = tmp_path / "out"
    export(vfs, fake.base, dest)
    w1 = dest / "widgets" / "w-1"
    describe = (w1 / "describe.json").read_text()
    assert "hunter2" not in describe
    assert json.loads(describe)["Environment"]["Variables"][
        "DB_PASSWORD"] == REDACTED
    assert (w1 / "user-data").read_text() == REDACTED + "\n"
    assert backend.count("fake", "get_widget_user_data") == 0
    assert backend.count("fake", "get_widget_details") == 3


def test_reveal_export(make_ctx: Callable[..., Context], backend: Any,
                       fake: Any, tmp_path: Path) -> None:
    """With --reveal the secrets are written and the marker says so."""
    ctx = make_ctx(reveal=True)
    dest = tmp_path / "out"
    export(build_vfs(ctx), fake.base, dest)
    w1 = dest / "widgets" / "w-1"
    assert (w1 / "user-data").read_bytes() == fake.user_data
    assert "hunter2" in (w1 / "describe.json").read_text()
    assert _marker(dest)["reveal"] is True
    assert backend.count("fake", "get_widget_user_data") == 3


def test_deterministic_across_sessions(make_ctx: Callable[..., Context],
                                       fake: Any, tmp_path: Path) -> None:
    """Unchanged accounts export to identical trees."""
    one = tmp_path / "one"
    two = tmp_path / "two"
    export(build_vfs(make_ctx()), fake.base, one, jobs=1)
    export(build_vfs(make_ctx()), fake.base, two, jobs=8)
    first = fs_snapshot(one)
    assert first
    assert first == fs_snapshot(two)


def test_no_hidden_names(vfs: VFS, fake: Any, tmp_path: Path) -> None:
    """Escaping guarantees no exported name starts with a dot."""
    dest = tmp_path / "out"
    export(vfs, fake.base, dest)
    for rel in fs_snapshot(dest):
        for part in rel.split("/"):
            assert not part.startswith("."), rel
    tag = dest / "widgets" / "w-1" / "tags" / "team%2Fowner"
    assert tag.read_text() == "ops\n"


def test_single_file_source(vfs: VFS, fake: Any, tmp_path: Path) -> None:
    """A file source is written under its own name."""
    dest = tmp_path / "out"
    report = export(vfs, f"{fake.base}/widgets/w-1/color", dest)
    assert report == ExportReport(dirs=0, files=1, links=0, errors=[])
    assert (dest / "color").read_text() == "red\n"


def test_symlinked_source_uses_real_path(vfs: VFS, fake: Any,
                                         tmp_path: Path) -> None:
    """A link source exports its target directory."""
    dest = tmp_path / "out"
    report = export(vfs, f"{fake.base}/widgets/w-1/links/gadget", dest)
    assert _marker(dest)["source"] == f"{fake.base}/gadgets/alpha~g-1"
    assert (dest / "name").read_text() == "alpha\n"
    # The link points outside the exported subtree, so a real symlink
    # would dangle (or hit an unrelated host path): it is written as a
    # text file holding the target and counted as external (AWSM-013).
    link = dest / "referenced-by" / "fake-widgets-w-1"
    assert not link.is_symlink()
    assert link.read_text() == "../../../widgets/w-1\n"
    assert report.external >= 1


def test_force_never_writes_through_symlinks(vfs: VFS, fake: Any,
                                             tmp_path: Path) -> None:
    """Pre-existing symlinks in dest are replaced, not followed."""
    outside = tmp_path / "outside.txt"
    outside.write_text("precious")
    outside_marker = tmp_path / "outside-marker"
    outside_marker.write_text("precious too")
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "color").symlink_to(outside)
    (dest / MARKER).symlink_to(outside_marker)
    export(vfs, f"{fake.base}/widgets/w-1/color", dest, force=True)
    assert outside.read_text() == "precious"
    assert outside_marker.read_text() == "precious too"
    assert not (dest / "color").is_symlink()
    assert (dest / "color").read_text() == "red\n"
    assert not (dest / MARKER).is_symlink()
