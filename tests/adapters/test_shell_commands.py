"""Shell command tests (ARCHITECTURE: Shell).

Structural behaviour (ls, cd, cat, head, tree, find, grep, stat, get)
is checked with exact outputs on a hand-built tree. AWS-shaped
behaviour (lazy files, redaction, links, referenced-by, refresh, cache,
budget, AccessDenied) is checked on the fake account from ``conftest``,
which runs the real Context machinery over a simulated backend.
"""

from __future__ import annotations

import errno
import io
import json
import os
from collections.abc import Callable
from typing import Any

import pytest

from awsmount.adapters.shell.commands import (
    COMMANDS,
    STATUS_NOT_FOUND,
    STATUS_PARTIAL,
    STATUS_USAGE,
    Shell,
)
from awsmount.errors import PermissionDenied
from awsmount.session.context import Context
from awsmount.session.redact import REDACTED
from awsmount.tree.root import build_vfs
from awsmount.vfs.resolver import VFS
from awsmount.vfs.stat import inode_for

ENOENT = os.strerror(errno.ENOENT)
ENOTDIR = os.strerror(errno.ENOTDIR)
EISDIR = os.strerror(errno.EISDIR)
ELOOP = os.strerror(errno.ELOOP)
EACCES = os.strerror(errno.EACCES)
EIO = os.strerror(errno.EIO)

DOC: dict[str, Any] = {
    "name": "web",
    "ports": [80, 443],
    "nested": {"k": "v"},
    "items": [{"id": 1}, {"id": 2}],
    "empty": None,
}
LINES = "".join(f"line {i}\n" for i in range(1, 21))
A_TXT = "alpha\nbeta\nGamma\n"
ROOT_LISTING = "docs\nempty\nesc\nlines.txt\nlinks\n"
DOCS_LISTING = "a.txt\nb.json\nbin.dat\nsub\nwith space\n"

TREE: dict[str, Any] = {
    "docs": {
        "a.txt": A_TXT,
        "b.json": ("json", DOC),
        "bin.dat": b"\x00\x01match\x00",
        "sub": {"deep.txt": "deep alpha\n"},
        "with space": "spaced out\n",
    },
    "empty": {},
    "esc": {"%2Ehidden": "hidden\n", "team%2Fowner": "ops\n"},
    "lines.txt": LINES,
    "links": {
        "dangling": ("link", "../nope"),
        "loop": ("link", "loop"),
        "to-a": ("link", "../docs/a.txt"),
        "to-docs": ("link", "../docs"),
    },
}


class Run:
    """Run shell lines and capture ``(status, stdout, stderr)``."""

    def __init__(self, vfs: VFS, ctx: Context, *, cwd: str = "/",
                 color: bool = False) -> None:
        self.sh = Shell(vfs, ctx, out=io.BytesIO(), err=io.StringIO(),
                        color=color, cwd=cwd)

    def raw(self, line: str) -> tuple[int, bytes, str]:
        """Run ``line``; stdout as bytes."""
        out = io.BytesIO()
        err = io.StringIO()
        self.sh.out = out
        self.sh.err = err
        status = self.sh.run_line(line)
        return status, out.getvalue(), err.getvalue()

    def __call__(self, line: str) -> tuple[int, str, str]:
        status, out, err = self.raw(line)
        return status, out.decode("utf-8", "replace"), err


def _denied() -> Any:
    raise PermissionDenied("simulated AccessDenied")


@pytest.fixture
def run(make_tree: Callable[..., VFS], ctx: Context) -> Run:
    """Shell over the hand-built tree, cwd ``/``."""
    return Run(make_tree(TREE), ctx)


@pytest.fixture
def acct(vfs: VFS, ctx: Context) -> Run:
    """Shell over the fake account tree."""
    return Run(vfs, ctx)


# -- ls ------------------------------------------------------------------


def test_ls_root_sorted(run: Run) -> None:
    """Entries are sorted, one per line when not on a tty."""
    assert run("ls /") == (0, ROOT_LISTING, "")


def test_ls_defaults_to_cwd(make_tree: Callable[..., VFS],
                            ctx: Context) -> None:
    """``ls`` without operands lists the logical cwd."""
    r = Run(make_tree(TREE), ctx, cwd="/docs/sub")
    assert r("ls") == (0, "deep.txt\n", "")


def test_ls_file_operand_prints_given_path(run: Run) -> None:
    """A file operand is echoed as given."""
    assert run("ls /docs/a.txt") == (0, "/docs/a.txt\n", "")


def test_ls_missing_path(run: Run) -> None:
    """Missing paths report ENOENT and exit 1."""
    assert run("ls /nope") == (
        1, "", f"ls: cannot access '/nope': {ENOENT}\n")


def test_ls_all_adds_dot_entries(run: Run) -> None:
    """``-a`` prepends ``.`` and ``..``."""
    assert run("ls -a /docs/sub") == (0, ".\n..\ndeep.txt\n", "")


def test_ls_recursive_exact(run: Run) -> None:
    """``-R`` prints headers and recurses into subdirectories."""
    assert run("ls -R /docs") == (
        0, "/docs:\n" + DOCS_LISTING + "\n/docs/sub:\ndeep.txt\n", "")


def test_ls_recursive_does_not_follow_links(run: Run) -> None:
    """``-R`` never descends through symlinked directories."""
    assert run("ls -R /links") == (
        0, "/links:\ndangling\nloop\nto-a\nto-docs\n", "")


def test_ls_multiple_directories(run: Run) -> None:
    """Several operands get headers separated by blank lines."""
    assert run("ls /docs/sub /empty") == (
        0, "/docs/sub:\ndeep.txt\n\n/empty:\n", "")


def test_ls_file_then_directory(run: Run) -> None:
    """Files are listed first, then directories with headers."""
    assert run("ls /lines.txt /empty") == (
        0, "/lines.txt\n\n/empty:\n", "")


def test_ls_short_follows_symlinked_dir(run: Run) -> None:
    """Short ``ls`` follows a link operand to its directory."""
    assert run("ls /links/to-docs") == (0, DOCS_LISTING, "")


def test_ls_long_does_not_follow_operand(run: Run) -> None:
    """``ls -l`` shows the link itself, with its target."""
    status, out, err = run("ls -l /links/to-docs")
    assert (status, err) == (0, "")
    assert out.startswith("lrwxrwxrwx ")
    assert out.endswith(" /links/to-docs -> ../docs\n")


def test_ls_long_file_row(run: Run) -> None:
    """``ls -l`` reports mode, nlink=1 and the rendered size."""
    status, out, _ = run("ls -l /docs/a.txt")
    assert status == 0
    fields = out.split()
    assert fields[0] == "-r--r--r--"
    assert fields[1] == "1"
    assert fields[4] == str(len(A_TXT))
    assert out.endswith(" /docs/a.txt\n")


def test_ls_long_links_show_targets(run: Run) -> None:
    """Link rows carry ``-> target`` and size = len(target)."""
    status, out, _ = run("ls -l /links")
    assert status == 0
    lines = out.splitlines()
    assert [line.split()[0] for line in lines] == ["lrwxrwxrwx"] * 4
    assert [line.split()[4] for line in lines] == ["7", "4", "13", "7"]
    assert lines[0].endswith(" dangling -> ../nope")
    assert lines[1].endswith(" loop -> loop")
    assert lines[2].endswith(" to-a -> ../docs/a.txt")
    assert lines[3].endswith(" to-docs -> ../docs")


def test_ls_long_directory_row(run: Run) -> None:
    """Directories are ``dr-xr-xr-x``."""
    status, out, _ = run("ls -l /docs")
    assert status == 0
    rows = {line.split()[-1]: line for line in out.splitlines()}
    assert rows["sub"].startswith("dr-xr-xr-x ")


def test_ls_dangling_and_looping_links(run: Run) -> None:
    """Following a dangling link is ENOENT; a loop is ELOOP."""
    assert run("ls /links/dangling") == (
        1, "", f"ls: cannot access '/links/dangling': {ENOENT}\n")
    assert run("ls /links/loop") == (
        1, "", f"ls: cannot access '/links/loop': {ELOOP}\n")


def test_ls_bad_option_is_usage_error(run: Run) -> None:
    """Unknown options give status 2 and the synopsis."""
    status, out, err = run("ls -z /")
    assert (status, out) == (STATUS_USAGE, "")
    assert "usage: ls [-l] [-a] [-R] [PATH...]" in err


# -- cd / pwd --------------------------------------------------------------


def test_cd_and_pwd(run: Run) -> None:
    """``cd`` changes the logical cwd; no argument goes to ``/``."""
    assert run("cd /docs/sub") == (0, "", "")
    assert run("pwd") == (0, "/docs/sub\n", "")
    assert run("cd ..") == (0, "", "")
    assert run("pwd") == (0, "/docs\n", "")
    assert run("cd") == (0, "", "")
    assert run("pwd") == (0, "/\n", "")


def test_cd_through_symlink_is_logical(run: Run) -> None:
    """cwd keeps the link name; ``ls ..`` stays physical."""
    assert run("cd /links/to-docs") == (0, "", "")
    assert run("pwd") == (0, "/links/to-docs\n", "")
    assert run("cat a.txt") == (0, A_TXT, "")
    assert run("ls ..") == (0, ROOT_LISTING, "")
    assert run("cd ..") == (0, "", "")
    assert run("pwd") == (0, "/links\n", "")
    assert run("cd -") == (0, "/links/to-docs\n", "")
    assert run("pwd") == (0, "/links/to-docs\n", "")


def test_cd_errors_keep_cwd(run: Run) -> None:
    """Failed ``cd`` reports the errno and leaves cwd unchanged."""
    assert run("cd /docs/a.txt") == (
        1, "", f"cd: /docs/a.txt: {ENOTDIR}\n")
    assert run("cd /nope") == (1, "", f"cd: /nope: {ENOENT}\n")
    assert run("cd /links/dangling") == (
        1, "", f"cd: /links/dangling: {ENOENT}\n")
    assert run("cd /links/to-a") == (
        1, "", f"cd: /links/to-a: {ENOTDIR}\n")
    assert run("pwd") == (0, "/\n", "")
    status, _out, err = run("cd a b")
    assert status == STATUS_USAGE
    assert "too many arguments" in err


def test_pwd_rejects_arguments(run: Run) -> None:
    """``pwd x`` is a usage error."""
    assert run("pwd x")[0] == STATUS_USAGE


# -- cat / head ------------------------------------------------------------


def test_cat_file(run: Run) -> None:
    """``cat`` prints the exact bytes."""
    assert run("cat /docs/a.txt") == (0, A_TXT, "")


def test_cat_json_is_canonical(run: Run) -> None:
    """JSON files are sorted, indented and newline-terminated."""
    expected = json.dumps(DOC, indent=2, sort_keys=True,
                          ensure_ascii=False) + "\n"
    assert run("cat /docs/b.json") == (0, expected, "")


def test_cat_binary_passthrough(run: Run) -> None:
    """Binary content is written untouched."""
    assert run.raw("cat /docs/bin.dat") == (0, b"\x00\x01match\x00", "")


def test_cat_directory(run: Run) -> None:
    """Reading a directory is EISDIR."""
    assert run("cat /docs") == (1, "", f"cat: /docs: {EISDIR}\n")


def test_cat_continues_after_error(run: Run) -> None:
    """Later operands are still printed after a failure."""
    assert run("cat /docs/a.txt /nope /docs/sub/deep.txt") == (
        1, A_TXT + "deep alpha\n", f"cat: /nope: {ENOENT}\n")


def test_cat_through_links(run: Run) -> None:
    """Links to files are followed; loops are ELOOP."""
    assert run("cat /links/to-a") == (0, A_TXT, "")
    assert run("cat /links/to-docs/sub/deep.txt") == (
        0, "deep alpha\n", "")
    assert run("cat /links/loop") == (
        1, "", f"cat: /links/loop: {ELOOP}\n")


def test_cat_relative_and_quoted(make_tree: Callable[..., VFS],
                                 ctx: Context) -> None:
    """Relative paths use the cwd; quotes keep spaces."""
    r = Run(make_tree(TREE), ctx, cwd="/docs")
    assert r("cat 'with space'") == (0, "spaced out\n", "")
    assert r("cat with\\ space") == (0, "spaced out\n", "")
    assert r("cat ../lines.txt")[1] == LINES


def test_cat_usage_and_parse_errors(run: Run) -> None:
    """No operand is status 2; unbalanced quotes are status 2."""
    assert run("cat") == (
        STATUS_USAGE, "",
        "cat: missing file operand\nusage: cat PATH...\n")
    status, _out, err = run('cat "unterminated')
    assert status == STATUS_USAGE
    assert err.startswith("awsmount: parse error")


def test_head_default_ten_lines(run: Run) -> None:
    """``head`` prints ten lines by default."""
    expected = "".join(f"line {i}\n" for i in range(1, 11))
    assert run("head /lines.txt") == (0, expected, "")


def test_head_counts(run: Run) -> None:
    """``-n N`` limits the output; ``-n 0`` prints nothing."""
    assert run("head -n 3 /lines.txt") == (
        0, "line 1\nline 2\nline 3\n", "")
    assert run("head -n 0 /lines.txt") == (0, "", "")


def test_head_multiple_files_headers(run: Run) -> None:
    """Several files get ``==> name <==`` headers."""
    assert run("head -n 2 /lines.txt /docs/a.txt") == (
        0, "==> /lines.txt <==\nline 1\nline 2\n\n"
           "==> /docs/a.txt <==\nalpha\nbeta\n", "")


def test_head_usage_errors(run: Run) -> None:
    """Bad counts and missing operands are usage errors."""
    status, _out, err = run("head -n x /lines.txt")
    assert status == STATUS_USAGE
    assert "invalid number for -n" in err
    assert run("head -n -1 /lines.txt")[0] == STATUS_USAGE
    assert run("head")[0] == STATUS_USAGE


# -- tree ------------------------------------------------------------------


def test_tree_exact(run: Run) -> None:
    """Drawing, ordering and the summary line."""
    expected = (
        "/docs\n"
        "\u251c\u2500\u2500 a.txt\n"
        "\u251c\u2500\u2500 b.json\n"
        "\u251c\u2500\u2500 bin.dat\n"
        "\u251c\u2500\u2500 sub\n"
        "\u2502   \u2514\u2500\u2500 deep.txt\n"
        "\u2514\u2500\u2500 with space\n"
        "\n1 directory, 5 files\n")
    assert run("tree /docs") == (0, expected, "")


def test_tree_depth_limit(run: Run) -> None:
    """``-L 1`` stops below the first level."""
    status, out, _ = run("tree -L 1 /docs")
    assert status == 0
    assert "deep.txt" not in out
    assert out.endswith("\n1 directory, 4 files\n")


def test_tree_links_not_followed(run: Run) -> None:
    """Links are drawn with targets and counted as files."""
    expected = (
        "/links\n"
        "\u251c\u2500\u2500 dangling -> ../nope\n"
        "\u251c\u2500\u2500 loop -> loop\n"
        "\u251c\u2500\u2500 to-a -> ../docs/a.txt\n"
        "\u2514\u2500\u2500 to-docs -> ../docs\n"
        "\n0 directories, 4 files\n")
    assert run("tree /links") == (0, expected, "")


def test_tree_empty_and_relative(make_tree: Callable[..., VFS],
                                 ctx: Context) -> None:
    """Empty dirs and the default ``.`` operand."""
    r = Run(make_tree(TREE), ctx, cwd="/docs/sub")
    assert r("tree") == (
        0, ".\n\u2514\u2500\u2500 deep.txt\n\n0 directories, 1 file\n",
        "")
    assert r("tree /empty") == (
        0, "/empty\n\n0 directories, 0 files\n", "")


def test_tree_errors(run: Run) -> None:
    """Missing path is status 1; bad options are usage errors."""
    assert run("tree /nope") == (1, "", f"tree: /nope: {ENOENT}\n")
    status, _out, err = run("tree -L 0 /")
    assert status == STATUS_USAGE
    assert "-L must be >= 1" in err
    assert run("tree /docs /empty")[0] == STATUS_USAGE


# -- find ------------------------------------------------------------------


def test_find_name(run: Run) -> None:
    """``-name`` globs, pre-order and sorted."""
    assert run("find /docs -name '*.txt'") == (
        0, "/docs/a.txt\n/docs/sub/deep.txt\n", "")
    assert run("find /docs -name '*.TXT'") == (0, "", "")


def test_find_types(run: Run) -> None:
    """``-type d`` and ``-type l``; links are not followed."""
    assert run("find /docs -type d") == (0, "/docs\n/docs/sub\n", "")
    assert run("find / -type l") == (
        0, "/links/dangling\n/links/loop\n/links/to-a\n/links/to-docs\n",
        "")


def test_find_maxdepth(run: Run) -> None:
    """``-maxdepth`` limits the walk."""
    assert run("find /docs -maxdepth 1 -type f") == (
        0, "/docs/a.txt\n/docs/b.json\n/docs/bin.dat\n/docs/with space\n",
        "")
    assert run("find /docs -maxdepth 0") == (0, "/docs\n", "")


def test_find_matches_unescaped_names(run: Run) -> None:
    """Patterns apply to the unescaped name."""
    assert run("find /esc -name .hidden") == (0, "/esc/%2Ehidden\n", "")
    assert run("find /esc -name team/owner") == (
        0, "/esc/team%2Fowner\n", "")
    assert run("find /esc -name '%2E*'") == (0, "", "")


def test_find_relative_paths(make_tree: Callable[..., VFS],
                             ctx: Context) -> None:
    """Output is relative to the operand, like GNU find."""
    r = Run(make_tree(TREE), ctx, cwd="/docs")
    assert r("find . -name deep.txt") == (0, "./sub/deep.txt\n", "")
    r2 = Run(make_tree(TREE), ctx, cwd="/docs/sub")
    assert r2("find") == (0, ".\n./deep.txt\n", "")


def test_find_errors(run: Run) -> None:
    """Missing paths are status 1; bad predicates status 2."""
    assert run("find /nope") == (1, "", f"find: /nope: {ENOENT}\n")
    assert run("find / -type x")[0] == STATUS_USAGE
    assert run("find / -bogus")[0] == STATUS_USAGE
    assert run("find / -name")[0] == STATUS_USAGE


# -- grep ------------------------------------------------------------------


def test_grep_single_file(run: Run) -> None:
    """No file names for a single non-recursive file."""
    assert run("grep alpha /docs/a.txt") == (0, "alpha\n", "")
    assert run("grep -n beta /docs/a.txt") == (0, "2:beta\n", "")
    assert run("grep -i -n GAMMA /docs/a.txt") == (0, "3:Gamma\n", "")
    assert run("grep -l a /docs/a.txt") == (0, "/docs/a.txt\n", "")


def test_grep_no_match_is_status_one(run: Run) -> None:
    """No match and no error gives status 1."""
    assert run("grep zzz /docs/a.txt") == (1, "", "")


def test_grep_regex_alternation_is_not_a_pipe(run: Run) -> None:
    """A quoted ``|`` is part of the pattern."""
    assert run("grep 'alpha|beta' /docs/a.txt") == (
        0, "alpha\nbeta\n", "")


def test_grep_multiple_files_show_names(run: Run) -> None:
    """Several operands print ``name:`` prefixes."""
    assert run("grep alpha /docs/a.txt /docs/sub/deep.txt") == (
        0, "/docs/a.txt:alpha\n/docs/sub/deep.txt:deep alpha\n", "")


def test_grep_recursive(run: Run) -> None:
    """``-r``, ``-n`` and ``-l`` over a directory."""
    assert run("grep -r alpha /docs") == (
        0, "/docs/a.txt:alpha\n/docs/sub/deep.txt:deep alpha\n", "")
    assert run("grep -r -n alpha /docs") == (
        0, "/docs/a.txt:1:alpha\n/docs/sub/deep.txt:1:deep alpha\n", "")
    assert run("grep -rl alpha /docs") == (
        0, "/docs/a.txt\n/docs/sub/deep.txt\n", "")
    assert run("grep -R beta /docs/a.txt") == (
        0, "/docs/a.txt:beta\n", "")


def test_grep_binary_file_reported(run: Run) -> None:
    """Binary matches are reported without content."""
    assert run("grep -r match /docs") == (
        0, "Binary file /docs/bin.dat matches\n", "")


def test_grep_recursive_does_not_follow_links(run: Run) -> None:
    """Dangling and looping links are not even resolved."""
    assert run("grep -r alpha /links") == (1, "", "")


def test_grep_directory_without_recursion(run: Run) -> None:
    """A directory operand without ``-r`` is a partial failure."""
    assert run("grep alpha /docs") == (
        STATUS_PARTIAL, "", f"grep: /docs: {EISDIR}\n")


def test_grep_continues_after_missing_path(run: Run) -> None:
    """Errors are printed and the search goes on (status 3)."""
    assert run("grep alpha /docs/a.txt /nope") == (
        STATUS_PARTIAL, "/docs/a.txt:alpha\n",
        f"grep: /nope: {ENOENT}\n")


def test_grep_permission_denied_continues(
        make_tree: Callable[..., VFS], ctx: Context) -> None:
    """EACCES on one file is reported; other matches still print."""
    tree = {"d": {"ok.txt": "needle\n", "secret": ("lazy", _denied)}}
    r = Run(make_tree(tree), ctx)
    assert r("grep -r needle /d") == (
        STATUS_PARTIAL, "/d/ok.txt:needle\n",
        f"grep: /d/secret: {EACCES}\n")


def test_grep_relative_default_path(make_tree: Callable[..., VFS],
                                    ctx: Context) -> None:
    """``grep -r PATTERN`` searches ``.``."""
    r = Run(make_tree(TREE), ctx, cwd="/docs")
    assert r("grep -r deep") == (0, "./sub/deep.txt:deep alpha\n", "")


def test_grep_usage_errors(run: Run) -> None:
    """Bad regex, missing pattern or path are usage errors."""
    status, _out, err = run("grep '(' /docs/a.txt")
    assert status == STATUS_USAGE
    assert "invalid pattern" in err
    assert run("grep")[0] == STATUS_USAGE
    status, _out, err = run("grep alpha")
    assert status == STATUS_USAGE
    assert "missing PATH" in err


# -- stat ------------------------------------------------------------------


def test_stat_file(run: Run) -> None:
    """Type, size, mode, links and inode of a file."""
    status, out, _ = run("stat /docs/a.txt")
    assert status == 0
    lines = out.splitlines()
    assert lines[0] == "  File: /docs/a.txt"
    assert "  Type: regular file" in lines
    assert f"  Size: {len(A_TXT)}" in lines
    assert "  Mode: (0444/-r--r--r--)" in lines
    assert " Links: 1" in lines
    assert f" Inode: {inode_for('/docs/a.txt')}" in lines


def test_stat_symlink_and_directory(run: Run) -> None:
    """Links are not followed; dirs are 0555."""
    status, out, _ = run("stat /links/to-docs")
    assert status == 0
    lines = out.splitlines()
    assert lines[0] == "  File: /links/to-docs -> ../docs"
    assert "  Type: symbolic link" in lines
    assert "  Size: 7" in lines
    assert "  Mode: (0777/lrwxrwxrwx)" in lines
    status, out, _ = run("stat /docs")
    assert "  Type: directory" in out.splitlines()
    assert "  Mode: (0555/dr-xr-xr-x)" in out.splitlines()


def test_stat_errors(run: Run) -> None:
    """Missing path is status 1; no operand is status 2."""
    assert run("stat /nope") == (1, "", f"stat: /nope: {ENOENT}\n")
    assert run("stat")[0] == STATUS_USAGE


# -- get -------------------------------------------------------------------


def test_get_values(run: Run) -> None:
    """Strings raw, other values as JSON."""
    assert run("get /docs/b.json name") == (0, "web\n", "")
    assert run("get /docs/b.json ports[1]") == (0, "443\n", "")
    assert run("get /docs/b.json ports") == (
        0, "[\n  80,\n  443\n]\n", "")
    assert run("get /docs/b.json nested") == (
        0, '{\n  "k": "v"\n}\n', "")
    assert run("get /docs/b.json empty") == (0, "null\n", "")
    assert run("get /docs/b.json 'items[*].id'") == (0, "1\n2\n", "")


def test_get_whole_document(run: Run) -> None:
    """An empty expression prints the whole document."""
    expected = json.dumps(DOC, indent=2, sort_keys=True) + "\n"
    assert run('get /docs/b.json ""') == (0, expected, "")


def test_get_missing_paths(run: Run) -> None:
    """A missing plain path fails; a wildcard selecting nothing is ok."""
    assert run("get /docs/b.json nested.missing") == (
        1, "", "get: nested.missing: no such path in /docs/b.json\n")
    assert run("get /docs/b.json 'items[*].missing'") == (0, "", "")


def test_get_errors(run: Run) -> None:
    """Non-JSON files, missing files and bad expressions."""
    assert run("get /docs/a.txt x") == (
        1, "", "get: /docs/a.txt: not a JSON document\n")
    assert run("get /nope x") == (1, "", f"get: /nope: {ENOENT}\n")
    status, _out, err = run("get /docs/b.json 'a[x'")
    assert status == STATUS_USAGE
    assert "invalid expression" in err
    assert run("get /docs/b.json")[0] == STATUS_USAGE


# -- misc ------------------------------------------------------------------


def test_unknown_command(run: Run) -> None:
    """Unknown commands give 127."""
    assert run("frobnicate") == (
        STATUS_NOT_FOUND, "",
        "frobnicate: command not found (try 'help')\n")


def test_blank_and_comment_lines(run: Run) -> None:
    """Blank lines and comments do nothing."""
    assert run("") == (0, "", "")
    assert run("   ") == (0, "", "")
    assert run("# ls /") == (0, "", "")


def test_help(run: Run) -> None:
    """``help`` lists every synopsis; ``help CMD`` details one."""
    status, out, _ = run("help")
    assert status == 0
    for cmd in COMMANDS.values():
        assert cmd.synopsis in out
    assert "Pipes:" in out
    assert run("help ls") == (
        0, "usage: ls [-l] [-a] [-R] [PATH...]\n"
           "  list directory contents\n", "")
    assert run("help nope") == (1, "", "help: no such command: nope\n")


def test_exit(run: Run) -> None:
    """``exit N`` stops the session with status N."""
    assert run("exit 3") == (3, "", "")
    assert run.sh.should_exit
    assert run.sh.exit_status == 3


def test_quit_and_bad_exit(make_tree: Callable[..., VFS],
                           ctx: Context) -> None:
    """``quit`` is an alias; ``exit x`` is a usage error."""
    r = Run(make_tree(TREE), ctx)
    assert r("exit x")[0] == STATUS_USAGE
    assert not r.sh.should_exit
    assert r("quit") == (0, "", "")
    assert r.sh.should_exit


def test_colors_when_forced(make_tree: Callable[..., VFS], ctx: Context,
                            monkeypatch: pytest.MonkeyPatch) -> None:
    """Dirs bold blue, links cyan, errors red."""
    monkeypatch.delenv("NO_COLOR", raising=False)
    r = Run(make_tree(TREE), ctx, color=True)
    status, out, _ = r("ls /")
    assert status == 0
    assert "\x1b[1;34mdocs\x1b[0m" in out
    assert "lines.txt\n" in out
    assert "\x1b[36mto-docs\x1b[0m" in r("ls /links")[1]
    assert r("cat /nope")[2].startswith("\x1b[31m")


def test_no_color_env_wins(make_tree: Callable[..., VFS], ctx: Context,
                           monkeypatch: pytest.MonkeyPatch) -> None:
    """``NO_COLOR`` disables colors even when forced."""
    monkeypatch.setenv("NO_COLOR", "1")
    r = Run(make_tree(TREE), ctx, color=True)
    assert r("ls /") == (0, ROOT_LISTING, "")


# -- fake account ----------------------------------------------------------


def test_account_resource_listing_is_free(acct: Run, backend: Any,
                                          fake: Any) -> None:
    """Short ls of a resource dir renders no lazy file."""
    status, out, _ = acct(f"ls {fake.base}/widgets/w-1")
    assert status == 0
    assert out.splitlines() == [
        "arn", "color", "describe.json", "details.json", "links",
        "name", "tags", "tags.json", "user-data"]
    assert backend.count("fake", "get_widget_details") == 0
    assert backend.count("fake", "get_widget_user_data") == 0


def test_ls_long_renders_lazy_files_once(acct: Run, backend: Any,
                                         fake: Any) -> None:
    """``ls -l`` stats lazy files (one call), cached for the TTL."""
    w1 = f"{fake.base}/widgets/w-1"
    status, out, _ = acct(f"ls -l {w1}")
    assert status == 0
    assert backend.count("fake", "get_widget_details") == 1
    assert backend.count("fake", "get_widget_user_data") == 0
    rows = {line.split()[-1]: line.split() for line in out.splitlines()}
    _status, details, _err = acct.raw(f"cat {w1}/details.json")
    assert rows["details.json"][4] == str(len(details))
    assert rows["user-data"][4] == str(len(REDACTED) + 1)
    acct(f"ls -l {w1}")
    assert backend.count("fake", "get_widget_details") == 1


def test_derived_files(acct: Run, fake: Any) -> None:
    """arn, name (Name tag) and derived spec files."""
    w1 = f"{fake.base}/widgets/w-1"
    assert acct(f"cat {w1}/color") == (0, "red\n", "")
    assert acct(f"cat {w1}/name") == (0, "first\n", "")
    assert acct(f"cat {w1}/arn") == (
        0, f"arn:aws:fake:{fake.region}:{fake.account_id}:widget/w-1\n",
        "")
    assert acct(f"cat {fake.base}/widgets/w-2/name")[0] == 1


def test_collision_names(acct: Run, fake: Any) -> None:
    """Case-insensitive collisions get ``~key`` suffixes."""
    assert acct(f"ls {fake.base}/gadgets") == (
        0, "Alpha~g-3\nalpha~g-1\nbeta\n", "")


def test_links_resolve_and_omit_unknown(acct: Run, fake: Any) -> None:
    """Relative links; unresolvable targets are not emitted."""
    w1 = f"{fake.base}/widgets/w-1"
    status, out, _ = acct(f"ls -l {w1}/links")
    assert status == 0
    assert out.endswith(" gadget -> ../../../gadgets/alpha~g-1\n")
    assert acct(f"cat {w1}/links/gadget/name") == (0, "alpha\n", "")
    assert acct(f"ls {fake.base}/widgets/w-3/links") == (0, "", "")


def test_referenced_by(acct: Run, fake: Any) -> None:
    """Reverse links point back at the referencing resource."""
    gadgets = f"{fake.base}/gadgets"
    status, out, _ = acct(f"ls -l {gadgets}/alpha~g-1/referenced-by")
    assert status == 0
    assert out.endswith(" fake-widgets-w-1 -> ../../../widgets/w-1\n")
    assert acct(f"cat {gadgets}/alpha~g-1/referenced-by/"
                "fake-widgets-w-1/color") == (0, "red\n", "")
    assert acct(f"ls {gadgets}/beta/referenced-by") == (
        0, "fake-widgets-w-2\n", "")
    assert acct(f"ls {gadgets}/Alpha~g-3/referenced-by") == (0, "", "")


def test_tags_dir_and_escaping(acct: Run, fake: Any) -> None:
    """Tag keys with ``/`` are escaped; values are not redacted."""
    w1 = f"{fake.base}/widgets/w-1"
    assert acct(f"ls {w1}/tags") == (
        0, "ApiToken\nName\nteam%2Fowner\n", "")
    assert acct(f"cat {w1}/tags/team%2Fowner") == (0, "ops\n", "")
    assert acct(f"find {w1} -name team/owner") == (
        0, f"{w1}/tags/team%2Fowner\n", "")
    tags = json.loads(acct(f"cat {w1}/tags.json")[1])
    assert tags == {"ApiToken": "tag-value-kept", "Name": "first",
                    "team/owner": "ops"}


def test_describe_json_is_redacted(acct: Run, fake: Any) -> None:
    """Rule-set and generic redaction in describe.json."""
    status, out, _ = acct(f"cat {fake.base}/widgets/w-1/describe.json")
    assert status == 0
    assert "hunter2" not in out
    data = json.loads(out)
    assert data["Environment"]["Variables"] == {
        "DB_PASSWORD": REDACTED, "MODE": REDACTED}
    assert data["Color"] == "red"
    assert {"Key": "ApiToken", "Value": "tag-value-kept"} in data["Tags"]


def test_get_on_describe(acct: Run, fake: Any) -> None:
    """``get`` sees the redacted, canonical content."""
    path = f"{fake.base}/widgets/w-1/describe.json"
    # Tags are an order-insensitive list that AWS returns in unstable
    # order, so they are rendered sorted by key (stable diffs).
    assert acct(f"get {path} 'Tags[*].Key'") == (
        0, "ApiToken\nName\nteam/owner\n", "")
    assert acct(f"get {path} Environment.Variables.MODE") == (
        0, REDACTED + "\n", "")


def test_user_data_redacted_without_call(acct: Run, backend: Any,
                                         fake: Any) -> None:
    """Whole-file redaction makes no API call."""
    assert acct.raw(f"cat {fake.base}/widgets/w-1/user-data") == (
        0, (REDACTED + "\n").encode(), "")
    assert backend.count("fake", "get_widget_user_data") == 0


def test_user_data_revealed(make_ctx: Callable[..., Context],
                            backend: Any, fake: Any) -> None:
    """``--reveal`` fetches and decodes user data (one call)."""
    ctx = make_ctx(reveal=True)
    r = Run(build_vfs(ctx), ctx)
    assert r.raw(f"cat {fake.base}/widgets/w-1/user-data") == (
        0, fake.user_data, "")
    assert backend.count("fake", "get_widget_user_data") == 1


def test_grep_whole_account_does_not_leak(acct: Run, backend: Any) -> None:
    """``grep -r`` over everything never sees redacted secrets."""
    assert acct("grep -r hunter2 /") == (1, "", "")
    assert acct("grep -r -i FAKE /")[0] in (0, 1)
    assert backend.count("fake", "get_widget_user_data") == 0


def test_grep_whole_account_revealed(make_ctx: Callable[..., Context],
                                     fake: Any) -> None:
    """With ``--reveal`` the secret is findable (and only there)."""
    ctx = make_ctx(reveal=True)
    r = Run(build_vfs(ctx), ctx)
    assert r("grep -r -l hunter2 /") == (
        0, f"{fake.base}/widgets/w-1/describe.json\n", "")


def test_find_never_renders_files(acct: Run, backend: Any,
                                  fake: Any) -> None:
    """find walks names only."""
    status, out, _ = acct(f"find {fake.base} -name describe.json")
    assert status == 0
    assert len(out.splitlines()) == 6
    assert backend.count("fake", "get_widget_details") == 0


def test_grep_access_denied_is_partial(acct: Run, backend: Any,
                                       fake: Any,
                                       fail_with: Callable[..., Any]
                                       ) -> None:
    """AccessDenied on lazy files: EACCES per file, status 3."""
    backend.on("fake", "get_widget_details",
               fail_with("AccessDenied", "GetWidgetDetails"))
    status, out, err = acct(f"grep -r Owner {fake.base}/widgets")
    assert (status, out) == (STATUS_PARTIAL, "")
    lines = err.splitlines()
    for wid in ("w-1", "w-2", "w-3"):
        assert (f"grep: {fake.base}/widgets/{wid}/details.json: "
                f"{EACCES}") in lines
    assert acct(f"cat {fake.base}/widgets/w-1/color") == (0, "red\n", "")


def test_whoami(acct: Run, fake: Any) -> None:
    """identity.json of all accounts, or the one under cwd."""
    status, out, _ = acct("whoami")
    assert status == 0
    assert json.loads(out)["Account"] == fake.account_id
    assert acct(f"cd /{fake.account_id}/{fake.region}")[0] == 0
    assert json.loads(acct("whoami")[1])["Account"] == fake.account_id
    assert acct("whoami x")[0] == STATUS_USAGE


def test_refresh_path_shows_new_resources(acct: Run, backend: Any,
                                          fake: Any) -> None:
    """Listings are cached until ``refresh PATH``."""
    widgets = f"{fake.base}/widgets"
    assert acct(f"ls {widgets}") == (0, "w-1\nw-2\nw-3\n", "")
    backend.widgets.append({"Id": "w-4", "GadgetId": "g-2",
                            "Color": "pink"})
    assert acct(f"ls {widgets}") == (0, "w-1\nw-2\nw-3\n", "")
    assert backend.count("fake", "list_widgets") == 1
    status, out, _ = acct(f"refresh {widgets}")
    assert status == 0
    assert out.startswith(f"refreshed {widgets}: ")
    assert out.endswith("budget reset\n")
    assert acct(f"ls {widgets}") == (0, "w-1\nw-2\nw-3\nw-4\n", "")
    assert backend.count("fake", "list_widgets") == 2


def test_refresh_file_refetches(acct: Run, backend: Any,
                                fake: Any) -> None:
    """Refreshing a lazy file drops its cached render."""
    details = f"{fake.base}/widgets/w-1/details.json"
    first = acct(f"cat {details}")
    assert first[0] == 0
    assert acct(f"cat {details}") == first
    assert backend.count("fake", "get_widget_details") == 1
    assert acct(f"refresh {details}")[0] == 0
    assert acct(f"cat {details}") == first
    assert backend.count("fake", "get_widget_details") == 2


def test_refresh_all_resets_budget(acct: Run, ctx: Context, backend: Any,
                                   fake: Any) -> None:
    """``refresh`` drops everything and resets the budget."""
    details = f"{fake.base}/widgets/w-1/details.json"
    first = acct(f"cat {details}")
    assert ctx.budget.used() > 0
    status, out, _ = acct("refresh")
    assert status == 0
    assert out.startswith("refreshed everything: ")
    assert ctx.budget.used() == 0
    assert acct(f"cat {details}") == first
    assert backend.count("fake", "get_widget_details") == 2


def test_refresh_errors(acct: Run) -> None:
    """Missing path is status 1; two paths status 2."""
    assert acct("refresh /nope") == (1, "", f"refresh: /nope: {ENOENT}\n")
    assert acct("refresh / /")[0] == STATUS_USAGE


def test_cache_command(acct: Run, ctx: Context, backend: Any,
                       fake: Any) -> None:
    """Stats, budget usage and ``--reset-budget``."""
    assert acct(f"ls {fake.base}")[0] == 0
    used = backend.count()
    assert used == 2
    assert ctx.budget.used() == used
    status, out, _ = acct("cache")
    assert status == 0
    lines = out.splitlines()
    assert lines[0].startswith("cache: entries=")
    assert lines[1] == f"budget: {used}/unlimited calls (window 600s)"
    assert lines[2].startswith("errors: ")
    status, out, _ = acct("cache --reset-budget")
    assert status == 0
    assert out.splitlines()[0] == "budget reset"
    assert "budget: 0/unlimited calls (window 600s)" in out.splitlines()


def test_cache_clear_forces_relisting(acct: Run, backend: Any,
                                      fake: Any) -> None:
    """``cache --clear`` empties the cache and memoised listings."""
    widgets = f"{fake.base}/widgets"
    acct(f"ls {widgets}")
    status, out, _ = acct("cache --clear")
    assert status == 0
    assert out.startswith("cache cleared (")
    acct(f"ls {widgets}")
    assert backend.count("fake", "list_widgets") == 2
    assert acct("cache bogus")[0] == STATUS_USAGE


def test_cache_unlimited_budget(make_ctx: Callable[..., Context]) -> None:
    """0 limit / 0 window are shown as unlimited / session."""
    ctx = make_ctx(max_api_calls=0, budget_window=0)
    r = Run(build_vfs(ctx), ctx)
    out = r("cache")[1]
    assert "budget: 0/unlimited calls (window session)" in out


def test_budget_exhaustion_serves_cached_data(
        make_ctx: Callable[..., Context], backend: Any,
        fake: Any) -> None:
    """Past the budget: EIO, a log entry, cached paths still work."""
    ctx = make_ctx(max_api_calls=3)
    r = Run(build_vfs(ctx), ctx)
    w1 = f"{fake.base}/widgets/w-1"
    assert r(f"cat {w1}/color") == (0, "red\n", "")
    assert ctx.budget.used() == 3
    assert r(f"cat {w1}/details.json") == (
        1, "", f"cat: {w1}/details.json: {EIO}\n")
    assert r.sh.budget_hit
    assert backend.count("fake", "get_widget_details") == 0
    assert r(f"cat {w1}/color") == (0, "red\n", "")
    assert "budget" in ctx.errors.render().decode()
