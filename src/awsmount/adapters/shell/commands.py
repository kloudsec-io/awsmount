"""Shell command implementations (ARCHITECTURE: Shell).

The same functions back the interactive REPL, ``awsmount shell -c`` and
the one-shot ``awsmount ls|cat|tree|find|grep|get`` commands. Commands
write bytes to :attr:`Shell.out` and diagnostics to :attr:`Shell.err`
and return an exit status: 0 ok, 1 error (or no grep match), 2 usage,
3 partial (some paths failed during grep), 127 unknown command.
"""

from __future__ import annotations

import getopt
import io
import json
import re
import shlex
import shutil
import sys
from collections.abc import Callable, Hashable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, BinaryIO, TextIO

from awsmount.adapters.shell import formatting as fmt
from awsmount.adapters.shell import jsonpath
from awsmount.adapters.shell.pipes import run_host, split_pipe
from awsmount.errors import AwsMountError, BudgetExceeded, NotADirectory
from awsmount.session.progress import clear_line
from awsmount.tree.collection import CollectionDir
from awsmount.vfs import walk as vwalk
from awsmount.vfs.node import DirNode, Node, NodeType, SymlinkNode
from awsmount.vfs.path import join, normpath, split
from awsmount.vfs.resolver import WalkErrorHandler

if TYPE_CHECKING:
    from awsmount.session.context import Context
    from awsmount.vfs.resolver import VFS

__all__ = [
    "COMMANDS",
    "Command",
    "CommandFn",
    "STATUS_ERROR",
    "STATUS_NOT_FOUND",
    "STATUS_OK",
    "STATUS_PARTIAL",
    "STATUS_USAGE",
    "Shell",
    "ShellUsageError",
    "command",
]

STATUS_OK = 0
STATUS_ERROR = 1
STATUS_USAGE = 2
STATUS_PARTIAL = 3
STATUS_NOT_FOUND = 127

CommandFn = Callable[["Shell", list[str]], int]

PIPE_HELP = (
    "Pipes: 'CMD ... | !HOST PIPELINE' feeds a builtin's output to\n"
    "/bin/sh (e.g. cat describe.json | !jq .State). A line starting\n"
    "with '!' runs a host command with AWSMOUNT_CWD exported; host\n"
    "commands cannot see the virtual filesystem. Pipes between two\n"
    "builtins are not supported.\n"
)


class ShellUsageError(Exception):
    """Bad usage of a shell command (exit status 2)."""


@dataclass(frozen=True)
class Command:
    """A registered shell command."""

    name: str
    fn: CommandFn
    synopsis: str
    summary: str


COMMANDS: dict[str, Command] = {}


def command(name: str, synopsis: str, summary: str,
            aliases: Sequence[str] = ()
            ) -> Callable[[CommandFn], CommandFn]:
    """Register a command function under ``name`` and ``aliases``."""

    def register(fn: CommandFn) -> CommandFn:
        for alias in (name, *aliases):
            COMMANDS[alias] = Command(alias, fn, synopsis, summary)
        return fn

    return register


class Shell:
    """One shell session: the VFS, a logical cwd and output streams."""

    def __init__(self, vfs: VFS, ctx: Context, *,
                 out: BinaryIO | None = None, err: TextIO | None = None,
                 color: bool | None = None, cwd: str = "/") -> None:
        self.vfs = vfs
        self.ctx = ctx
        self.out: BinaryIO = out if out is not None else sys.stdout.buffer
        self.err: TextIO = err if err is not None else sys.stderr
        self._color_setting = color
        self._capturing = 0
        self.cwd = "/"
        self.oldpwd = "/"
        self.should_exit = False
        self.exit_status = 0
        self.budget_hit = False
        if cwd != "/":
            self.cwd = self.logical(cwd)
            self.oldpwd = self.cwd

    # -- output ------------------------------------------------------

    @property
    def color(self) -> bool:
        """True when stdout output is colored (never while capturing)."""
        if self._capturing:
            return False
        return fmt.color_enabled(self._color_setting, self.out)

    @property
    def err_color(self) -> bool:
        """True when diagnostics are colored."""
        return fmt.color_enabled(self._color_setting, self.err)

    @property
    def interactive(self) -> bool:
        """True when stdout is a terminal and not being captured."""
        if self._capturing:
            return False
        isatty = getattr(self.out, "isatty", None)
        if isatty is None:
            return False
        try:
            return bool(isatty())
        except (OSError, ValueError):
            return False

    def write(self, text: str) -> None:
        """Write text to stdout (UTF-8)."""
        self.out.write(text.encode("utf-8", "surrogateescape"))

    def write_bytes(self, data: bytes) -> None:
        """Write raw bytes to stdout."""
        self.out.write(data)

    def flush(self) -> None:
        """Flush stdout, ignoring closed or broken streams."""
        try:
            self.out.flush()
        except (OSError, ValueError):
            pass

    def error(self, message: str) -> None:
        """Write one diagnostic line to stderr (red on a tty)."""
        self.flush()
        clear_line()
        self.err.write(fmt.paint(message, fmt.ERROR_COLOR, self.err_color)
                       + "\n")
        try:
            self.err.flush()
        except (OSError, ValueError):
            pass

    def note(self, exc: BaseException) -> None:
        """Remember that the API budget was exhausted."""
        if isinstance(exc, BudgetExceeded):
            self.budget_hit = True

    def report(self, cmd: str, shown: str, exc: AwsMountError) -> None:
        """Print ``cmd: shown: strerror``."""
        self.note(exc)
        self.error(f"{cmd}: {shown}: {exc.strerror}")

    # -- paths -------------------------------------------------------

    def abspath(self, path: str) -> str:
        """VFS path for a user path (relative to the logical cwd).

        ``..`` is kept so that the VFS applies physical semantics; a
        trailing slash is preserved (it forces symlink following).
        """
        if not path:
            path = "."
        base = path if path.startswith("/") else join(self.cwd, path)
        norm = normpath(base)
        if path.endswith("/") and norm != "/":
            norm += "/"
        return norm

    def logical(self, path: str) -> str:
        """Lexically normalised path (``..`` removes a component)."""
        base = path if path.startswith("/") else join(self.cwd, path)
        parts: list[str] = []
        for comp in base.split("/"):
            if comp in ("", "."):
                continue
            if comp == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(comp)
        return "/" + "/".join(parts)

    # -- execution ---------------------------------------------------

    def capture(self, argv: list[str]) -> tuple[int, bytes]:
        """Run a builtin with stdout captured; return (status, bytes)."""
        buffer = io.BytesIO()
        saved = self.out
        self.out = buffer
        self._capturing += 1
        try:
            status = self.run_argv(argv)
        finally:
            self.out = saved
            self._capturing -= 1
        return status, buffer.getvalue()

    def run_line(self, line: str) -> int:
        """Parse and run one command line (pipes and ``!`` included)."""
        text = line.strip()
        if not text or text.startswith("#"):
            return STATUS_OK
        if text.startswith("!"):
            return run_host(text[1:].strip(), cwd=self.cwd, out=self.out,
                            err=self.err)
        left, right = split_pipe(text)
        try:
            argv = shlex.split(left, posix=True)
        except ValueError as exc:
            self.error(f"awsmount: parse error: {exc}")
            return STATUS_USAGE
        if right is None:
            return self.run_argv(argv)
        pipeline = right.strip()
        if not pipeline.startswith("!"):
            self.error("awsmount: pipes between builtins are not "
                       "supported; use 'CMD | !host-command'")
            return STATUS_USAGE
        if not argv:
            self.error("awsmount: missing command before '|'")
            return STATUS_USAGE
        _status, data = self.capture(argv)
        return run_host(pipeline[1:].strip(), cwd=self.cwd, out=self.out,
                        err=self.err, stdin_data=data)

    def run_argv(self, argv: list[str]) -> int:
        """Run one builtin given as an argument vector."""
        if not argv:
            return STATUS_OK
        name, args = argv[0], argv[1:]
        cmd = COMMANDS.get(name)
        if cmd is None:
            self.error(f"{name}: command not found (try 'help')")
            return STATUS_NOT_FOUND
        try:
            return cmd.fn(self, args)
        except (ShellUsageError, getopt.GetoptError) as exc:
            message = exc.msg if isinstance(exc, getopt.GetoptError) \
                else str(exc)
            self.error(f"{name}: {message}")
            self.error(f"usage: {cmd.synopsis}")
            return STATUS_USAGE
        except AwsMountError as exc:
            self.note(exc)
            detail = exc.message or exc.strerror
            if detail == exc.strerror:
                self.error(f"{name}: {exc.strerror}")
            else:
                self.error(f"{name}: {detail}: {exc.strerror}")
            return STATUS_ERROR
        except BrokenPipeError:
            return STATUS_ERROR
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            self.error(f"{name}: internal error: {type(exc).__name__}: "
                       f"{exc}")
            return STATUS_ERROR


# -- helpers -----------------------------------------------------------


def _show(start: str, shown: str, found: str) -> str:
    """Display ``found`` relative to the user-supplied ``shown`` start."""
    start_n = normpath(start)
    found_n = normpath(found)
    if found_n == start_n:
        return shown
    if start_n == "/":
        rest = found_n[1:]
    elif found_n.startswith(start_n + "/"):
        rest = found_n[len(start_n) + 1:]
    else:
        return found_n
    if shown.endswith("/"):
        return shown + rest
    return f"{shown}/{rest}"


def _child(shown: str, name: str) -> str:
    """Join a child name onto a displayed path."""
    if shown.endswith("/"):
        return shown + name
    return f"{shown}/{name}"


def _int(value: str, option: str, minimum: int = 0) -> int:
    """Parse a non-negative option value."""
    try:
        number = int(value)
    except ValueError as exc:
        raise ShellUsageError(
            f"invalid number for {option}: {value!r}") from exc
    if number < minimum:
        raise ShellUsageError(f"{option} must be >= {minimum}")
    return number


class _ErrorSink:
    """Counts walk errors and prints them relative to the user path."""

    def __init__(self, sh: Shell, cmd: str) -> None:
        self.sh = sh
        self.cmd = cmd
        self.count = 0

    def handler(self, start: str, shown: str) -> WalkErrorHandler:
        """Error callback for a walk started at ``start``."""

        def on_error(path: str, exc: AwsMountError) -> None:
            self.count += 1
            self.sh.report(self.cmd, _show(start, shown, path), exc)

        return on_error

    def fail(self, shown: str, exc: AwsMountError) -> None:
        """Record an error outside a walk."""
        self.count += 1
        self.sh.report(self.cmd, shown, exc)


# -- ls ----------------------------------------------------------------


def _ls_entries(sh: Shell, entries: list[tuple[str, Node]],
                long_: bool) -> int:
    """Print entries in long or short format; return 1 on errors."""
    if not entries:
        return 0
    color = sh.color
    if long_:
        status = 0
        rows: list[fmt.LongEntry] = []
        for name, node in entries:
            try:
                st = node.stat()
            except AwsMountError as exc:
                sh.report("ls", f"cannot access '{name}'", exc)
                status = 1
                continue
            target = node.readlink() if isinstance(node, SymlinkNode) \
                else None
            rows.append(fmt.LongEntry(fmt.colorize(name, node.type, color),
                                      st, target))
        for line in fmt.long_lines(rows):
            sh.write(line + "\n")
        return status
    plain = [name for name, _ in entries]
    painted = [fmt.colorize(name, node.type, color)
               for name, node in entries]
    if sh.interactive:
        width = shutil.get_terminal_size((80, 24)).columns
        lines = fmt.columns(plain, painted, width)
    else:
        lines = painted
    for line in lines:
        sh.write(line + "\n")
    return 0


def _ls_dir(sh: Shell, shown: str, abs_: str, node: DirNode, long_: bool,
            all_: bool, recursive: bool, header: bool) -> int:
    """List one directory (and, with -R, its subdirectories)."""
    try:
        children = node.children()
    except AwsMountError as exc:
        sh.report("ls", f"cannot open directory '{shown}'", exc)
        return 1
    if header:
        sh.write(f"{shown}:\n")
    entries: list[tuple[str, Node]] = list(children.items())
    if all_:
        parent: Node = node.parent if node.parent is not None else node
        entries = [(".", node), ("..", parent)] + entries
    status = _ls_entries(sh, entries, long_)
    if recursive:
        base = normpath(abs_)
        for name, child in children.items():
            if isinstance(child, DirNode):
                sh.write("\n")
                status |= _ls_dir(sh, _child(shown, name),
                                  join(base, name), child, long_, all_,
                                  recursive, True)
    return status


@command("ls", "ls [-l] [-a] [-R] [PATH...]", "list directory contents")
def cmd_ls(sh: Shell, args: list[str]) -> int:
    """``ls``: list directories; -R recurses without following links."""
    opts, paths = getopt.gnu_getopt(args, "laR")
    flags = {opt for opt, _ in opts}
    long_ = "-l" in flags
    all_ = "-a" in flags
    recursive = "-R" in flags
    targets = paths or ["."]
    status = 0
    files: list[tuple[str, Node]] = []
    dirs: list[tuple[str, str, DirNode]] = []
    for path in targets:
        abs_ = sh.abspath(path)
        try:
            node = sh.vfs.resolve(abs_, follow=not long_)
        except AwsMountError as exc:
            sh.report("ls", f"cannot access '{path}'", exc)
            status = 1
            continue
        if isinstance(node, DirNode):
            dirs.append((path, abs_, node))
        else:
            files.append((path, node))
    status |= _ls_entries(sh, files, long_)
    header = len(targets) > 1 or recursive
    for index, (path, abs_, node) in enumerate(dirs):
        if files or index > 0:
            sh.write("\n")
        status |= _ls_dir(sh, path, abs_, node, long_, all_, recursive,
                          header)
    return STATUS_ERROR if status else STATUS_OK


# -- navigation --------------------------------------------------------


@command("cd", "cd [PATH|-]", "change the logical working directory")
def cmd_cd(sh: Shell, args: list[str]) -> int:
    """``cd``: logical cwd; no argument goes to ``/``."""
    if len(args) > 1:
        raise ShellUsageError("too many arguments")
    arg = args[0] if args else "/"
    target = sh.oldpwd if arg == "-" else sh.logical(arg)
    try:
        node = sh.vfs.resolve(target, follow=True)
    except AwsMountError as exc:
        sh.report("cd", arg, exc)
        return STATUS_ERROR
    if not isinstance(node, DirNode):
        sh.report("cd", arg, NotADirectory(arg))
        return STATUS_ERROR
    sh.oldpwd, sh.cwd = sh.cwd, target
    if arg == "-":
        sh.write(target + "\n")
    return STATUS_OK


@command("pwd", "pwd", "print the logical working directory")
def cmd_pwd(sh: Shell, args: list[str]) -> int:
    """``pwd``: print the logical cwd."""
    if args:
        raise ShellUsageError("too many arguments")
    sh.write(sh.cwd + "\n")
    return STATUS_OK


# -- reading -----------------------------------------------------------


@command("cat", "cat PATH...", "print file contents")
def cmd_cat(sh: Shell, args: list[str]) -> int:
    """``cat``: write file bytes to stdout."""
    if not args:
        raise ShellUsageError("missing file operand")
    status = STATUS_OK
    for path in args:
        try:
            data = sh.vfs.read(sh.abspath(path))
        except AwsMountError as exc:
            sh.report("cat", path, exc)
            status = STATUS_ERROR
            continue
        sh.write_bytes(data)
    return status


@command("head", "head [-n N] PATH...", "print the first lines of files")
def cmd_head(sh: Shell, args: list[str]) -> int:
    """``head``: first N lines (default 10)."""
    opts, paths = getopt.gnu_getopt(args, "n:")
    count = 10
    for _opt, value in opts:
        count = _int(value, "-n")
    if not paths:
        raise ShellUsageError("missing file operand")
    status = STATUS_OK
    printed = 0
    for path in paths:
        try:
            data = sh.vfs.read(sh.abspath(path))
        except AwsMountError as exc:
            sh.report("head", path, exc)
            status = STATUS_ERROR
            continue
        if len(paths) > 1:
            sh.write(("\n" if printed else "") + f"==> {path} <==\n")
        printed += 1
        lines = data.splitlines(keepends=True)[:count]
        sh.write_bytes(b"".join(lines))
    return status


@command("stat", "stat PATH...", "show type, size, mode, mtime, inode")
def cmd_stat(sh: Shell, args: list[str]) -> int:
    """``stat``: lstat semantics (links are not followed)."""
    if not args:
        raise ShellUsageError("missing operand")
    kinds = {NodeType.DIR: "directory", NodeType.FILE: "regular file",
             NodeType.LINK: "symbolic link"}
    status = STATUS_OK
    for index, path in enumerate(args):
        try:
            node = sh.vfs.resolve(sh.abspath(path), follow=False)
            st = node.stat()
        except AwsMountError as exc:
            sh.report("stat", path, exc)
            status = STATUS_ERROR
            continue
        title = f"  File: {path}"
        if isinstance(node, SymlinkNode):
            title += f" -> {node.readlink()}"
        modified = datetime.fromtimestamp(st.mtime, timezone.utc)
        lines = [
            title,
            f"  Type: {kinds[node.type]}",
            f"  Size: {st.size}",
            f"Blocks: {st.blocks}",
            f"  Mode: ({st.mode & 0o7777:04o}/{fmt.mode_string(st.mode)})",
            f" Links: {st.nlink}",
            f"   Uid: {st.uid}   Gid: {st.gid}",
            f" Inode: {st.ino}",
            f"Modify: {modified.isoformat(timespec='seconds')}",
        ]
        if index:
            sh.write("\n")
        sh.write("\n".join(lines) + "\n")
    return status


@command("get", "get PATH EXPR",
         "extract a JSON value (a.b[0].c, [*], *)")
def cmd_get(sh: Shell, args: list[str]) -> int:
    """``get``: strings printed raw, other values as JSON."""
    if len(args) != 2:
        raise ShellUsageError("expected PATH and EXPR")
    path, expr = args
    try:
        wildcard = jsonpath.has_wildcard(expr)
    except jsonpath.JsonPathError as exc:
        raise ShellUsageError(f"invalid expression: {exc}") from exc
    try:
        data = sh.vfs.read(sh.abspath(path))
    except AwsMountError as exc:
        sh.report("get", path, exc)
        return STATUS_ERROR
    try:
        doc: Any = json.loads(data.decode("utf-8", "replace"))
    except ValueError:
        sh.error(f"get: {path}: not a JSON document")
        return STATUS_ERROR
    values = jsonpath.evaluate(doc, expr)
    if not values:
        if wildcard:
            return STATUS_OK
        sh.error(f"get: {expr}: no such path in {path}")
        return STATUS_ERROR
    for value in values:
        if isinstance(value, str):
            sh.write(value + "\n")
        else:
            sh.write(json.dumps(value, indent=2, sort_keys=True,
                                ensure_ascii=False) + "\n")
    return STATUS_OK


# -- traversal ---------------------------------------------------------


@command("tree", "tree [-L N] [PATH]",
         "draw a directory tree (links not followed)")
def cmd_tree(sh: Shell, args: list[str]) -> int:
    """``tree``: pre-order drawing with a dir/file summary."""
    opts, paths = getopt.gnu_getopt(args, "L:")
    depth: int | None = None
    for _opt, value in opts:
        depth = _int(value, "-L", minimum=1)
    if len(paths) > 1:
        raise ShellUsageError("only one PATH is supported")
    shown = paths[0] if paths else "."
    abs_ = sh.abspath(shown)
    sink = _ErrorSink(sh, "tree")
    color = sh.color
    dirs = 0
    files = 0
    try:
        for entry in vwalk.tree(sh.vfs, abs_, max_depth=depth,
                                on_error=sink.handler(normpath(abs_),
                                                      shown)):
            if entry.depth == 0:
                sh.write(fmt.colorize(shown, entry.node.type, color)
                         + "\n")
                continue
            name = fmt.colorize(entry.name, entry.node.type, color)
            if isinstance(entry.node, SymlinkNode):
                name += f" -> {entry.node.readlink()}"
                files += 1
            elif isinstance(entry.node, DirNode):
                dirs += 1
            else:
                files += 1
            sh.write(fmt.tree_prefix(entry.lasts) + name + "\n")
    except AwsMountError as exc:
        sink.fail(shown, exc)
        return STATUS_ERROR
    dir_word = "directory" if dirs == 1 else "directories"
    file_word = "file" if files == 1 else "files"
    sh.write(f"\n{dirs} {dir_word}, {files} {file_word}\n")
    return STATUS_ERROR if sink.count else STATUS_OK


def _parse_find(args: list[str]
                ) -> tuple[list[str], str | None, str | None, int | None]:
    """Parse ``find`` paths and the -name/-type/-maxdepth predicates."""
    paths: list[str] = []
    name: str | None = None
    type_: str | None = None
    depth: int | None = None
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in ("-name", "-type", "-maxdepth"):
            if index + 1 >= len(args):
                raise ShellUsageError(f"missing argument to {arg}")
            value = args[index + 1]
            index += 2
            if arg == "-name":
                name = value
            elif arg == "-type":
                if value not in ("f", "d", "l"):
                    raise ShellUsageError(f"invalid -type {value!r}")
                type_ = value
            else:
                depth = _int(value, "-maxdepth")
            continue
        if arg.startswith("-") and arg != "-":
            raise ShellUsageError(f"unknown predicate {arg!r}")
        paths.append(arg)
        index += 1
    return paths, name, type_, depth


@command("find", "find [PATH...] [-name GLOB] [-type f|d|l] "
         "[-maxdepth N]", "search for files by name and type")
def cmd_find(sh: Shell, args: list[str]) -> int:
    """``find``: fnmatch on unescaped names; links not followed."""
    paths, name, type_, depth = _parse_find(args)
    sink = _ErrorSink(sh, "find")
    for shown in paths or ["."]:
        abs_ = sh.abspath(shown)
        start = normpath(abs_)
        try:
            for found, _node in vwalk.find(
                    sh.vfs, abs_, name=name, type_=type_,
                    max_depth=depth,
                    on_error=sink.handler(start, shown)):
                sh.write(_show(start, shown, found) + "\n")
        except AwsMountError as exc:
            sink.fail(shown, exc)
    return STATUS_ERROR if sink.count else STATUS_OK


@command("grep", "grep [-r] [-i] [-n] [-l] PATTERN PATH...",
         "search file contents (Python regular expressions)")
def cmd_grep(sh: Shell, args: list[str]) -> int:
    """``grep``: 0 match, 1 no match, 3 when some paths failed."""
    opts, rest = getopt.gnu_getopt(args, "rRinl")
    flags = {opt for opt, _ in opts}
    recursive = "-r" in flags or "-R" in flags
    ignore_case = "-i" in flags
    numbers = "-n" in flags
    files_only = "-l" in flags
    if not rest:
        raise ShellUsageError("missing PATTERN")
    pattern, paths = rest[0], rest[1:]
    if not paths:
        if not recursive:
            raise ShellUsageError("missing PATH")
        paths = ["."]
    try:
        re.compile(pattern, re.IGNORECASE if ignore_case else 0)
    except re.error as exc:
        raise ShellUsageError(f"invalid pattern: {exc}") from exc
    show_names = recursive or len(paths) > 1
    sink = _ErrorSink(sh, "grep")
    matched = False
    for shown in paths:
        abs_ = sh.abspath(shown)
        start = normpath(abs_)
        try:
            hits = vwalk.grep(sh.vfs, pattern, [abs_],
                              recursive=recursive,
                              ignore_case=ignore_case,
                              files_only=files_only,
                              on_error=sink.handler(start, shown))
            for hit in hits:
                matched = True
                name = _show(start, shown, hit.path)
                if files_only:
                    sh.write(name + "\n")
                    continue
                if hit.binary:
                    sh.write(f"Binary file {name} matches\n")
                    continue
                prefix = f"{name}:" if show_names else ""
                if numbers:
                    prefix += f"{hit.lineno}:"
                sh.write(f"{prefix}{hit.line}\n")
        except AwsMountError as exc:
            sink.fail(shown, exc)
    if sink.count:
        return STATUS_PARTIAL
    return STATUS_OK if matched else STATUS_ERROR


# -- session -----------------------------------------------------------


@command("whoami", "whoami",
         "identity of the account under cwd (or of all accounts)")
def cmd_whoami(sh: Shell, args: list[str]) -> int:
    """``whoami``: print ``_meta/identity.json``."""
    if args:
        raise ShellUsageError("too many arguments")
    parts = split(sh.cwd)
    if parts:
        accounts = [parts[0]]
    else:
        try:
            accounts = sh.vfs.listdir("/")
        except AwsMountError as exc:
            sh.report("whoami", "/", exc)
            return STATUS_ERROR
    status = STATUS_OK
    for index, account in enumerate(accounts):
        path = f"/{account}/_meta/identity.json"
        try:
            data = sh.vfs.read(path)
        except AwsMountError as exc:
            sh.report("whoami", path, exc)
            status = STATUS_ERROR
            continue
        if len(accounts) > 1:
            sh.write(("\n" if index else "") + f"==> {account} <==\n")
        sh.write_bytes(data)
    return status


@dataclass(frozen=True)
class _KeyFilter:
    """Cache-key predicate on ``(profile, region, client, ...)``."""

    profile: str | None
    region: str | None
    clients: frozenset[str] | None

    def __call__(self, key: Hashable) -> bool:
        if not isinstance(key, tuple) or len(key) < 3:
            return False
        if key[0] != self.profile:
            return False
        if self.region is not None and key[1] != self.region:
            return False
        if self.clients is not None and key[2] not in self.clients:
            return False
        return True


def _service_clients(sh: Shell, scope: str,
                     dirname: str) -> frozenset[str] | None:
    """boto3 client names used by a service directory."""
    registry = sh.ctx.registry
    svc = registry.service("global" if scope == "global" else "region",
                           dirname)
    if svc is None:
        return None
    found: set[str] = set()
    stack = list(svc.collections)
    while stack:
        spec = stack.pop()
        found.add(spec.client)
        stack.extend(spec.children)
    return frozenset(found)


def _key_filter(sh: Shell, real: str) -> _KeyFilter | None:
    """Predicate for a physical path; None means "everything"."""
    parts = split(real)
    if not parts:
        return None
    account = next((a for a in sh.ctx.accounts.accounts()
                    if a.dirname == parts[0]), None)
    if account is None:
        return None
    region: str | None = None
    clients: frozenset[str] | None = None
    if len(parts) >= 2 and parts[1] != "_meta":
        scope = "global" if parts[1] == "global" else "region"
        region = account.global_region if scope == "global" else parts[1]
        if len(parts) >= 3:
            clients = _service_clients(sh, scope, parts[2])
    return _KeyFilter(account.profile, region, clients)


def _invalidate_up(target: DirNode) -> None:
    """Invalidate ``target`` and its ancestors up to a CollectionDir.

    A ResourceDir keeps the item of its collection's memoised listing,
    so refreshing a resource (or a file in it) must also invalidate the
    enclosing collection. Outside a collection only ``target`` is
    invalidated.
    """
    chain: list[DirNode] = []
    cur: DirNode | None = target
    while cur is not None:
        chain.append(cur)
        if isinstance(cur, CollectionDir):
            break
        cur = cur.parent
    else:
        chain = [target]
    for node in chain:
        node.invalidate()


def _reset_accounts(sh: Shell) -> None:
    """Forget resolved accounts and the root listing."""
    sh.ctx.accounts.reset()
    sh.vfs.root.invalidate()


@command("refresh", "refresh [PATH]",
         "drop cached data under PATH (all if none) and reset the budget")
def cmd_refresh(sh: Shell, args: list[str]) -> int:
    """``refresh``: invalidate cache entries and memoised listings."""
    if len(args) > 1:
        raise ShellUsageError("too many arguments")
    ctx = sh.ctx
    if not args:
        dropped = ctx.cache.invalidate()
        _reset_accounts(sh)
        ctx.budget.reset()
        sh.write(f"refreshed everything: {dropped} cache entries "
                 "dropped, budget reset\n")
        return STATUS_OK
    shown = args[0]
    try:
        node = sh.vfs.resolve(sh.abspath(shown), follow=True)
    except AwsMountError as exc:
        sh.report("refresh", shown, exc)
        return STATUS_ERROR
    key_filter = _key_filter(sh, node.path)
    if key_filter is None:
        dropped = ctx.cache.invalidate()
    else:
        dropped = ctx.cache.invalidate(key_filter)
    target = node if isinstance(node, DirNode) else node.parent
    if target is not None:
        _invalidate_up(target)
    if len(split(node.path)) <= 1:
        _reset_accounts(sh)
    ctx.budget.reset()
    sh.write(f"refreshed {shown}: {dropped} cache entries dropped, "
             "budget reset\n")
    return STATUS_OK


@command("cache", "cache [--clear] [--reset-budget]",
         "show cache statistics and API budget")
def cmd_cache(sh: Shell, args: list[str]) -> int:
    """``cache``: print CacheStats and budget usage."""
    opts, rest = getopt.gnu_getopt(args, "", ["clear", "reset-budget"])
    if rest:
        raise ShellUsageError("unexpected arguments")
    flags = {opt for opt, _ in opts}
    ctx = sh.ctx
    if "--clear" in flags:
        dropped = ctx.cache.invalidate()
        _reset_accounts(sh)
        sh.write(f"cache cleared ({dropped} entries)\n")
    if "--reset-budget" in flags:
        ctx.budget.reset()
        sh.write("budget reset\n")
    stats = ctx.cache.stats()
    budget = ctx.budget
    limit = str(budget.limit) if budget.limit else "unlimited"
    window = f"{budget.window:g}s" if budget.window else "session"
    sh.write(f"cache: entries={stats.entries} hits={stats.hits} "
             f"misses={stats.misses} coalesced={stats.coalesced} "
             f"evictions={stats.evictions} negative={stats.negative}\n")
    sh.write(f"budget: {budget.used()}/{limit} calls (window {window})\n")
    sh.write(f"errors: {ctx.errors.count()} (see _meta/errors.log)\n")
    return STATUS_OK


@command("help", "help [CMD]", "show help")
def cmd_help(sh: Shell, args: list[str]) -> int:
    """``help``: list commands or describe one."""
    if len(args) > 1:
        raise ShellUsageError("too many arguments")
    if args:
        cmd = COMMANDS.get(args[0])
        if cmd is None:
            sh.error(f"help: no such command: {args[0]}")
            return STATUS_ERROR
        sh.write(f"usage: {cmd.synopsis}\n  {cmd.summary}\n")
        return STATUS_OK
    sh.write("Commands (read-only):\n")
    seen: set[int] = set()
    for name in sorted(COMMANDS):
        cmd = COMMANDS[name]
        if id(cmd.fn) in seen and name != cmd.synopsis.split()[0]:
            continue
        seen.add(id(cmd.fn))
        sh.write(f"  {cmd.synopsis}\n      {cmd.summary}\n")
    sh.write("\n" + PIPE_HELP)
    return STATUS_OK


@command("exit", "exit [STATUS]", "leave the shell", aliases=("quit",))
def cmd_exit(sh: Shell, args: list[str]) -> int:
    """``exit``/``quit``: stop the REPL."""
    if len(args) > 1:
        raise ShellUsageError("too many arguments")
    code = _int(args[0], "STATUS") if args else STATUS_OK
    sh.should_exit = True
    sh.exit_status = code
    return code
