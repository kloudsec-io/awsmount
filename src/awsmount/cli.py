"""Command line interface (click); see ARCHITECTURE: Command line.

Exit codes: 0 ok, 1 error, 2 usage, 3 partial (errors recorded),
4 API budget exhausted, 130 interrupted. AWS-touching options are
accepted both before the subcommand and after it; values given on the
subcommand win.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn

import click
from click.core import ParameterSource

from awsmount import __version__
from awsmount.config import Config, parse_services
from awsmount.errors import AwsMountError
from awsmount.secrets.cli import secrets_group

if TYPE_CHECKING:
    from awsmount.adapters.shell.commands import Shell
    from awsmount.session.context import Context
    from awsmount.vfs.resolver import VFS

__all__ = [
    "EXIT_BUDGET",
    "EXIT_ERROR",
    "EXIT_INTERRUPTED",
    "EXIT_OK",
    "EXIT_PARTIAL",
    "EXIT_USAGE",
    "cli",
    "common_options",
    "main",
]

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_PARTIAL = 3
EXIT_BUDGET = 4
EXIT_INTERRUPTED = 130

COMMON_NAMES = ("profile", "region", "endpoint_url", "services", "reveal",
                "ttl", "max_api_calls", "budget_window", "concurrency",
                "max_attempts", "s3_objects", "lazy_size", "verbose",
                "no_color")

REVEAL_WARNING = (
    "awsmount: WARNING: --reveal disables secret redaction. Any local "
    "process, including AI agents, can read revealed values.")
FOLLOW_WARNING = (
    "awsmount: WARNING: --webdav-links follow serves symlinks as their "
    "targets; recursive tools may loop.")


def common_options(region_short: bool = True) -> Callable[[Any], Any]:
    """Decorator adding the options every AWS-touching command accepts.

    ``region_short=False`` drops ``-r`` (used by ``grep -r``).
    """

    def decorate(f: Any) -> Any:
        region = (("--region", "-r", "region") if region_short
                  else ("--region", "region"))
        options = [
            click.option("--profile", "-p", "profile", multiple=True,
                         metavar="NAME",
                         help="AWS profile; repeat for several "
                              "accounts."),
            click.option(*region, multiple=True, metavar="REGION",
                         help="Region to mount; repeatable, or 'all'."),
            click.option("--endpoint-url", "endpoint_url", default=None,
                         metavar="URL",
                         help="AWS-compatible endpoint (moto, "
                              "localemu)."),
            click.option("--services", "services", default=None,
                         metavar="LIST",
                         help="Comma list of service dirs to mount."),
            click.option("--reveal", "reveal", is_flag=True,
                         default=False,
                         help="Show secrets instead of <hidden> (risky)."),
            click.option("--ttl", "ttl", type=click.FloatRange(min=0),
                         default=60.0, show_default=True,
                         help="Cache TTL in seconds."),
            click.option("--max-api-calls", "max_api_calls",
                         type=click.IntRange(min=0), default=0,
                         show_default="unlimited",
                         help="Stop after N API calls per window; "
                              "0 = unlimited."),
            click.option("--budget-window", "budget_window",
                         type=click.FloatRange(min=0), default=600.0,
                         show_default=True,
                         help="Budget window seconds; 0 = lifetime."),
            click.option("--concurrency", "concurrency",
                         type=click.IntRange(min=1), default=4,
                         show_default=True,
                         help="In-flight calls per AWS service."),
            click.option("--max-attempts", "max_attempts",
                         type=click.IntRange(min=1), default=10,
                         show_default=True,
                         help="botocore retry attempts."),
            click.option("--s3-objects", "s3_objects",
                         type=click.IntRange(min=0), default=0,
                         show_default=True,
                         help="S3 object keys listed per bucket."),
            click.option("--lazy-size", "lazy_size",
                         type=click.Choice(["render", "zero"]),
                         default="zero", show_default=True,
                         help="FUSE size of unrendered lazy files "
                              "(WebDAV reports 0 until read)."),
            click.option("--verbose", "-v", "verbose", is_flag=True,
                         default=False,
                         help="Progress counter and errors on stderr."),
            click.option("--no-color", "no_color", is_flag=True,
                         default=False, help="Disable colors."),
        ]
        for option in reversed(options):
            f = option(f)
        return f

    return decorate


def _merged(local: dict[str, Any]) -> dict[str, Any]:
    """Common options, falling back to values given before the command."""
    cctx = click.get_current_context()
    root = cctx.find_root()
    inherited = root.obj if isinstance(root.obj, dict) else {}
    merged: dict[str, Any] = {}
    for name in COMMON_NAMES:
        value = local.get(name)
        source = cctx.get_parameter_source(name)
        if source in (None, ParameterSource.DEFAULT) and name in inherited:
            value = inherited[name]
        merged[name] = value
    return merged


def _config(local: dict[str, Any]) -> Config:
    """Build and validate a Config from the CLI options."""
    from awsmount.providers import ProviderRegistry

    opts = _merged(local)
    regions = tuple(dict.fromkeys(
        part.strip() for value in opts["region"] or ()
        for part in str(value).split(",") if part.strip()))
    names = tuple(dict.fromkeys(str(p) for p in opts["profile"] or ()))
    profiles: tuple[str | None, ...] = names if names else (None,)
    services = parse_services(opts["services"])
    if services is not None:
        known = {s.dirname for s in ProviderRegistry().services()}
        unknown = sorted(services - known)
        if unknown:
            raise click.UsageError(
                f"unknown service(s) {', '.join(unknown)}; known: "
                f"{', '.join(sorted(known))}")
    try:
        config = Config(
            profiles=profiles,
            regions=regions,
            endpoint_url=opts["endpoint_url"],
            reveal=bool(opts["reveal"]),
            ttl=float(opts["ttl"]),
            max_api_calls=int(opts["max_api_calls"]),
            budget_window=float(opts["budget_window"]),
            concurrency=int(opts["concurrency"]),
            max_attempts=int(opts["max_attempts"]),
            s3_objects=int(opts["s3_objects"]),
            services=services,
            verbose=bool(opts["verbose"]),
            color=False if opts["no_color"] else None,
            lazy_size=opts["lazy_size"],
        )
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    if config.reveal:
        click.echo(REVEAL_WARNING, err=True)
    return config


def _session(local: dict[str, Any]) -> tuple[Context, VFS]:
    """Context and lazy VFS for the given options (no API call yet)."""
    from awsmount import tree as _tree
    from awsmount.session import context as _context

    config = _config(local)
    ctx = _context.Context.from_config(config)
    return ctx, _tree.build_vfs(ctx)


def _shell(local: dict[str, Any]) -> Shell:
    from awsmount.adapters.shell import commands as _commands

    ctx, vfs = _session(local)
    return _commands.Shell(vfs, ctx, color=ctx.config.color)


def _exit(code: int) -> NoReturn:
    click.get_current_context().exit(code)
    raise AssertionError("unreachable")


def _budget_exhausted(ctx: Context) -> bool:
    budget = ctx.budget
    return budget.limit > 0 and budget.used() >= budget.limit


def _partial(ctx: Context, status: int) -> int:
    """Exit 3 when a profile failed and the command would say 0 or 1.

    Without it, "nothing found" and "could not look" are the same answer.
    """
    if status in (EXIT_OK, EXIT_ERROR) and ctx.accounts.failures():
        return EXIT_PARTIAL
    return status


def _finish(sh: Shell, status: int) -> NoReturn:
    sh.flush()
    sh.ctx.progress.finish()
    _exit(EXIT_BUDGET if sh.budget_hit else _partial(sh.ctx, status))


def _one_shot(local: dict[str, Any], argv: list[str]) -> NoReturn:
    sh = _shell(local)
    try:
        status = sh.run_argv(argv)
    finally:
        sh.ctx.progress.finish()
    _finish(sh, status)


def _adapter(module: str, attr: str) -> Callable[..., Any]:
    """Import an adapter entry point lazily with a clear failure."""
    try:
        mod = importlib.import_module(module)
    except ModuleNotFoundError as exc:
        missing = exc.name or module
        if missing.startswith("awsmount"):
            raise click.ClickException(
                f"{module} is not available in this installation of "
                f"awsmount {__version__}") from exc
        raise click.ClickException(
            f"missing dependency {missing!r} needed by {module} "
            f"(pip install {missing}); see 'awsmount doctor'") from exc
    except (ImportError, OSError) as exc:
        raise click.ClickException(
            f"cannot load {module}: {exc}; see 'awsmount doctor'") from exc
    fn = getattr(mod, attr, None)
    if not callable(fn):
        raise click.ClickException(f"{module}.{attr} is not available")
    return fn  # type: ignore[no-any-return]


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="awsmount")
@common_options()
@click.pass_context
def cli(ctx: click.Context, **kwargs: Any) -> None:
    """Mount any AWS account as a read-only filesystem."""
    ctx.obj = dict(kwargs)


@cli.command("version")
def version_cmd() -> None:
    """Print the awsmount version."""
    click.echo(f"awsmount {__version__}")


@cli.command("shell")
@click.option("-c", "command", default=None, metavar="CMD",
              help="Run one command line and exit with its status.")
@common_options()
def shell_cmd(command: str | None, **opts: Any) -> None:
    """Interactive shell (ls, cd, cat, grep, tree, find, get...)."""
    sh = _shell(opts)
    if command is not None:
        status = sh.run_line(command)
        _finish(sh, status)
    try:
        from awsmount.adapters.shell import repl as _repl
    except ImportError as exc:
        raise click.ClickException(
            f"the interactive shell needs prompt_toolkit: {exc}") from exc
    status = _repl.run_repl(sh)
    _finish(sh, status)


@cli.command("ls")
@click.argument("paths", nargs=-1)
@click.option("-l", "long_", is_flag=True, help="Long listing.")
@click.option("-a", "all_", is_flag=True, help="Include . and ..")
@click.option("-R", "recursive", is_flag=True, help="Recurse.")
@common_options()
def ls_cmd(paths: tuple[str, ...], long_: bool, all_: bool,
           recursive: bool, **opts: Any) -> None:
    """List directory contents."""
    argv = ["ls"]
    if long_:
        argv.append("-l")
    if all_:
        argv.append("-a")
    if recursive:
        argv.append("-R")
    _one_shot(opts, argv + ["--", *(paths or ("/",))])


@cli.command("cat")
@click.argument("paths", nargs=-1, required=True)
@common_options()
def cat_cmd(paths: tuple[str, ...], **opts: Any) -> None:
    """Print file contents."""
    _one_shot(opts, ["cat", *paths])


@cli.command("tree")
@click.argument("path", required=False, default="/")
@click.option("-L", "level", type=click.IntRange(min=1), default=None,
              help="Maximum depth.")
@common_options()
def tree_cmd(path: str, level: int | None, **opts: Any) -> None:
    """Draw a directory tree (links are not followed)."""
    argv = ["tree"]
    if level is not None:
        argv += ["-L", str(level)]
    _one_shot(opts, argv + ["--", path])


@cli.command("find")
@click.argument("paths", nargs=-1)
@click.option("-name", "name_glob", default=None, metavar="GLOB",
              help="Match the (unescaped) name.")
@click.option("-type", "type_char", type=click.Choice(["f", "d", "l"]),
              default=None, help="Entry type.")
@click.option("-maxdepth", "maxdepth", type=click.IntRange(min=0),
              default=None, help="Maximum depth.")
@common_options()
def find_cmd(paths: tuple[str, ...], name_glob: str | None,
             type_char: str | None, maxdepth: int | None,
             **opts: Any) -> None:
    """Find entries by name and type."""
    argv = ["find", *(paths or ("/",))]
    if name_glob is not None:
        argv += ["-name", name_glob]
    if type_char is not None:
        argv += ["-type", type_char]
    if maxdepth is not None:
        argv += ["-maxdepth", str(maxdepth)]
    _one_shot(opts, argv)


@cli.command("grep")
@click.argument("pattern")
@click.argument("paths", nargs=-1)
@click.option("-r", "--recursive", "recursive", is_flag=True,
              help="Recurse into directories (links not followed).")
@click.option("-i", "--ignore-case", "ignore_case", is_flag=True)
@click.option("-n", "--line-number", "line_number", is_flag=True)
@click.option("-l", "--files-with-matches", "files_only", is_flag=True)
@common_options(region_short=False)
def grep_cmd(pattern: str, paths: tuple[str, ...], recursive: bool,
             ignore_case: bool, line_number: bool, files_only: bool,
             **opts: Any) -> None:
    """Search file contents with a Python regular expression."""
    argv = ["grep"]
    if recursive:
        argv.append("-r")
    if ignore_case:
        argv.append("-i")
    if line_number:
        argv.append("-n")
    if files_only:
        argv.append("-l")
    targets = paths or (("/",) if recursive else ())
    if not targets:
        raise click.UsageError("missing PATH (or use -r)")
    _one_shot(opts, argv + ["--", pattern, *targets])


@cli.command("get")
@click.argument("path")
@click.argument("expr")
@common_options()
def get_cmd(path: str, expr: str, **opts: Any) -> None:
    """Extract a value from a JSON file (a.b[0].c, [*], *)."""
    _one_shot(opts, ["get", path, expr])


@cli.command("export")
@click.argument("path")
@click.argument("dest", type=click.Path(file_okay=False, path_type=Path))
@click.option("--links", "links", type=click.Choice(["keep", "skip",
                                                     "file"]),
              default="file", show_default=True,
              help="How symlinks are written: 'file' = a text file with "
                   "the target (safe for diff -r / grep -R), 'keep' = a "
                   "real symlink (cycles confuse recursive tools), "
                   "'skip' = omit.")
@click.option("--jobs", "jobs", type=click.IntRange(min=1), default=8,
              show_default=True, help="Parallel renderers.")
@click.option("--clean", is_flag=True,
              help="Replace a previous export (marker required).")
@click.option("--force", is_flag=True,
              help="Overwrite in place, never delete.")
@common_options()
def export_cmd(path: str, dest: Path, links: str, jobs: int, clean: bool,
               force: bool, **opts: Any) -> None:
    """Materialise PATH into the real directory DEST."""
    from awsmount.adapters import export as _export

    ctx, vfs = _session(opts)
    try:
        report = _export.export(vfs, path, dest,
                                links=links,  # type: ignore[arg-type]
                                jobs=jobs, clean=clean, force=force)
    except _export.ExportError as exc:
        raise click.ClickException(str(exc)) from exc
    except AwsMountError as exc:
        raise click.ClickException(f"{path}: {exc.strerror}") from exc
    finally:
        ctx.progress.finish()
    click.echo(f"exported {report.dirs} dirs, {report.files} files, "
               f"{report.links} links to {dest} "
               f"({len(report.errors)} errors)", err=True)
    if report.external:
        click.echo(f"awsmount: {report.external} links pointing outside "
                   f"{path} were written as text files", err=True)
    if report.errors:
        _exit(EXIT_BUDGET if _budget_exhausted(ctx) else EXIT_PARTIAL)
    _exit(_partial(ctx, EXIT_OK))


@cli.command("mount")
@click.argument("mountpoint", type=click.Path(file_okay=False))
@click.option("--method", type=click.Choice(["auto", "fuse", "webdav"]),
              default="auto", show_default=True,
              help="auto: Linux->fuse; macOS->webdav (built in, nothing "
                   "to install). FUSE on macOS only with --method fuse.")
@click.option("--webdav-links", "webdav_links",
              type=click.Choice(["file", "follow"]), default="file",
              show_default=True, help="How WebDAV serves symlinks.")
@click.option("--port", type=click.IntRange(0, 65535), default=0,
              show_default=True, help="WebDAV port (0 = random).")
@common_options()
def mount_cmd(mountpoint: str, method: str, webdav_links: str, port: int,
              **opts: Any) -> None:
    """Mount the account(s) read-only at MOUNTPOINT (blocks)."""
    from awsmount import doctor as _doctor
    from awsmount import platform as _platform

    chosen = _doctor.preferred_mount_method() if method == "auto" \
        else method
    if chosen is None:
        raise click.ClickException(
            "no mount method on this OS; use 'awsmount shell' or "
            "'awsmount serve'")
    if chosen == "webdav":
        if not _platform.is_macos():
            raise click.ClickException(
                "WebDAV mounting is automated on macOS only; use "
                "'--method fuse', or 'awsmount serve' with davfs2")
        fn = _adapter("awsmount.adapters.webdav.macos", "mount")
    else:
        fn = _adapter("awsmount.adapters.fuse.mount", "mount")
    ctx, vfs = _session(opts)
    if chosen == "webdav":
        if webdav_links == "follow":
            click.echo(FOLLOW_WARNING, err=True)
        status = fn(vfs, ctx, mountpoint, port=port,
                    links_mode=webdav_links)
    else:
        status = fn(vfs, ctx, mountpoint)
    ctx.progress.finish()
    _exit(int(status or 0))


@cli.command("umount")
@click.argument("mountpoint", type=click.Path(file_okay=False))
def umount_cmd(mountpoint: str) -> None:
    """Unmount MOUNTPOINT."""
    from awsmount import platform as _platform

    if not _platform.is_mounted(mountpoint):
        click.echo(f"awsmount: {mountpoint}: not a mount point", err=True)
        _exit(EXIT_ERROR)
    if _platform.unmount(mountpoint):
        _exit(EXIT_OK)
    click.echo(f"awsmount: cannot unmount {mountpoint}", err=True)
    _exit(EXIT_ERROR)


@cli.command("serve")
@click.option("--port", type=click.IntRange(0, 65535), default=0,
              show_default=True, help="Port on 127.0.0.1 (0 = random).")
@click.option("--webdav-links", "webdav_links",
              type=click.Choice(["file", "follow"]), default="file",
              show_default=True, help="How symlinks are served.")
@common_options()
def serve_cmd(port: int, webdav_links: str, **opts: Any) -> None:
    """Serve the tree over WebDAV on 127.0.0.1 (prints credentials)."""
    fn = _adapter("awsmount.adapters.webdav.server", "serve")
    ctx, vfs = _session(opts)
    if webdav_links == "follow":
        click.echo(FOLLOW_WARNING, err=True)
    status = fn(vfs, ctx, port=port, links_mode=webdav_links,
                echo=click.echo)
    ctx.progress.finish()
    _exit(int(status or 0))


@cli.command("doctor")
@click.option("--json", "as_json", is_flag=True, help="JSON output.")
@click.option("--check-credentials", is_flag=True,
              help="Also call sts get_caller_identity per profile.")
@click.option("--profile", "-p", "profile", multiple=True,
              metavar="NAME", help="Profile for --check-credentials.")
@click.option("--endpoint-url", "endpoint_url", default=None,
              metavar="URL", help="Endpoint for --check-credentials.")
def doctor_cmd(as_json: bool, check_credentials: bool,
               profile: tuple[str, ...], endpoint_url: str | None) -> None:
    """Report which mount methods work on this machine."""
    from awsmount import doctor as _doctor

    # ``awsmount -p NAME doctor`` and ``awsmount doctor -p NAME`` are the
    # same, as for every other command.
    opts = _merged({"profile": profile, "endpoint_url": endpoint_url})
    profiles: tuple[str | None, ...] = tuple(opts["profile"] or ()) or (None,)
    report = _doctor.run_doctor(check_credentials=check_credentials,
                                profiles=profiles,
                                endpoint_url=opts["endpoint_url"])
    if as_json:
        click.echo(json.dumps(report.to_json(), indent=2, sort_keys=True))
    else:
        click.echo(report.render_text(), nl=False)
    # A row that says FAIL (a profile that cannot be used, an unsupported
    # Python) is an error for scripts; MISSING and optional rows are not.
    _exit(EXIT_ERROR if any(c.status == _doctor.FAIL
                            for c in report.checks) else EXIT_OK)


LAYOUT_LEGEND = ("* = fetched on first read (an API call), "
                 "? = only when the resource has one, "
                 "/ = directory")


@cli.command("services")
@click.option("--json", "as_json", is_flag=True,
              help="JSON output, with the files and links of each type.")
@click.option("--markdown", is_flag=True,
              help="Markdown tables (coverage, then files and links).")
@click.option("--short", is_flag=True,
              help="One line per service, without files and links.")
def services_cmd(as_json: bool, markdown: bool, short: bool) -> None:
    """List supported services, resource types and what each contains."""
    from awsmount.providers import ProviderRegistry

    registry = ProviderRegistry()
    rows = registry.summary()
    layouts = registry.layouts()
    nservices = len(registry.services())
    header = f"{nservices} services, {len(rows)} resource types"
    groups: dict[tuple[str, str], list[str]] = {}
    for service, collection, scope in rows:
        groups.setdefault((service, scope), []).append(collection)
    if as_json:
        data = {
            "services": nservices,
            "resource_types": len(rows),
            "items": [{"service": lay.service, "collection": lay.collection,
                       "scope": lay.scope, "files": list(lay.files),
                       "links": list(lay.links)} for lay in layouts],
        }
        click.echo(json.dumps(data, indent=2, sort_keys=True))
    elif markdown:
        lines = ["# awsmount coverage", "", header, "",
                 "| Service | Scope | Resource types |",
                 "|---|---|---|"]
        for (service, scope), names in groups.items():
            lines.append(f"| {service} | {scope} | {', '.join(names)} |")
        lines += ["", "## Files and links of each resource directory", "",
                  LAYOUT_LEGEND.replace("*", "\\*") + ".", "",
                  "| Resource type | Files | Links |", "|---|---|---|"]
        for lay in layouts:
            files = ", ".join(f.replace("*", "\\*") for f in lay.files)
            links = ", ".join(lay.links) or "-"
            lines.append(f"| {lay.service}/{lay.collection} | {files} "
                         f"| {links} |")
        click.echo("\n".join(lines))
    elif short:
        click.echo(header)
        width = max((len(s) for s, _ in groups), default=0)
        for (service, scope), names in groups.items():
            click.echo(f"  {service:<{width}}  {scope:<6}  "
                       f"{', '.join(names)}")
    else:
        click.echo(header)
        click.echo(LAYOUT_LEGEND)
        current: tuple[str, str] | None = None
        for lay in layouts:
            if (lay.service, lay.scope) != current:
                current = (lay.service, lay.scope)
                click.echo(f"\n{lay.service}  ({lay.scope})")
            click.echo(f"  {lay.collection}")
            click.echo(f"    files: {', '.join(lay.files)}")
            if lay.links:
                click.echo(f"    links: {', '.join(lay.links)}")
    _exit(EXIT_OK)


cli.add_command(secrets_group)


def _quiet_stdout() -> None:
    """Point stdout at /dev/null after a broken pipe."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except (OSError, ValueError):
        pass


def main(argv: list[str] | None = None) -> None:
    """Console-script entry point."""
    try:
        rv = cli.main(args=argv, prog_name="awsmount",
                      standalone_mode=False)
    except click.ClickException as exc:
        exc.show()
        sys.exit(exc.exit_code)
    except (click.Abort, KeyboardInterrupt):
        sys.stderr.write("\n")
        sys.exit(EXIT_INTERRUPTED)
    except BrokenPipeError:
        _quiet_stdout()
        sys.exit(EXIT_ERROR)
    sys.exit(rv if isinstance(rv, int) else EXIT_OK)
