"""``awsmount secrets``: mount Secrets Manager and Parameter Store values.

The only command that serves secret values. ``mount``, ``shell``,
``serve`` and ``export`` of the normal tree never do.
"""

from __future__ import annotations

from typing import Any, NoReturn

import click
from click.core import ParameterSource

from awsmount.config import Config

__all__ = ["WEBDAV_CACHE_WARNING", "secrets_group"]

WEBDAV_CACHE_WARNING = (
    "awsmount: WARNING: macOS's own WebDAV client keeps a temporary copy "
    "of every file read through this mount in /private/tmp/.webdavcache.* "
    "(owner-only, unlinked, removed at unmount). awsmount writes no value "
    "to disk itself; keep FileVault on.")

# name -> default used when neither the command nor the root group
# gave the option.
_DEFAULTS: dict[str, Any] = {
    "ttl": 300.0, "max_api_calls": 0, "budget_window": 600.0,
    "concurrency": 4, "max_attempts": 10, "endpoint_url": None,
    "verbose": False, "no_color": False,
}
_REJECTED = {"services": "--services", "reveal": "--reveal",
             "s3_objects": "--s3-objects", "lazy_size": "--lazy-size"}


def _explicit(name: str) -> tuple[bool, Any]:
    """Value of an option given on the command or on the root group."""
    cctx = click.get_current_context()
    if cctx.get_parameter_source(name) not in (None,
                                               ParameterSource.DEFAULT):
        return True, cctx.params.get(name)
    root = cctx.find_root()
    if root.get_parameter_source(name) not in (None,
                                               ParameterSource.DEFAULT):
        return True, root.params.get(name)
    return False, None


def _one(name: str, what: str) -> str | None:
    """A single-valued option (the root group allows several)."""
    found, value = _explicit(name)
    if not found:
        return None
    values = tuple(value) if isinstance(value, (tuple, list)) else (value,)
    parts = [p.strip() for v in values for p in str(v).split(",")
             if p.strip()]
    if len(set(parts)) > 1:
        raise click.UsageError(f"awsmount secrets mounts one {what}")
    return parts[0] if parts else None


def _config() -> Config:
    """Validated Config of the current secrets command."""
    from awsmount.secrets import session as _session

    for name, flag in _REJECTED.items():
        found, value = _explicit(name)
        if found and value:
            raise click.UsageError(
                f"{flag} does not apply to 'awsmount secrets'")
    opts = {}
    for name, default in _DEFAULTS.items():
        found, value = _explicit(name)
        opts[name] = value if found else default
    profile = _one("profile", "profile")
    try:
        region = _session.resolve_region(profile, _one("region", "region"))
        return Config(
            profiles=(profile,), regions=(region,),
            endpoint_url=opts["endpoint_url"], ttl=float(opts["ttl"]),
            max_api_calls=int(opts["max_api_calls"]),
            budget_window=float(opts["budget_window"]),
            concurrency=int(opts["concurrency"]),
            max_attempts=int(opts["max_attempts"]),
            verbose=bool(opts["verbose"]),
            color=False if opts["no_color"] else None)
    except (ValueError, _session.SecretsError) as exc:
        raise click.UsageError(str(exc)) from exc


def _start() -> Any:
    """Build the session (one STS call) or fail with a clear message."""
    from awsmount.errors import AwsMountError
    from awsmount.secrets import session as _session

    config = _config()
    _session.harden_process()
    try:
        session = _session.build_session(config)
    except AwsMountError as exc:
        raise click.ClickException(str(exc)) from exc
    _session.echo_banner(session, config.ttl)
    return session


def _exit(code: int) -> NoReturn:
    click.get_current_context().exit(code)
    raise AssertionError("unreachable")


def secrets_options(f: Any) -> Any:
    """Options of the secrets commands."""
    options = [
        click.option("--profile", "-p", "profile", metavar="NAME",
                     default=None, help="AWS profile."),
        click.option("--region", "-r", "region", metavar="REGION",
                     default=None,
                     help="Region to mount (default: the profile's)."),
        click.option("--endpoint-url", "endpoint_url", default=None,
                     metavar="URL", help="Custom endpoint (tests)."),
        click.option("--ttl", "ttl", type=click.FloatRange(min=0),
                     default=None, metavar="SECONDS",
                     help="Seconds a value (and a listing) is kept in "
                          "memory; 0 = values are not cached. "
                          "[default: 300]"),
        click.option("--max-api-calls", "max_api_calls",
                     type=click.IntRange(min=0), default=0,
                     help="Stop after N API calls per window; 0 = "
                          "unlimited."),
        click.option("--budget-window", "budget_window",
                     type=click.FloatRange(min=0), default=600.0,
                     show_default=True,
                     help="Budget window seconds; 0 = lifetime."),
        click.option("--concurrency", "concurrency",
                     type=click.IntRange(min=1), default=4,
                     show_default=True, help="Parallel calls per service."),
        click.option("--max-attempts", "max_attempts",
                     type=click.IntRange(min=1), default=10,
                     show_default=True, help="boto3 retry attempts."),
        click.option("--verbose", "-v", "verbose", is_flag=True,
                     help="Log API calls to stderr."),
        click.option("--no-color", "no_color", is_flag=True,
                     help="Disable colors."),
    ]
    for option in reversed(options):
        f = option(f)
    return f


@click.group("secrets")
def secrets_group() -> None:
    """Mount Secrets Manager and Parameter Store VALUES, read-only.

    Unlike the rest of awsmount, these files hold secret values. Only this
    command reads them. One profile and one region per mount.
    """


@secrets_group.command("mount")
@click.argument("mountpoint", type=click.Path(file_okay=False))
@click.option("--method", type=click.Choice(["auto", "fuse", "webdav"]),
              default="auto", show_default=True,
              help="auto: Linux->fuse; macOS->webdav.")
@click.option("--port", type=click.IntRange(0, 65535), default=0,
              show_default=True, help="WebDAV port (0 = random).")
@secrets_options
def mount_cmd(mountpoint: str, method: str, port: int,
              **_opts: Any) -> None:
    """Mount the values read-only at MOUNTPOINT (blocks)."""
    from awsmount import doctor as _doctor
    from awsmount import platform as _platform
    from awsmount.cli import _adapter

    chosen = _doctor.preferred_mount_method() if method == "auto" \
        else method
    if chosen is None:
        raise click.ClickException(
            "no mount method on this OS; use 'awsmount secrets shell'")
    if chosen == "webdav" and not _platform.is_macos():
        raise click.ClickException(
            "WebDAV mounting is automated on macOS only; use "
            "'--method fuse'")
    fn = _adapter("awsmount.adapters.webdav.macos", "mount") \
        if chosen == "webdav" \
        else _adapter("awsmount.adapters.fuse.mount", "mount")
    session = _start()
    if chosen == "webdav":
        click.echo(WEBDAV_CACHE_WARNING, err=True)
    try:
        if chosen == "webdav":
            status = fn(session.vfs, session.ctx, mountpoint, port=port,
                        links_mode="file")
        else:
            status = fn(session.vfs, session.ctx, mountpoint)
    finally:
        session.close()
        session.ctx.progress.finish()
    _exit(int(status or 0))


@secrets_group.command("shell")
@click.option("-c", "command", default=None, metavar="CMD",
              help="Run one command line and exit with its status.")
@secrets_options
def shell_cmd(command: str | None, **_opts: Any) -> None:
    """Interactive shell over the values (ls, cat, tree, find, grep)."""
    from awsmount.adapters.shell import commands as _commands

    session = _start()
    sh = _commands.Shell(session.vfs, session.ctx,
                         color=session.ctx.config.color)
    try:
        if command is not None:
            status = sh.run_line(command)
        else:
            try:
                from awsmount.adapters.shell import repl as _repl
            except ImportError as exc:
                raise click.ClickException(
                    f"the interactive shell needs prompt_toolkit: "
                    f"{exc}") from exc
            status = _repl.run_repl(sh)
        sh.flush()
    finally:
        session.close()
        session.ctx.progress.finish()
    _exit(4 if sh.budget_hit else status)


@secrets_group.command("umount")
@click.argument("mountpoint", type=click.Path(file_okay=False))
def umount_cmd(mountpoint: str) -> None:
    """Unmount MOUNTPOINT."""
    from awsmount.cli import umount_cmd as _umount

    click.get_current_context().invoke(_umount, mountpoint=mountpoint)
