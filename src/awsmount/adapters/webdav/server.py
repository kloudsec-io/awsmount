"""cheroot WebDAV server and middleware chain (ARCHITECTURE: WebDAV).

Middleware order, outermost first: HostCheck, JunkFilter, TokenPrefix,
MethodFilter, then wsgidav. OPTIONS is answered by MethodFilter itself
(it reveals nothing and must work on the share root, which wsgidav
would otherwise report as 404 for a read-only provider).
"""

from __future__ import annotations

import signal
import sys
import threading
from collections.abc import Callable, Iterable
from typing import Any

from awsmount.adapters.webdav.auth import Credentials
from awsmount.adapters.webdav.provider import LinksMode, VFSDavProvider
from awsmount.vfs.resolver import VFS

__all__ = [
    "BIND_HOST",
    "HostCheck",
    "JUNK_NAMES",
    "JunkFilter",
    "MethodFilter",
    "TokenPrefix",
    "WebDavServer",
    "build_app",
    "is_junk",
    "is_junk_name",
    "is_junk_path",
]

BIND_HOST = "127.0.0.1"
READ_METHODS = frozenset({"OPTIONS", "GET", "HEAD", "PROPFIND"})
ALLOW_HEADER = "OPTIONS, GET, HEAD, PROPFIND"
JUNK_NAMES = frozenset({
    ".DS_Store",
    ".metadata_never_index",
    ".metadata_never_index_unless_rootfs",
    ".Spotlight-V100",
    ".Trashes",
    ".fseventsd",
    ".hidden",
    ".localized",
    ".VolumeIcon.icns",
    ".TemporaryItems",
    ".com.apple.timemachine.donotpresent",
    "Icon\r",
    "desktop.ini",
})
FINITE_DEPTH_BODY = (
    b'<?xml version="1.0" encoding="utf-8"?>\n'
    b'<D:error xmlns:D="DAV:"><D:propfind-finite-depth/></D:error>\n')

Environ = dict[str, Any]
StartResponse = Callable[..., Any]
WSGIApp = Callable[[Environ, StartResponse], Iterable[bytes]]


def _respond(start_response: StartResponse, status: str,
             body: bytes = b"",
             content_type: str = "text/plain; charset=utf-8",
             extra: Iterable[tuple[str, str]] = ()) -> list[bytes]:
    """Send a complete small response."""
    headers = [("Content-Type", content_type),
               ("Content-Length", str(len(body)))]
    headers.extend(extra)
    start_response(status, headers)
    return [body]


def is_junk(name: str) -> bool:
    """True for macOS/Windows junk names (``.DS_Store``, ``._x``...)."""
    return name in JUNK_NAMES or name.startswith("._")


def is_junk_name(name: str) -> bool:
    """Alias of :func:`is_junk` for a single path component."""
    return is_junk(name)


def is_junk_path(path: str) -> bool:
    """True when any component of ``path`` is a junk name."""
    return any(is_junk(c) for c in path.split("/") if c)


class HostCheck:
    """421 unless Host is ``127.0.0.1:PORT`` or ``localhost:PORT``."""

    def __init__(self, app: WSGIApp, port: Callable[[], int]) -> None:
        self.app = app
        self._port = port

    def __call__(self, environ: Environ,
                 start_response: StartResponse) -> Iterable[bytes]:
        """WSGI entry point."""
        host = str(environ.get("HTTP_HOST", "")).strip().lower()
        port = self._port()
        if host not in (f"127.0.0.1:{port}", f"localhost:{port}"):
            return _respond(start_response, "421 Misdirected Request",
                            b"Misdirected Request\n")
        return self.app(environ, start_response)


class JunkFilter:
    """404 for junk names, without touching the VFS."""

    def __init__(self, app: WSGIApp) -> None:
        self.app = app

    def __call__(self, environ: Environ,
                 start_response: StartResponse) -> Iterable[bytes]:
        """WSGI entry point."""
        if is_junk_path(str(environ.get("PATH_INFO", ""))):
            return _respond(start_response, "404 Not Found",
                            b"Not Found\n")
        return self.app(environ, start_response)


class TokenPrefix:
    """404 unless the path starts with ``/<token>/``."""

    def __init__(self, app: WSGIApp, credentials: Credentials) -> None:
        self.app = app
        self._creds = credentials

    def __call__(self, environ: Environ,
                 start_response: StartResponse) -> Iterable[bytes]:
        """WSGI entry point."""
        path = str(environ.get("PATH_INFO", ""))
        parts = path.split("/", 2)
        ok = (len(parts) >= 2 and parts[0] == ""
              and self._creds.check_token(parts[1]))
        if not ok:
            return _respond(start_response, "404 Not Found",
                            b"Not Found\n")
        return self.app(environ, start_response)


class MethodFilter:
    """Allow read methods only; finite PROPFIND depth; answer OPTIONS."""

    def __init__(self, app: WSGIApp) -> None:
        self.app = app

    def __call__(self, environ: Environ,
                 start_response: StartResponse) -> Iterable[bytes]:
        """WSGI entry point."""
        method = str(environ.get("REQUEST_METHOD", "")).upper()
        if method not in READ_METHODS:
            return _respond(start_response, "403 Forbidden",
                            b"Read-only file system\n")
        if method == "OPTIONS":
            return _respond(
                start_response, "200 OK",
                extra=[("DAV", "1"), ("Allow", ALLOW_HEADER),
                       ("MS-Author-Via", "DAV")])
        if method == "PROPFIND":
            depth = environ.get("HTTP_DEPTH")
            if depth is None or str(depth).strip() not in ("0", "1"):
                return _respond(start_response, "403 Forbidden",
                                FINITE_DEPTH_BODY,
                                content_type="application/xml; "
                                             "charset=utf-8")
        return self.app(environ, start_response)


def _wsgidav_app(vfs: VFS, credentials: Credentials,
                 links_mode: LinksMode, digest: bool,
                 denied_status: int = 403) -> WSGIApp:
    """The configured ``WsgiDAVApp``."""
    from wsgidav.wsgidav_app import WsgiDAVApp

    config: dict[str, Any] = {
        "provider_mapping": {
            credentials.prefix: VFSDavProvider(
                vfs, links_mode, denied_status)},
        "http_authenticator": {
            "domain_controller":
                "wsgidav.dc.simple_dc.SimpleDomainController",
            "accept_basic": True,
            "accept_digest": digest,
            "default_to_digest": digest,
        },
        "simple_dc": {"user_mapping": {"*": {
            credentials.user: {"password": credentials.password}}}},
        "lock_storage": False,
        "property_manager": None,
        "dir_browser": {"enable": False},
        "verbose": 1,
    }
    app: WSGIApp = WsgiDAVApp(config)
    return app


def build_app(vfs: VFS, credentials: Credentials,
              port: Callable[[], int], *,
              links_mode: LinksMode = "file",
              digest: bool = False,
              denied_status: int = 403) -> WSGIApp:
    """Full middleware chain in front of wsgidav."""
    app = _wsgidav_app(vfs, credentials, links_mode, digest, denied_status)
    app = MethodFilter(app)
    app = TokenPrefix(app, credentials)
    app = JunkFilter(app)
    return HostCheck(app, port)


class WebDavServer:
    """Read-only WebDAV server bound to 127.0.0.1 only."""

    def __init__(self, vfs: VFS, port: int = 0, *,
                 links_mode: LinksMode = "file",
                 credentials: Credentials | None = None,
                 digest: bool = True, numthreads: int = 16,
                 verbose: bool = False, denied_status: int = 403) -> None:
        if links_mode not in ("file", "follow"):
            raise ValueError(f"invalid links mode {links_mode!r}")
        self.vfs = vfs
        self.denied_status = denied_status
        self.links_mode: LinksMode = links_mode
        self.credentials = credentials or Credentials.generate()
        self.digest = digest
        self.verbose = verbose
        self._requested_port = port
        self._port = port
        self._numthreads = numthreads
        self._server: Any = None
        self._thread: threading.Thread | None = None
        if links_mode == "follow":
            sys.stderr.write(
                "[awsmount] warning: --webdav-links follow serves "
                "symlinks as their targets; recursive tools may loop\n")

    @property
    def host(self) -> str:
        """Bind address (always 127.0.0.1)."""
        return BIND_HOST

    @property
    def port(self) -> int:
        """Actual listening port (after :meth:`start`)."""
        return self._port

    @property
    def url(self) -> str:
        """Share URL including the token."""
        return f"http://{BIND_HOST}:{self._port}/{self.credentials.token}/"

    @property
    def running(self) -> bool:
        """True while the server thread is serving."""
        return (self._thread is not None and self._thread.is_alive()
                and self._server is not None
                and bool(getattr(self._server, "ready", False)))

    def start(self) -> int:
        """Bind, start serving on a thread and return the port."""
        if self._server is not None:
            return self._port
        from cheroot import wsgi as cheroot_wsgi

        app = build_app(self.vfs, self.credentials, lambda: self._port,
                        links_mode=self.links_mode, digest=self.digest,
                        denied_status=self.denied_status)
        server = cheroot_wsgi.Server(
            (BIND_HOST, self._requested_port), app,
            numthreads=self._numthreads, shutdown_timeout=1)
        server.prepare()
        self._port = int(server.bind_addr[1])
        self._server = server
        self._thread = threading.Thread(target=server.serve,
                                        name="awsmount-webdav",
                                        daemon=True)
        self._thread.start()
        return self._port

    def stop(self) -> None:
        """Stop serving and join the thread."""
        server, thread = self._server, self._thread
        self._server = None
        self._thread = None
        if server is not None:
            server.stop()
        if thread is not None:
            thread.join(timeout=5.0)

    def wait(self, timeout: float | None = None) -> None:
        """Block until the server thread ends (or ``timeout``)."""
        thread = self._thread
        if thread is not None:
            thread.join(timeout)

    def serve_forever(self) -> None:
        """Start if needed and block until stopped or interrupted."""
        self.start()
        try:
            while self._thread is not None and self._thread.is_alive():
                self._thread.join(0.5)
        finally:
            self.stop()

    def __enter__(self) -> WebDavServer:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()


class ShutdownSignals:
    """Context manager: SIGINT/SIGTERM set :attr:`event` instead of killing.

    Handlers are restored on exit. Usable only from the main thread
    (signal handlers cannot be installed elsewhere); in other threads it
    degrades to a plain event that nobody sets.
    """

    _SIGNALS = (signal.SIGINT, signal.SIGTERM)

    def __init__(self) -> None:
        self.event = threading.Event()
        self._previous: dict[int, Any] = {}

    def wait(self, timeout: float | None = None) -> bool:
        """Block until a signal arrives or ``timeout``; True if set."""
        return self.event.wait(timeout)

    def _handler(self, _signum: int, _frame: Any) -> None:
        self.event.set()

    def __enter__(self) -> ShutdownSignals:
        if threading.current_thread() is threading.main_thread():
            for sig in self._SIGNALS:
                self._previous[sig] = signal.signal(sig, self._handler)
        return self

    def __exit__(self, *_exc: object) -> None:
        for sig, previous in self._previous.items():
            signal.signal(sig, previous)
        self._previous.clear()


def serve(vfs: VFS, ctx: Any, *, port: int = 0,
          links_mode: LinksMode = "file",
          echo: Callable[[str], Any] | None = None) -> int:
    """Serve ``vfs`` over WebDAV on 127.0.0.1 until interrupted.

    Prints the URL and a fresh user/password pair (never written to disk)
    so any WebDAV client (Finder, davfs2, gio) can connect. Returns an
    exit status (0 = clean stop, 1 = could not start).
    """
    say = echo if echo is not None else print
    server = WebDavServer(vfs, port=port, links_mode=links_mode,
                          verbose=bool(getattr(
                              getattr(ctx, "config", None), "verbose",
                              False)))
    try:
        server.start()
    except OSError as exc:
        say(f"awsmount: cannot start WebDAV server: {exc}")
        return 1
    creds = server.credentials
    say(f"URL:      {server.url}")
    say(f"User:     {creds.user}")
    say(f"Password: {creds.password}")
    say("Read-only WebDAV on 127.0.0.1 only. Press Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    return 0
