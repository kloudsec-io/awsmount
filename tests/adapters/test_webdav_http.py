"""WebDAV adapter over HTTP: a real cheroot server backed by moto.

A ``ThreadedMotoServer`` is seeded with the EC2/VPC estate from
``tests/fixtures/seed.py``. A real :class:`Context` is pointed at that
server with ``--endpoint-url``, and a real :class:`WebDavServer` is
started on ``127.0.0.1`` port 0. Every test talks plain HTTP through
``http.client``.

Adversarial checks:

* authentication is required (Basic accepted), and a wrong password is
  rejected;
* the per-session token prefix is required, even with valid
  credentials;
* every write method is refused with 403;
* ``PROPFIND`` with ``Depth: infinity`` (or no Depth) is refused;
* a foreign ``Host`` header gets 421 (DNS-rebinding defence);
* ``Content-Length`` (from PROPFIND, HEAD and GET) always equals the
  real body length, Range requests slice the same bytes;
* symlinks are served as regular files containing the relative target,
  and paths that would traverse a symlink do not exist;
* whole-file redaction holds over WebDAV.
"""

from __future__ import annotations

import http.client
import importlib.util
import os
import socket
import sys
import xml.etree.ElementTree as ET
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.parse import quote, unquote, urlsplit

import boto3
import pytest

pytest.importorskip("wsgidav")
pytest.importorskip("cheroot")
_moto_server = pytest.importorskip("moto.server")

from awsmount.adapters.webdav.server import (  # noqa: E402
    WebDavServer,
)
from awsmount.config import Config  # noqa: E402
from awsmount.session.context import Context  # noqa: E402
from awsmount.session.redact import REDACTED  # noqa: E402
from awsmount.tree.root import build_vfs  # noqa: E402
from awsmount.vfs.resolver import VFS  # noqa: E402

REGION = "us-east-1"
DAV = "{DAV:}"
ALLPROP = (b'<?xml version="1.0" encoding="utf-8"?>\n'
           b'<D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>\n')
AWS_ENV = {
    "AWS_ACCESS_KEY_ID": "testing",
    "AWS_SECRET_ACCESS_KEY": "testing",
    "AWS_SECURITY_TOKEN": "testing",
    "AWS_SESSION_TOKEN": "testing",
    "AWS_DEFAULT_REGION": REGION,
    "AWS_CONFIG_FILE": os.devnull,
    "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
}
WRITE_METHODS = ("PUT", "DELETE", "MKCOL", "COPY", "MOVE", "PROPPATCH",
                 "LOCK", "UNLOCK", "POST")
SEED_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "seed.py"


# ---------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------


def _load_seed() -> ModuleType:
    """Import ``tests/fixtures/seed.py`` regardless of sys.path."""
    name = "awsmount_tests_fixtures_seed"
    cached = sys.modules.get(name)
    if cached is not None:
        return cached
    spec = importlib.util.spec_from_file_location(name, SEED_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {SEED_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _free_port() -> int:
    """An unused loopback TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@dataclass(frozen=True)
class Reply:
    """One HTTP response."""

    status: int
    headers: dict[str, str]
    body: bytes


@dataclass(frozen=True)
class Entry:
    """One ``<D:response>`` of a multistatus body."""

    href: str
    is_dir: bool
    length: int | None

    @property
    def name(self) -> str:
        """Last path component (URL-decoded once, i.e. the VFS name)."""
        return unquote(self.href.rstrip("/").rsplit("/", 1)[-1])


def parse_multistatus(body: bytes) -> dict[str, Entry]:
    """Parse a 207 body into ``{href without trailing slash: Entry}``."""
    root = ET.fromstring(body)
    out: dict[str, Entry] = {}
    for resp in root.findall(f"{DAV}response"):
        href = urlsplit(resp.findtext(f"{DAV}href") or "").path
        is_dir = False
        length: int | None = None
        for propstat in resp.findall(f"{DAV}propstat"):
            status = propstat.findtext(f"{DAV}status") or ""
            if " 200" not in status:
                continue
            prop = propstat.find(f"{DAV}prop")
            if prop is None:
                continue
            rtype = prop.find(f"{DAV}resourcetype")
            if rtype is not None and \
                    rtype.find(f"{DAV}collection") is not None:
                is_dir = True
            text = prop.findtext(f"{DAV}getcontentlength")
            if text:
                length = int(text.strip())
        out[href.rstrip("/")] = Entry(href, is_dir, length)
    return out


class Dav:
    """Tiny HTTP client for the server under test."""

    def __init__(self, server: WebDavServer) -> None:
        self.server = server
        self.port = server.port
        self.token = server.credentials.token
        self.base = f"/{self.token}"

    def url(self, vpath: str) -> str:
        """Request path for an (escaped) absolute VFS path."""
        return self.base + quote(vpath, safe="/")

    def vpath(self, href: str) -> str:
        """VFS path of an href returned by the server."""
        assert href.startswith(self.base + "/") or href == self.base
        return unquote(href[len(self.base):]) or "/"

    def request(self, method: str, path: str, *,
                headers: Mapping[str, str] | None = None,
                body: bytes | None = None, auth: bool = True,
                password: str | None = None,
                host: str | None = None) -> Reply:
        """Send one request on a fresh connection."""
        creds = self.server.credentials
        hdrs: dict[str, str] = {}
        if auth:
            if password is None:
                hdrs["Authorization"] = creds.basic_header()
            else:
                import base64

                raw = f"{creds.user}:{password}".encode("utf-8")
                hdrs["Authorization"] = (
                    "Basic " + base64.b64encode(raw).decode("ascii"))
        if host is not None:
            hdrs["Host"] = host
        hdrs.update(headers or {})
        conn = http.client.HTTPConnection("127.0.0.1", self.port,
                                          timeout=60)
        try:
            conn.request(method, path, body=body, headers=hdrs)
            resp = conn.getresponse()
            data = resp.read()
            return Reply(resp.status,
                         {k.lower(): v for k, v in resp.getheaders()},
                         data)
        finally:
            conn.close()

    def get(self, path: str, **kw: Any) -> Reply:
        """GET ``path``."""
        return self.request("GET", path, **kw)

    def propfind(self, path: str, depth: str | None = "1",
                 **kw: Any) -> Reply:
        """PROPFIND allprop with the given Depth (None = no header)."""
        headers = {"Content-Type": "application/xml; charset=utf-8"}
        if depth is not None:
            headers["Depth"] = depth
        return self.request("PROPFIND", path, headers=headers,
                            body=ALLPROP, **kw)


@dataclass(frozen=True)
class Estate:
    """Seeded moto account seen through a real Context and VFS."""

    seed: Any
    ctx: Context
    vfs: VFS

    @property
    def account_dir(self) -> str:
        """The single top-level account directory name."""
        names = self.vfs.listdir("/")
        assert len(names) == 1, names
        return names[0]

    @property
    def instance(self) -> str:
        """VFS path of the seeded web instance."""
        return (f"/{self.account_dir}/{REGION}/ec2/instances/"
                f"{self.seed.instance_web}")


# ---------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------


@pytest.fixture(scope="module")
def moto_endpoint() -> Iterator[str]:
    """A threaded moto server with isolated fake credentials."""
    patch = pytest.MonkeyPatch()
    for key, value in AWS_ENV.items():
        patch.setenv(key, value)
    patch.delenv("AWS_PROFILE", raising=False)
    patch.delenv("AWS_DEFAULT_PROFILE", raising=False)
    port = _free_port()
    server = _moto_server.ThreadedMotoServer(ip_address="127.0.0.1",
                                             port=port, verbose=False)
    server.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.stop()
        patch.undo()


@pytest.fixture(scope="module")
def estate(moto_endpoint: str) -> Estate:
    """Seeded account plus a Context/VFS pointed at moto."""
    session = boto3.Session(aws_access_key_id="testing",
                            aws_secret_access_key="testing",
                            region_name=REGION)
    seed = _load_seed().seed_ec2_vpc(session, region=REGION,
                                     endpoint_url=moto_endpoint)
    config = Config(regions=(REGION,), endpoint_url=moto_endpoint)
    ctx = Context.from_config(config)
    return Estate(seed=seed, ctx=ctx, vfs=build_vfs(ctx))


@pytest.fixture(scope="module")
def dav(estate: Estate) -> Iterator[Dav]:
    """A real WebDAV server on 127.0.0.1:0 over the moto-backed VFS."""
    server = WebDavServer(estate.vfs, port=0)
    port = server.start()
    assert port > 0
    try:
        yield Dav(server)
    finally:
        server.stop()


# ---------------------------------------------------------------------
# basics and authentication
# ---------------------------------------------------------------------


def test_server_binds_loopback_on_random_port(dav: Dav) -> None:
    """port=0 picks a free port; the URL embeds the token."""
    assert dav.port != 0
    assert dav.server.url == (f"http://127.0.0.1:{dav.port}/"
                              f"{dav.token}/")
    assert dav.server.running


def test_options(dav: Dav) -> None:
    """OPTIONS on the share is allowed and advertises DAV."""
    reply = dav.request("OPTIONS", dav.base + "/")
    assert reply.status == 200
    assert "dav" in reply.headers
    assert "PROPFIND" in reply.headers.get("allow", "")


def test_get_without_credentials_is_401(dav: Dav,
                                        estate: Estate) -> None:
    """The token alone does not grant access."""
    path = dav.url(estate.instance + "/describe.json")
    reply = dav.get(path, auth=False)
    assert reply.status == 401
    assert "www-authenticate" in reply.headers
    assert b'"InstanceId"' not in reply.body


def test_propfind_without_credentials_is_401(dav: Dav) -> None:
    """Listings need authentication too."""
    reply = dav.propfind(dav.base + "/", depth="1", auth=False)
    assert reply.status == 401


def test_wrong_password_is_401(dav: Dav, estate: Estate) -> None:
    """A wrong password is rejected."""
    path = dav.url(estate.instance + "/describe.json")
    reply = dav.get(path, password="not-the-password")
    assert reply.status == 401


def test_get_with_basic_auth(dav: Dav, estate: Estate) -> None:
    """Authenticated GET returns exactly the VFS bytes."""
    vpath = estate.instance + "/describe.json"
    reply = dav.get(dav.url(vpath))
    assert reply.status == 200
    assert reply.body == estate.vfs.read(vpath)
    assert reply.headers["content-type"].startswith("application/json")
    assert int(reply.headers["content-length"]) == len(reply.body)
    assert estate.seed.instance_web.encode() in reply.body


# ---------------------------------------------------------------------
# token prefix
# ---------------------------------------------------------------------


@pytest.mark.parametrize("auth", [True, False])
def test_missing_token_prefix_is_404(dav: Dav, estate: Estate,
                                     auth: bool) -> None:
    """Without the exact token as first component: 404, no auth hint."""
    acct = estate.account_dir
    paths = [
        "/",
        f"/{acct}/",
        quote(estate.instance + "/describe.json", safe="/"),
        f"/{dav.token}x/",
        f"/x{dav.token}/{acct}/",
        f"/{dav.token[:-1]}/",
        f"/{acct}/{dav.token}/",
    ]
    for path in paths:
        reply = dav.get(path, auth=auth)
        assert reply.status == 404, path
        assert "www-authenticate" not in reply.headers, path
        reply = dav.propfind(path, depth="1", auth=auth)
        assert reply.status == 404, path


def test_wrong_token_beats_method_filter(dav: Dav) -> None:
    """Write methods on a foreign prefix are 404, not even 403."""
    reply = dav.request("PUT", "/not-the-token/x", body=b"x")
    assert reply.status == 404


# ---------------------------------------------------------------------
# read-only: write methods and infinite depth
# ---------------------------------------------------------------------


@pytest.mark.parametrize("method", WRITE_METHODS)
@pytest.mark.parametrize("target", ["file", "dir", "new"])
def test_write_methods_are_403(dav: Dav, estate: Estate, method: str,
                               target: str) -> None:
    """Every write method is refused on files, dirs and new paths."""
    if target == "file":
        vpath = estate.instance + "/describe.json"
    elif target == "dir":
        vpath = estate.instance
    else:
        vpath = estate.instance + "/new-file.txt"
    path = dav.url(vpath)
    headers = {"Destination":
               f"http://127.0.0.1:{dav.port}{dav.url('/copy')}",
               "Overwrite": "T"}
    body = b"<x/>" if method in ("LOCK", "PROPPATCH") else b"payload"
    reply = dav.request(method, path, headers=headers, body=body)
    assert reply.status == 403, (method, vpath)
    assert estate.vfs.read(estate.instance + "/describe.json")


@pytest.mark.parametrize("method", ["PUT", "DELETE", "MKCOL"])
def test_write_methods_are_403_without_auth(dav: Dav, estate: Estate,
                                            method: str) -> None:
    """The method filter refuses writes before authentication."""
    reply = dav.request(method, dav.url(estate.instance), body=b"x",
                        auth=False)
    assert reply.status == 403


@pytest.mark.parametrize("depth", ["infinity", "Infinity", " INFINITY ",
                                   "2", None])
def test_propfind_infinite_depth_is_403(dav: Dav, depth: str | None
                                        ) -> None:
    """Depth infinity (or a missing Depth header) is refused."""
    reply = dav.propfind(dav.base + "/", depth=depth)
    assert reply.status == 403
    assert b"propfind-finite-depth" in reply.body
    ET.fromstring(reply.body)


# ---------------------------------------------------------------------
# Host header
# ---------------------------------------------------------------------


def test_wrong_host_is_421(dav: Dav, estate: Estate) -> None:
    """Only 127.0.0.1:PORT and localhost:PORT are accepted."""
    other = dav.port + 1 if dav.port < 65535 else dav.port - 1
    hosts = [
        "evil.example",
        f"evil.example:{dav.port}",
        f"127.0.0.1:{other}",
        f"localhost:{other}",
        "127.0.0.1",
        "localhost",
        f"192.168.1.10:{dav.port}",
        f"127.0.0.2:{dav.port}",
        f"[::1]:{dav.port}",
    ]
    path = dav.url(estate.instance + "/describe.json")
    for host in hosts:
        reply = dav.get(path, host=host)
        assert reply.status == 421, host
        assert b"InstanceId" not in reply.body
    reply = dav.get("/", host="evil.example")
    assert reply.status == 421


def test_localhost_host_is_accepted(dav: Dav, estate: Estate) -> None:
    """``localhost:PORT`` is a valid Host."""
    path = dav.url(estate.instance + "/describe.json")
    reply = dav.get(path, host=f"localhost:{dav.port}")
    assert reply.status == 200
    reply = dav.get(path, host=f"LOCALHOST:{dav.port}")
    assert reply.status == 200


# ---------------------------------------------------------------------
# PROPFIND, HEAD, Range: sizes always match bodies
# ---------------------------------------------------------------------


def test_propfind_depth0_directory(dav: Dav, estate: Estate) -> None:
    """Depth 0 on a directory returns only that collection."""
    reply = dav.propfind(dav.url(estate.instance), depth="0")
    assert reply.status == 207
    entries = parse_multistatus(reply.body)
    assert len(entries) == 1
    (entry,) = entries.values()
    assert entry.is_dir
    assert dav.vpath(entry.href.rstrip("/")) == estate.instance


def test_propfind_depth0_file(dav: Dav, estate: Estate) -> None:
    """Depth 0 on a file reports its real length."""
    vpath = estate.instance + "/describe.json"
    reply = dav.propfind(dav.url(vpath), depth="0")
    assert reply.status == 207
    entries = parse_multistatus(reply.body)
    assert len(entries) == 1
    (entry,) = entries.values()
    assert not entry.is_dir
    body = dav.get(dav.url(vpath)).body
    assert entry.length == len(body) == len(estate.vfs.read(vpath))


def test_propfind_depth1_lengths_match_bodies(dav: Dav,
                                              estate: Estate) -> None:
    """Every member's getcontentlength equals its GET body length."""
    reply = dav.propfind(dav.url(estate.instance), depth="1")
    assert reply.status == 207
    entries = parse_multistatus(reply.body)
    own = dav.url(estate.instance).rstrip("/")
    members = {k: e for k, e in entries.items() if k != own}
    assert own in entries
    assert {e.name for e in members.values()} == set(
        estate.vfs.listdir(estate.instance))
    files = [e for e in members.values() if not e.is_dir]
    dirs = {e.name for e in members.values() if e.is_dir}
    assert {"describe.json", "state", "user-data"} <= {
        e.name for e in files}
    assert {"links", "tags"} <= dirs
    for entry in files:
        got = dav.get(entry.href)
        assert got.status == 200, entry.href
        assert entry.length == len(got.body), entry.href
        assert int(got.headers["content-length"]) == len(got.body)
        assert got.body == estate.vfs.read(dav.vpath(entry.href))


def test_head_matches_get(dav: Dav, estate: Estate) -> None:
    """HEAD has the GET headers and no body."""
    path = dav.url(estate.instance + "/describe.json")
    head = dav.request("HEAD", path)
    get = dav.get(path)
    assert head.status == 200
    assert head.body == b""
    assert int(head.headers["content-length"]) == len(get.body)
    assert head.headers.get("etag") == get.headers.get("etag")
    assert head.headers.get("etag")


def test_range_get(dav: Dav, estate: Estate) -> None:
    """Range requests slice the same rendered bytes."""
    vpath = estate.instance + "/describe.json"
    full = estate.vfs.read(vpath)
    assert len(full) > 20
    path = dav.url(vpath)
    reply = dav.get(path, headers={"Range": "bytes=5-14"})
    assert reply.status == 206
    assert reply.body == full[5:15]
    assert reply.headers["content-range"] == f"bytes 5-14/{len(full)}"
    assert int(reply.headers["content-length"]) == 10
    reply = dav.get(path, headers={"Range": "bytes=10-"})
    assert reply.status == 206
    assert reply.body == full[10:]


# ---------------------------------------------------------------------
# symlinks and redaction
# ---------------------------------------------------------------------


def test_symlink_served_as_file_with_relative_target(
        dav: Dav, estate: Estate) -> None:
    """A link is a text file containing ``<relative target>\\n``."""
    vpath = estate.instance + "/links/subnet"
    target = estate.vfs.readlink(vpath)
    assert not target.startswith("/")
    assert target == f"../../../../vpc/subnets/{estate.seed.subnet_public}"
    reply = dav.get(dav.url(vpath))
    assert reply.status == 200
    assert reply.body == (target + "\n").encode("utf-8")
    assert reply.headers["content-type"].startswith("text/plain")
    head = dav.request("HEAD", dav.url(vpath))
    assert int(head.headers["content-length"]) == len(reply.body)


def test_links_dir_listing(dav: Dav, estate: Estate) -> None:
    """In listings, links are non-collections with correct sizes."""
    links = estate.instance + "/links"
    reply = dav.propfind(dav.url(links), depth="1")
    assert reply.status == 207
    entries = parse_multistatus(reply.body)
    members = {e.name: e for k, e in entries.items()
               if k != dav.url(links).rstrip("/")}
    assert "subnet" in members and not members["subnet"].is_dir
    assert members["security-groups"].is_dir
    for entry in members.values():
        if entry.is_dir:
            continue
        expected = (estate.vfs.readlink(dav.vpath(entry.href))
                    + "\n").encode("utf-8")
        assert entry.length == len(expected)
        assert dav.get(entry.href).body == expected
    sgs = links + "/security-groups"
    reply = dav.propfind(dav.url(sgs), depth="1")
    sg_entries = parse_multistatus(reply.body)
    sg_files = [e for e in sg_entries.values() if not e.is_dir]
    assert estate.seed.sg_web in {e.name for e in sg_files}
    for entry in sg_files:
        body = dav.get(entry.href).body
        assert body.startswith(b"../")
        assert body.endswith(f"/{entry.name}\n".encode())


def test_paths_through_symlinks_do_not_exist(dav: Dav,
                                             estate: Estate) -> None:
    """In file mode, a symlink cannot be traversed."""
    links = estate.instance + "/links"
    assert dav.get(dav.url(links + "/subnet/describe.json")).status \
        == 404
    assert dav.get(dav.url(links + "/vpc/cidr")).status == 404
    # A trailing slash on a symlink-as-file may resolve to the file
    # itself, but it must never be presented as a traversable directory.
    slashed = dav.propfind(dav.url(links + "/vpc/"), depth="0")
    assert slashed.status in (207, 404)
    if slashed.status == 207:
        assert not any(e.is_dir for e in
                       parse_multistatus(slashed.body).values())
    assert dav.get(dav.url(links + "/subnet/../vpc")).status in (
        200, 404)


def test_user_data_redacted_over_webdav(dav: Dav,
                                        estate: Estate) -> None:
    """Whole-file redaction holds; the seeded secret never leaks."""
    secret = _load_seed().FAKE_SECRET.encode()
    reply = dav.get(dav.url(estate.instance + "/user-data"))
    assert reply.status == 200
    assert reply.body == (REDACTED + "\n").encode()
    assert secret not in reply.body
    listing = dav.propfind(dav.url(estate.instance), depth="1")
    assert secret not in listing.body


def test_escaped_tag_names_round_trip(dav: Dav, estate: Estate) -> None:
    """Escaped names (``team%2Fowner``) survive href quoting."""
    tags = estate.instance + "/tags"
    reply = dav.propfind(dav.url(tags), depth="1")
    assert reply.status == 207
    entries = parse_multistatus(reply.body)
    files = {e.name: e for e in entries.values() if not e.is_dir}
    assert set(files) == set(estate.vfs.listdir(tags))
    assert "team%2Fowner" in files
    for name, entry in files.items():
        got = dav.get(entry.href)
        assert got.status == 200, name
        assert got.body == estate.vfs.read(f"{tags}/{name}")
        assert entry.length == len(got.body)
    assert dav.get(files["team%2Fowner"].href).body == b"alice\n"
