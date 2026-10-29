"""The mount adapters over the secrets tree: FUSE operations, WebDAV.

The same adapters serve the normal tree. What matters here is what they
do with value files: sizes are not rendered (so ``ls -l`` and ``find``
read nothing), a read gives the exact bytes, a denied read is EACCES
(FUSE) or 401 (the macOS mount), and nothing can be written.
"""

from __future__ import annotations

import errno
import http.client
import os
import types
from collections.abc import Iterator
from typing import Any

import pytest

from awsmount.adapters.fuse.operations import AwsFuse, FuseOSError
from awsmount.secrets.session import SecretsSession
from awsmount.vfs.path import escape_name

from conftest import (  # type: ignore[import-not-found]
    BINARY,
    PLAIN,
    Estate,
    deny_op,
    value_reads,
)

pytest.importorskip("wsgidav")
pytest.importorskip("cheroot")

from awsmount.adapters.webdav.macos import (  # noqa: E402
    ACCESS_DENIED_STATUS,
)
from awsmount.adapters.webdav.server import WebDavServer  # noqa: E402

PROPFIND_BODY = (b'<?xml version="1.0" encoding="utf-8"?>\n'
                 b'<D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>\n')


def value_path(name: str) -> str:
    return f"/secretsmanager/{escape_name(name)}/value"


@pytest.fixture
def ops(session: SecretsSession) -> AwsFuse:
    return AwsFuse(session.vfs, lazy_size="zero")


def open_raw(ops: AwsFuse, path: str) -> tuple[Any, Any]:
    fi = types.SimpleNamespace(flags=os.O_RDONLY, fh=0, direct_io=False,
                               keep_cache=True)
    ops.open(path, fi)
    return fi.fh, fi


# --------------------------------------------------------------- FUSE


def test_fuse_getattr_of_a_value_is_zero_bytes_and_reads_nothing(
        session: SecretsSession, estate: Estate, ops: AwsFuse,
        op_log: list[tuple[str, str]]) -> None:
    attrs = ops.getattr(value_path(estate.plain))
    assert attrs["st_size"] == 0
    assert attrs["st_mode"] & 0o777 == 0o400
    assert ops.getattr("/ssm")["st_mode"] & 0o777 == 0o500
    assert value_reads(op_log) == []


def test_fuse_readdir_never_reads_a_value(
        session: SecretsSession, estate: Estate, ops: AwsFuse,
        op_log: list[tuple[str, str]]) -> None:
    for directory in ("/", "/secretsmanager", "/ssm", "/ssm/app",
                      f"/secretsmanager/{escape_name(estate.json)}",
                      f"/secretsmanager/{escape_name(estate.json)}"
                      "/versions"):
        names = [e[0] if isinstance(e, tuple) else e
                 for e in ops.readdir(directory)]
        assert "." in names and ".." in names
    assert value_reads(op_log) == []


def test_fuse_open_uses_direct_io_and_returns_the_exact_bytes(
        session: SecretsSession, estate: Estate, ops: AwsFuse) -> None:
    handle, fi = open_raw(ops, value_path(estate.binary))
    assert fi.direct_io is True
    assert not fi.keep_cache
    data = ops.read(value_path(estate.binary), 1 << 16, 0, handle)
    assert data == BINARY
    assert ops.read(value_path(estate.binary), 3, 1, handle) == BINARY[1:4]
    ops.release(value_path(estate.binary), handle)
    assert ops.getattr(value_path(estate.binary))["st_size"] == len(BINARY)


def test_fuse_denied_read_is_eacces(session: SecretsSession,
                                    estate: Estate, ops: AwsFuse) -> None:
    deny_op(session, "secretsmanager", "GetSecretValue")
    with pytest.raises(FuseOSError) as caught:
        open_raw(ops, value_path(estate.plain))
    assert caught.value.errno == errno.EACCES


def test_fuse_vanished_secret_is_enoent(session: SecretsSession,
                                        estate: Estate, ops: AwsFuse,
                                        moto_aws: None) -> None:
    import boto3
    ops.readdir(f"/secretsmanager/{escape_name(estate.plain)}")
    boto3.client("secretsmanager", region_name="us-east-1").delete_secret(
        SecretId=estate.plain, ForceDeleteWithoutRecovery=True)
    with pytest.raises(FuseOSError) as caught:
        open_raw(ops, value_path(estate.plain))
    assert caught.value.errno == errno.ENOENT


@pytest.mark.parametrize("method, args", [
    ("write", ("/ssm/toplevel", b"x", 0, 0)),
    ("create", ("/ssm/new", 0o644)),
    ("unlink", ("/ssm/toplevel",)),
    ("truncate", ("/ssm/toplevel", 0)),
    ("rename", ("/ssm/toplevel", "/ssm/other")),
    ("mkdir", ("/ssm/dir", 0o755)),
    ("chmod", ("/ssm/toplevel", 0o777)),
])
def test_fuse_cannot_write_to_the_secrets_tree(
        session: SecretsSession, ops: AwsFuse, method: str,
        args: tuple[Any, ...]) -> None:
    with pytest.raises(FuseOSError) as caught:
        getattr(ops, method)(*args)
    assert caught.value.errno == errno.EROFS


# ------------------------------------------------------------- WebDAV


class Dav:
    """A cheroot server over the secrets tree and a request helper."""

    def __init__(self, session: SecretsSession, *, mount: bool) -> None:
        kwargs: dict[str, Any] = {}
        if mount:
            kwargs["denied_status"] = ACCESS_DENIED_STATUS
        self.server = WebDavServer(session.vfs, port=0, **kwargs)
        self.server.start()

    def request(self, method: str, path: str, depth: str = "0"
                ) -> tuple[int, bytes]:
        headers = {"Authorization":
                   self.server.credentials.basic_header()}
        body = None
        if method == "PROPFIND":
            headers["Depth"] = depth
            headers["Content-Type"] = "application/xml; charset=utf-8"
            body = PROPFIND_BODY
        conn = http.client.HTTPConnection("127.0.0.1", self.server.port,
                                          timeout=30)
        try:
            conn.request(method, f"/{self.server.credentials.token}"
                         f"{path}", body=body, headers=headers)
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()


@pytest.fixture
def dav(session: SecretsSession) -> Iterator[Dav]:
    server = Dav(session, mount=True)
    try:
        yield server
    finally:
        server.server.stop()


def test_webdav_listing_reads_no_value(
        dav: Dav, estate: Estate, op_log: list[tuple[str, str]]) -> None:
    for path in ("/", "/secretsmanager", "/ssm", "/ssm/app/db"):
        status, _body = dav.request("PROPFIND", path, depth="1")
        assert status == 207, path
    status, body = dav.request(
        "PROPFIND", f"/secretsmanager/{escape_name(estate.plain)}",
        depth="1")
    assert status == 207
    assert PLAIN.encode() not in body
    assert value_reads(op_log) == []


def test_webdav_get_returns_the_exact_bytes(dav: Dav,
                                            estate: Estate) -> None:
    status, body = dav.request("GET", value_path(estate.binary))
    assert (status, body) == (200, BINARY)
    status, body = dav.request("GET", "/ssm/app/db/password")
    assert status == 200 and body.startswith(b"CANARY-")


def test_webdav_denied_read_is_401_on_the_mount_server(
        session: SecretsSession, dav: Dav, estate: Estate) -> None:
    deny_op(session, "secretsmanager", "GetSecretValue")
    status, body = dav.request("GET", value_path(estate.plain))
    assert status == 401
    assert PLAIN.encode() not in body


def test_webdav_refuses_every_write(dav: Dav) -> None:
    for method in ("PUT", "DELETE", "MKCOL", "MOVE", "COPY", "PROPPATCH"):
        status, _body = dav.request(method, "/ssm/toplevel")
        assert status in (403, 405, 400, 501), (method, status)
