"""Error classification and errors.log (ARCHITECTURE: Error log)."""

from __future__ import annotations

import errno
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

import pytest
from botocore.exceptions import (
    ConnectTimeoutError,
    EndpointConnectionError,
    NoCredentialsError,
    ReadTimeoutError,
)

from awsmount.errors import (
    AwsMountError,
    BudgetExceeded,
    PermissionDenied,
    UpstreamError,
)
from awsmount.session.accounts import AccountInfo
from awsmount.session.context import Scope
from awsmount.session.errorlog import ErrorKind, ErrorLog, classify
from awsmount.vfs.resolver import VFS


def _fields(log: ErrorLog, account: str | None = None) -> list[list[str]]:
    text = log.render(account).decode("utf-8")
    return [line.split("\t") for line in text.splitlines()]


def _other_scope(account: AccountInfo) -> Scope:
    other = AccountInfo(
        profile="prod", account_id="210987654321", aliases=(),
        partition="aws", dirname="210987654321", regions=("eu-west-1",),
        global_region="us-east-1", identity=None, error=None)
    assert other.account_id != account.account_id
    return Scope(other, "eu-west-1", False)


def test_tsv_format(clock: Any, scope: Scope,
                    aws_error: Callable[..., Any]) -> None:
    """8 TSV fields: time, account, region, service, op, kind, code, msg."""
    clock.now = 0.0
    log = ErrorLog(clock=clock)
    log.record(scope, "lambda", "list_functions",
               aws_error("AccessDenied", "ListFunctions", "nope"))
    rows = _fields(log)
    assert len(rows) == 1
    row = rows[0]
    assert len(row) == 8
    stamp = datetime.fromisoformat(row[0].replace("Z", "+00:00"))
    assert stamp == datetime(1970, 1, 1, tzinfo=timezone.utc)
    assert row[0].endswith(("Z", "+00:00"))
    assert row[1:7] == ["123456789012", "us-east-1", "lambda",
                        "list_functions", "access-denied",
                        "AccessDenied"]
    assert "nope" in row[7]


def test_scope_none_uses_dashes(clock: Any) -> None:
    """No scope -> '-' account and region."""
    log = ErrorLog(clock=clock)
    log.record(None, "awsmount", "budget", BudgetExceeded("over"))
    row = _fields(log)[0]
    assert row[1] == "-" and row[2] == "-"
    assert row[5] == "budget"


def test_message_newlines_and_tabs_flattened(clock: Any,
                                             scope: Scope) -> None:
    """Messages never break the one-line, 8-field format."""
    log = ErrorLog(clock=clock)
    log.record(scope, "s3", "op",
               UpstreamError("line1\nline2\tx\ry", code="X",
                             kind="other"))
    rendered = log.render().decode()
    assert rendered.count("\n") == 1
    assert len(rendered.rstrip("\n").split("\t")) == 8


def test_collapse_identical_entries(clock: Any, scope: Scope,
                                    aws_error: Callable[..., Any]) -> None:
    """Identical entries within 60 s collapse into '(xN)'."""
    log = ErrorLog(clock=clock)
    for _ in range(3):
        log.record(scope, "ec2", "describe_instances",
                   aws_error("Throttling"))
        clock.advance(10)
    assert log.count() == 1
    assert log.render().decode().rstrip("\n").endswith("(x3)")
    clock.advance(61)
    log.record(scope, "ec2", "describe_instances", aws_error("Throttling"))
    assert log.count() == 2


def test_different_codes_not_collapsed(clock: Any, scope: Scope,
                                       aws_error: Callable[..., Any]
                                       ) -> None:
    """Different codes (or ops) are separate lines."""
    log = ErrorLog(clock=clock)
    log.record(scope, "ec2", "op", aws_error("Throttling"))
    log.record(scope, "ec2", "op", aws_error("AccessDenied"))
    log.record(scope, "ec2", "op2", aws_error("AccessDenied"))
    assert log.count() == 3
    assert "(x" not in log.render().decode()


def test_ring_buffer(clock: Any, scope: Scope,
                     aws_error: Callable[..., Any]) -> None:
    """Only the newest max_entries lines are kept."""
    log = ErrorLog(max_entries=3, clock=clock)
    for i in range(5):
        log.record(scope, "svc", f"op{i}", aws_error("X"))
    assert log.count() == 3
    ops = [row[4] for row in _fields(log)]
    assert ops == ["op2", "op3", "op4"]


def test_account_filter(clock: Any, scope: Scope, account: AccountInfo,
                        aws_error: Callable[..., Any]) -> None:
    """render(account_id) keeps only that account's lines."""
    log = ErrorLog(clock=clock)
    log.record(scope, "svc", "mine", aws_error("X"))
    log.record(_other_scope(account), "svc", "theirs", aws_error("X"))
    log.record(None, "svc", "nobody", aws_error("X"))
    assert [r[4] for r in _fields(log, "123456789012")] == ["mine"]
    assert [r[4] for r in _fields(log, "210987654321")] == ["theirs"]
    assert len(_fields(log)) == 3


def test_empty_render(clock: Any) -> None:
    """No entries -> empty bytes."""
    log = ErrorLog(clock=clock)
    assert log.render() == b""
    assert log.count() == 0


def test_echo(clock: Any, scope: Scope,
              aws_error: Callable[..., Any]) -> None:
    """echo receives new lines (verbose mode)."""
    lines: list[str] = []
    log = ErrorLog(echo=lines.append, clock=clock)
    log.record(scope, "svc", "visible_op", aws_error("AccessDenied"))
    assert len(lines) == 1
    assert "visible_op" in lines[0]


@pytest.mark.parametrize("code, kind", [
    ("AccessDenied", ErrorKind.ACCESS_DENIED),
    ("AccessDeniedException", ErrorKind.ACCESS_DENIED),
    ("UnauthorizedOperation", ErrorKind.ACCESS_DENIED),
    ("AuthorizationError", ErrorKind.ACCESS_DENIED),
    ("Forbidden", ErrorKind.ACCESS_DENIED),
    ("OptInRequired", ErrorKind.ACCESS_DENIED),
    ("UnrecognizedClientException", ErrorKind.ACCESS_DENIED),
    ("InvalidClientTokenId", ErrorKind.ACCESS_DENIED),
    ("AuthFailure", ErrorKind.ACCESS_DENIED),
    ("ResourceNotFoundException", ErrorKind.NOT_FOUND),
    ("NoSuchEntity", ErrorKind.NOT_FOUND),
    ("NotFoundException", ErrorKind.NOT_FOUND),
    ("NoSuchBucket", ErrorKind.NOT_FOUND),
    ("InvalidVpcID.NotFound", ErrorKind.NOT_FOUND),
    ("DBInstanceNotFound", ErrorKind.NOT_FOUND),
    ("NoSuchBucketPolicy", ErrorKind.NOT_CONFIGURED),
    ("ServerSideEncryptionConfigurationNotFoundError",
     ErrorKind.NOT_CONFIGURED),
    ("NoSuchPublicAccessBlockConfiguration", ErrorKind.NOT_CONFIGURED),
    ("NoSuchTagSet", ErrorKind.NOT_CONFIGURED),
    ("AWSOrganizationsNotInUseException", ErrorKind.NOT_CONFIGURED),
    ("Throttling", ErrorKind.THROTTLED),
    ("ThrottlingException", ErrorKind.THROTTLED),
    ("RequestLimitExceeded", ErrorKind.THROTTLED),
    ("TooManyRequestsException", ErrorKind.THROTTLED),
    ("ValidationError", ErrorKind.OTHER),
    ("InternalError", ErrorKind.OTHER),
])
def test_classify_client_errors(code: str, kind: ErrorKind,
                                aws_error: Callable[..., Any]) -> None:
    """The error code table of ``errorlog.py``."""
    assert classify(aws_error(code)) is kind


@pytest.mark.parametrize("exc, kind", [
    (NoCredentialsError(), ErrorKind.ACCESS_DENIED),
    (EndpointConnectionError(endpoint_url="http://127.0.0.1:9"),
     ErrorKind.ENDPOINT),
    (ConnectTimeoutError(endpoint_url="http://127.0.0.1:9"),
     ErrorKind.ENDPOINT),
    (ReadTimeoutError(endpoint_url="http://127.0.0.1:9"),
     ErrorKind.ENDPOINT),
    (BudgetExceeded("x"), ErrorKind.BUDGET),
    (PermissionDenied("x"), ErrorKind.ACCESS_DENIED),
    (UpstreamError("x", code="Foo", kind="throttled"),
     ErrorKind.THROTTLED),
    (ValueError("x"), ErrorKind.OTHER),
])
def test_classify_exceptions(exc: BaseException, kind: ErrorKind) -> None:
    """Non-ClientError exceptions."""
    assert classify(exc) is kind


# ---------------------------------------------------------------------
# failure surfacing through the tree
# ---------------------------------------------------------------------


def _log_lines(vfs: VFS, fake: Any) -> list[str]:
    data = vfs.read(f"/{fake.account_id}/_meta/errors.log")
    return data.decode().splitlines()


def test_access_denied_listing_degrades(vfs: VFS, backend: Any,
                                        fake: Any,
                                        fail_with: Callable[..., Any]
                                        ) -> None:
    """AccessDenied on a list: empty dir + one log line; rest serves."""
    backend.on_pages("fake", "list_gadgets",
                     fail_with("AccessDenied", "ListGadgets"))
    assert vfs.listdir(f"{fake.base}/gadgets") == []
    assert vfs.listdir(f"{fake.base}/widgets") == ["w-1", "w-2", "w-3"]
    assert vfs.listdir(f"{fake.base}/widgets/w-1/links") == []
    assert b"red" in vfs.read(f"{fake.base}/widgets/w-1/describe.json")
    lines = _log_lines(vfs, fake)
    assert len(lines) == 1
    fields = lines[0].split("\t")
    assert len(fields) == 8
    assert fields[1] == fake.account_id
    assert fields[2] == fake.region
    assert fields[5] == "access-denied"
    assert fields[6] == "AccessDenied"


def test_not_configured_listing_silent(vfs: VFS, backend: Any,
                                       fake: Any,
                                       fail_with: Callable[..., Any]
                                       ) -> None:
    """NOT_CONFIGURED on a list: empty dir, nothing logged."""
    backend.on_pages("fake", "list_gadgets",
                     fail_with("AWSOrganizationsNotInUseException"))
    assert vfs.listdir(f"{fake.base}/gadgets") == []
    assert _log_lines(vfs, fake) == []


def test_lazy_access_denied_is_eacces(vfs: VFS, backend: Any, fake: Any,
                                      fail_with: Callable[..., Any]
                                      ) -> None:
    """Lazy file AccessDenied -> PermissionDenied (EACCES) + log."""
    backend.on("fake", "get_widget_details", fail_with("AccessDenied"))
    with pytest.raises(PermissionDenied) as info:
        vfs.read(f"{fake.base}/widgets/w-1/details.json")
    assert info.value.errno == errno.EACCES
    lines = _log_lines(vfs, fake)
    assert len(lines) == 1
    assert "\taccess-denied\t" in lines[0]


def test_lazy_not_found_is_null(vfs: VFS, backend: Any, fake: Any,
                                fail_with: Callable[..., Any]) -> None:
    """Lazy file NOT_FOUND -> 'null' + log."""
    backend.on("fake", "get_widget_details",
               fail_with("ResourceNotFoundException"))
    assert vfs.read(f"{fake.base}/widgets/w-1/details.json") == b"null\n"
    lines = _log_lines(vfs, fake)
    assert len(lines) == 1
    assert "\tnot-found\t" in lines[0]


def test_lazy_not_configured_is_silent_null(vfs: VFS, backend: Any,
                                            fake: Any,
                                            fail_with: Callable[..., Any]
                                            ) -> None:
    """Lazy file NOT_CONFIGURED -> 'null', not logged."""
    backend.on("fake", "get_widget_details",
               fail_with("NoSuchBucketPolicy"))
    assert vfs.read(f"{fake.base}/widgets/w-1/details.json") == b"null\n"
    assert _log_lines(vfs, fake) == []


def test_lazy_other_is_eio(vfs: VFS, backend: Any, fake: Any,
                           fail_with: Callable[..., Any]) -> None:
    """Lazy file other failure -> EIO + log."""
    backend.on("fake", "get_widget_details", fail_with("ValidationError"))
    with pytest.raises(AwsMountError) as info:
        vfs.read(f"{fake.base}/widgets/w-1/details.json")
    assert info.value.errno == errno.EIO
    assert not isinstance(info.value, PermissionDenied)
    lines = _log_lines(vfs, fake)
    assert len(lines) == 1
    assert "\tother\t" in lines[0]
