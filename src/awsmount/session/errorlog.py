"""Error classification and the errors.log ring buffer.

See ARCHITECTURE: Error log.
"""

from __future__ import annotations

import enum
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from botocore.exceptions import (
    ClientError,
    ConnectTimeoutError,
    EndpointConnectionError,
    NoCredentialsError,
    ReadTimeoutError,
)

from awsmount.errors import BudgetExceeded, PermissionDenied, UpstreamError

if TYPE_CHECKING:
    from awsmount.session.context import Scope

__all__ = [
    "ACCESS_DENIED_CODES",
    "ErrorKind",
    "ErrorLog",
    "NOT_CONFIGURED_CODES",
    "NOT_FOUND_CODES",
    "THROTTLED_CODES",
    "UNSCOPED",
    "classify",
    "error_code",
    "label_for",
]

COLLAPSE_SECONDS = 60.0
MAX_MESSAGE = 1000
UNSCOPED = "-"
"""Account column of session-wide entries (e.g. budget exhaustion)."""


class ErrorKind(enum.Enum):
    """Classification of an upstream failure."""

    ACCESS_DENIED = "access-denied"
    NOT_FOUND = "not-found"
    NOT_CONFIGURED = "not-configured"
    THROTTLED = "throttled"
    BUDGET = "budget"
    ENDPOINT = "endpoint"
    OTHER = "other"


ACCESS_DENIED_CODES = frozenset({
    "AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
    "AuthorizationError", "Forbidden", "OptInRequired",
    "UnrecognizedClientException", "InvalidClientTokenId", "AuthFailure",
    "NoCredentialsError", "403",
})
NOT_FOUND_CODES = frozenset({
    "ResourceNotFoundException", "NoSuchEntity", "NotFoundException",
    "NoSuchBucket", "404",
})
NOT_CONFIGURED_CODES = frozenset({
    "NoSuchBucketPolicy",
    "ServerSideEncryptionConfigurationNotFoundError",
    "NoSuchPublicAccessBlockConfiguration", "NoSuchTagSet",
    "AWSOrganizationsNotInUseException",
})
THROTTLED_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "TooManyRequestsException",
})


def error_code(exc: BaseException) -> str:
    """Return the AWS error code, or the exception type name."""
    if isinstance(exc, UpstreamError) and exc.code:
        return exc.code
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code")
        return str(code) if code else "ClientError"
    return type(exc).__name__


def classify(exc: BaseException) -> ErrorKind:
    """Classify an exception into its :class:`ErrorKind`."""
    if isinstance(exc, BudgetExceeded):
        return ErrorKind.BUDGET
    if isinstance(exc, UpstreamError) and exc.kind:
        try:
            return ErrorKind(exc.kind)
        except ValueError:
            pass
    if isinstance(exc, PermissionDenied):
        return ErrorKind.ACCESS_DENIED
    if isinstance(exc, NoCredentialsError):
        return ErrorKind.ACCESS_DENIED
    if isinstance(exc, (EndpointConnectionError, ConnectTimeoutError,
                        ReadTimeoutError)):
        return ErrorKind.ENDPOINT
    code = error_code(exc)
    if code in NOT_CONFIGURED_CODES:
        return ErrorKind.NOT_CONFIGURED
    if code in ACCESS_DENIED_CODES:
        return ErrorKind.ACCESS_DENIED
    if code in THROTTLED_CODES:
        return ErrorKind.THROTTLED
    if code in NOT_FOUND_CODES or code.endswith("NotFound"):
        return ErrorKind.NOT_FOUND
    return ErrorKind.OTHER


def label_for(account: Any) -> str:
    """errors.log account column for an AccountInfo-like object."""
    account_id = getattr(account, "account_id", None)
    if account_id:
        return str(account_id)
    profile = getattr(account, "profile", None)
    return f"profile:{profile or 'default'}"


def _clean(text: str) -> str:
    flat = text.replace("\t", " ").replace("\r", " ").replace("\n", " ")
    return flat[:MAX_MESSAGE]


@dataclass
class _Line:
    first: float
    last: float
    account: str
    region: str
    service: str
    op: str
    kind: ErrorKind
    code: str
    message: str
    count: int = 1
    alive: bool = True

    @property
    def ident(self) -> tuple[str, str, str, str, str]:
        return (self.account, self.region, self.service, self.op,
                self.code)

    def render(self) -> str:
        stamp = datetime.fromtimestamp(self.first, timezone.utc)
        message = self.message
        if self.count > 1:
            message = f"{message} (x{self.count})"
        return "\t".join([stamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
                          self.account, self.region, self.service,
                          self.op, self.kind.value, self.code, message])


class ErrorLog:
    """Ring buffer of classified errors rendered as TSV."""

    def __init__(self, max_entries: int = 2000,
                 echo: Callable[[str], None] | None = None, *,
                 clock: Callable[[], float] = time.time) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be >= 1")
        self._max = max_entries
        self._echo = echo
        self._clock = clock
        self._lock = threading.Lock()
        self._lines: deque[_Line] = deque()
        self._index: dict[tuple[str, str, str, str, str], _Line] = {}

    def record(self, scope: Scope | None, service: str, op: str,
               exc: BaseException, *, account: str | None = None) -> None:
        """Record one failure; identical entries within 60 s collapse."""
        if account is None:
            account = (label_for(scope.account) if scope is not None
                       else UNSCOPED)
        region = scope.region if scope is not None else "-"
        kind = classify(exc)
        code = error_code(exc)
        now = self._clock()
        text: str | None = None
        with self._lock:
            ident = (account, region, service, op, code)
            line = self._index.get(ident)
            if (line is not None and line.alive
                    and now - line.last <= COLLAPSE_SECONDS):
                line.count += 1
                line.last = now
                return
            line = _Line(now, now, account, region, service, op, kind,
                         code, _clean(str(exc)))
            if len(self._lines) >= self._max:
                old = self._lines.popleft()
                old.alive = False
                if self._index.get(old.ident) is old:
                    del self._index[old.ident]
            self._lines.append(line)
            self._index[ident] = line
            text = line.render()
        if self._echo is not None and text is not None:
            self._echo(text)

    def render(self, account_id: str | None = None, *,
               include_unscoped: bool = False) -> bytes:
        """TSV lines, optionally filtered by account label.

        With ``include_unscoped``, session-wide rows (account ``-``,
        such as budget exhaustion) are kept by the account filter.
        """
        with self._lock:
            rows = [line.render() for line in self._lines
                    if account_id is None or line.account == account_id
                    or (include_unscoped and line.account == UNSCOPED)]
        if not rows:
            return b""
        return ("\n".join(rows) + "\n").encode("utf-8")

    def count(self) -> int:
        """Number of lines currently held."""
        with self._lock:
            return len(self._lines)
