"""Exception hierarchy with errno mapping (ARCHITECTURE: Errors)."""

from __future__ import annotations

import errno as _errno
import os

__all__ = [
    "AwsMountError",
    "BudgetExceeded",
    "ForbiddenOperation",
    "IsADirectory",
    "NotADirectory",
    "NotALink",
    "NotFound",
    "PermissionDenied",
    "ReadOnly",
    "SymlinkLoop",
    "UpstreamError",
    "errno_of",
]


class AwsMountError(Exception):
    """Base class of every awsmount error; maps to EIO."""

    errno: int = _errno.EIO

    def __init__(self, message: str = "") -> None:
        super().__init__(message)
        self.message = message

    @property
    def strerror(self) -> str:
        """Return the C library description of :attr:`errno`."""
        return os.strerror(self.errno)

    def __str__(self) -> str:
        return self.message or self.strerror


class NotFound(AwsMountError):
    """A path does not exist."""

    errno = _errno.ENOENT


class NotADirectory(AwsMountError):
    """A path traverses through a non-directory."""

    errno = _errno.ENOTDIR


class IsADirectory(AwsMountError):
    """A directory was read as a file."""

    errno = _errno.EISDIR


class SymlinkLoop(AwsMountError):
    """More than 40 symlink expansions during resolution."""

    errno = _errno.ELOOP


class NotALink(AwsMountError):
    """``readlink`` was called on something that is not a symlink."""

    errno = _errno.EINVAL


class ReadOnly(AwsMountError):
    """Any write intent on the read-only filesystem."""

    errno = _errno.EROFS


class BudgetExceeded(AwsMountError):
    """The global API-call budget is exhausted."""

    errno = _errno.EIO


class ForbiddenOperation(AwsMountError):
    """The read-only guard refused an AWS operation (a bug)."""

    errno = _errno.EPERM


class UpstreamError(AwsMountError):
    """An AWS or endpoint failure, already classified."""

    errno = _errno.EIO

    def __init__(self, message: str = "", *, code: str | None = None,
                 kind: str | None = None, service: str | None = None,
                 op: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.kind = kind
        self.service = service
        self.op = op


class PermissionDenied(UpstreamError):
    """AccessDenied surfaced on a lazy file."""

    errno = _errno.EACCES


def errno_of(exc: BaseException) -> int:
    """Return the errno that best represents ``exc``."""
    if isinstance(exc, AwsMountError):
        return exc.errno
    if isinstance(exc, OSError) and exc.errno:
        return int(exc.errno)
    return _errno.EIO
