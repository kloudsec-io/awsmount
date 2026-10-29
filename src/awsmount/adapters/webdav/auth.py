"""Per-session WebDAV credentials (ARCHITECTURE: WebDAV).

A fresh URL token, user name and password are generated for every
session.

The **password** is the secret that keeps other local users out of the
account. It lives only in memory: it is never written to disk, never
put in argv and never put in the environment.

The URL token is **not a secret**. On macOS it is part of the share URL
passed in argv to ``/sbin/mount_webdav``, so every local user can see
it with ``ps`` during the handshake, and it stays visible afterwards in
``mount``/``df`` output; ``awsmount serve`` prints it too. It only
scopes the share path (stray requests get a cheap 404). HTTP
authentication is therefore always required in addition to the token,
and the token alone never grants access.
"""

from __future__ import annotations

import base64
import hmac
import secrets
from dataclasses import dataclass, field

__all__ = ["DEFAULT_USER", "Credentials", "generate_credentials"]

DEFAULT_USER = "awsmount"


@dataclass(frozen=True)
class Credentials:
    """URL token (not secret) plus Basic/Digest user and password.

    Only the password is secret; it is excluded from ``repr``.
    """

    token: str
    user: str
    password: str = field(repr=False)

    @classmethod
    def generate(cls, user: str = DEFAULT_USER) -> Credentials:
        """Create fresh random credentials for one session."""
        # The token must be lowercase: wsgidav matches share names through
        # a lowercased lookup, so mixed-case tokens never resolve.
        return cls(token=secrets.token_hex(24), user=user,
                   password=secrets.token_urlsafe(32))

    @property
    def prefix(self) -> str:
        """The share path, ``/<token>``."""
        return f"/{self.token}"

    def basic_header(self) -> str:
        """Value of an ``Authorization`` header for Basic auth."""
        raw = f"{self.user}:{self.password}".encode("utf-8")
        return "Basic " + base64.b64encode(raw).decode("ascii")

    def check_basic(self, header: str | None) -> bool:
        """True when ``header`` carries exactly these credentials."""
        if not header:
            return False
        expected = self.basic_header().encode("utf-8")
        given = header.strip().encode("utf-8", "replace")
        return hmac.compare_digest(expected, given)

    def check_token(self, candidate: str) -> bool:
        """Constant-time comparison of a URL path component."""
        given = candidate.encode("utf-8", "replace")
        return hmac.compare_digest(self.token.encode("ascii"), given)


def generate_credentials(user: str = DEFAULT_USER) -> Credentials:
    """Create fresh random credentials for one session."""
    return Credentials.generate(user)
