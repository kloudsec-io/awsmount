"""Immutable runtime configuration (ARCHITECTURE: Configuration)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

__all__ = ["Config", "LazySize", "RESERVED_REGION_NAMES", "parse_services"]

LazySize = Literal["render", "zero"]

REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d+$")
"""Shape of an AWS region name (``us-east-1``, ``us-gov-west-1``...)."""

RESERVED_REGION_NAMES = frozenset({"global", "_meta"})
"""Account directory entries that a region name must never shadow."""


@dataclass(frozen=True)
class Config:
    """Every tunable of one awsmount session.

    ``lazy_size`` only affects FUSE mounts: ``zero`` (the default)
    reports unrendered lazy files with size 0 and opens them with
    ``direct_io``, so metadata operations (``find``, ``ls -l``) never
    make API calls. WebDAV mounts always report 0 for unrendered lazy
    files; the shell always renders them.
    """

    profiles: tuple[str | None, ...] = (None,)
    regions: tuple[str, ...] = ()
    endpoint_url: str | None = None
    reveal: bool = False
    ttl: float = 60.0
    negative_ttl: float = 10.0
    max_api_calls: int = 0
    budget_window: float = 600.0
    concurrency: int = 4
    global_concurrency: int = 16
    max_attempts: int = 10
    connect_timeout: float = 10.0
    read_timeout: float = 30.0
    s3_objects: int = 0
    services: frozenset[str] | None = None
    verbose: bool = False
    color: bool | None = None
    lazy_size: LazySize = "zero"

    def __post_init__(self) -> None:
        self.validate()

    @staticmethod
    def _region_problem(region: str) -> str | None:
        """Why ``region`` is not usable, or None when it is."""
        if not region or not region.strip():
            return "empty region name"
        if region == "all":
            return None
        if region in RESERVED_REGION_NAMES:
            return f"region name {region!r} is reserved"
        if "/" in region:
            return f"region name {region!r} must not contain '/'"
        if not REGION_RE.match(region):
            return f"invalid region name {region!r}"
        return None

    def validate(self) -> None:
        """Raise ``ValueError`` listing every invalid setting."""
        problems: list[str] = []
        if not self.profiles:
            problems.append("at least one profile entry is required")
        for region in self.regions:
            problem = self._region_problem(region)
            if problem is not None:
                problems.append(problem)
        if self.ttl < 0:
            problems.append("ttl must be >= 0")
        if self.negative_ttl < 0:
            problems.append("negative_ttl must be >= 0")
        if self.max_api_calls < 0:
            problems.append("max_api_calls must be >= 0")
        if self.budget_window < 0:
            problems.append("budget_window must be >= 0")
        if self.concurrency < 1:
            problems.append("concurrency must be >= 1")
        if self.global_concurrency < 1:
            problems.append("global_concurrency must be >= 1")
        if self.max_attempts < 1:
            problems.append("max_attempts must be >= 1")
        if self.connect_timeout <= 0 or self.read_timeout <= 0:
            problems.append("timeouts must be > 0")
        if self.s3_objects < 0:
            problems.append("s3_objects must be >= 0")
        if self.lazy_size not in ("render", "zero"):
            problems.append("lazy_size must be 'render' or 'zero'")
        if problems:
            raise ValueError("; ".join(problems))

    @property
    def all_regions(self) -> bool:
        """True when ``--region all`` was requested."""
        return "all" in self.regions

    def service_enabled(self, dirname: str) -> bool:
        """True when the service directory ``dirname`` is mounted."""
        return self.services is None or dirname in self.services


def parse_services(text: str | None) -> frozenset[str] | None:
    """Parse a ``--services`` comma list; empty means all services."""
    if text is None:
        return None
    names = frozenset(p.strip() for p in text.split(",") if p.strip())
    return names or None
