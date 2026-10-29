"""Moto-backed helpers shared by the provider test modules.

The ``test_<service>.py`` modules load this file by path (see their
``_load_kit``), so it works whatever pytest import mode is configured.
It loads ``tests/fixtures/seed.py`` by path in the same way.

Fixtures are module-scoped: one in-process ``mock_aws`` backend is
started and seeded per test module. Every test builds its own
:class:`Mount`, i.e. a fresh awsmount Context (cache, budget, error
log) over that backend. awsmount never writes to AWS, so tests cannot
disturb each other.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from awsmount.config import Config
from awsmount.providers.base import CollectionRef
from awsmount.session.context import Context
from awsmount.tree.root import build_vfs
from awsmount.vfs import walk as vwalk

__all__ = [
    "ENV",
    "FAKE_SECRET",
    "Mount",
    "REGION",
    "compute",
    "load_by_path",
    "management",
    "moto_session",
    "seed",
]


def load_by_path(name: str, path: Path) -> ModuleType:
    """Import ``path`` as module ``name`` once (cached in sys.modules)."""
    module = sys.modules.get(name)
    if module is not None:
        return module
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        del sys.modules[name]
        raise
    return module


seed = load_by_path(
    "awsmount_tests_seed",
    Path(__file__).resolve().parents[1] / "fixtures" / "seed.py")

REGION: str = seed.REGION
FAKE_SECRET: str = seed.FAKE_SECRET

ENV: dict[str, str] = {
    "AWS_ACCESS_KEY_ID": "testing",
    "AWS_SECRET_ACCESS_KEY": "testing",
    "AWS_SECURITY_TOKEN": "testing",
    "AWS_SESSION_TOKEN": "testing",
    "AWS_DEFAULT_REGION": REGION,
    "AWS_CONFIG_FILE": os.devnull,
    "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
}
UNSET_ENV = ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ENDPOINT_URL")

# Bounded retries: an operation moto does not implement must fail fast.
MOUNT_DEFAULTS: dict[str, Any] = {
    "regions": (REGION,),
    "max_attempts": 2,
    "connect_timeout": 5.0,
    "read_timeout": 15.0,
}


@pytest.fixture(scope="module")
def moto_session() -> Iterator[boto3.Session]:
    """An in-process moto backend shared by one test module."""
    with pytest.MonkeyPatch.context() as patch:
        for name, value in ENV.items():
            patch.setenv(name, value)
        for name in UNSET_ENV:
            patch.delenv(name, raising=False)
        with mock_aws():
            yield boto3.Session(region_name=REGION)


@pytest.fixture(scope="module")
def compute(moto_session: boto3.Session) -> Any:
    """The seeded compute estate (EC2/VPC included)."""
    return seed.seed_compute(moto_session)


@pytest.fixture(scope="module")
def management(moto_session: boto3.Session) -> Any:
    """The seeded CloudFormation estate (EC2/VPC included)."""
    return seed.seed_management(moto_session)


def _ignore(_path: str, _exc: Exception) -> None:
    return None


class Mount:
    """A fresh awsmount session (Context + VFS) over the moto backend."""

    def __init__(self, **overrides: Any) -> None:
        options = dict(MOUNT_DEFAULTS)
        options.update(overrides)
        self.ctx = Context.from_config(Config(**options))
        self.vfs = build_vfs(self.ctx)
        accounts = self.ctx.accounts.accounts()
        assert len(accounts) == 1, accounts
        assert accounts[0].error is None, accounts[0].error
        self.account = accounts[0]
        self.root = f"/{self.account.dirname}"
        self.region_root = f"{self.root}/{REGION}"
        self.global_root = f"{self.root}/global"

    # -- paths and reads ---------------------------------------------

    def path(self, rel: str) -> str:
        """Absolute path of ``rel`` under the mounted region."""
        return f"{self.region_root}/{rel}"

    def gpath(self, rel: str) -> str:
        """Absolute path of ``rel`` under ``global``."""
        return f"{self.global_root}/{rel}"

    def read(self, path: str) -> bytes:
        """File content."""
        return self.vfs.read(path)

    def text(self, path: str) -> str:
        """File content decoded as UTF-8."""
        return self.vfs.read(path).decode("utf-8")

    def json(self, path: str) -> Any:
        """File content parsed as JSON."""
        return json.loads(self.text(path))

    def ls(self, path: str) -> list[str]:
        """Sorted names in a directory."""
        return self.vfs.listdir(path)

    def target(self, path: str) -> str:
        """Physical path a symlink (chain) resolves to."""
        return self.vfs.realpath(path)

    def targets(self, path: str) -> set[str]:
        """Physical targets of every symlink in a links directory."""
        return {self.target(f"{path}/{name}") for name in self.ls(path)}

    def relative_links(self, path: str) -> bool:
        """True when every symlink in ``path`` has a relative target."""
        return all(not self.vfs.readlink(f"{path}/{name}").startswith("/")
                   for name in self.ls(path))

    def grep(self, path: str, needle: str) -> list[str]:
        """Files under ``path`` containing ``needle`` (links unfollowed)."""
        hits = vwalk.grep(self.vfs, re.escape(needle), [path],
                          recursive=True, files_only=True,
                          on_error=_ignore)
        return sorted({hit.path for hit in hits})

    # -- session state -----------------------------------------------

    def calls(self) -> int:
        """API calls charged to the budget so far."""
        return self.ctx.budget.used()

    def mounted(self, ref: CollectionRef) -> bool:
        """True when the collection exists in this session's tree."""
        return (self.ctx.registry.collection(ref) is not None
                and self.ctx.config.service_enabled(ref.service))

    def deny(self, service: str, op: str,
             code: str = "AccessDenied") -> None:
        """Make ``service:op`` fail with ``code`` before any HTTP."""
        client = self.ctx.clients.get(self.account.profile, REGION,
                                      service)
        service_id = client.meta.service_model.service_id.hyphenize()

        def refuse(**_kwargs: Any) -> None:
            raise ClientError(
                {"Error": {"Code": code, "Message": "denied by test"},
                 "ResponseMetadata": {"HTTPStatusCode": 403}}, op)

        client.meta.events.register(f"before-call.{service_id}.{op}",
                                    refuse)

    def error_lines(self) -> list[list[str]]:
        """``_meta/errors.log`` rows split into their TSV columns."""
        raw = self.text(f"{self.root}/_meta/errors.log")
        return [line.split("\t") for line in raw.splitlines() if line]

    def denied(self, service: str,
               op: str | None = None) -> list[list[str]]:
        """errors.log rows of kind access-denied for ``service``."""
        return [cols for cols in self.error_lines()
                if len(cols) >= 8 and cols[3] == service
                and cols[5] == "access-denied"
                and (op is None or cols[4] == op)]
