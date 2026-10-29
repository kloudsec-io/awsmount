"""Provider-test fixtures: moto in-process, the seeded estate, mounts.

The seed module is loaded by file path, so that it does not depend on
how pytest arranges ``sys.path``. Mounts use the *real*
``Context.from_config`` wiring: ClientFactory with its read-only guard,
budget, cache, registry and redaction. Only AWS is replaced, by
moto's ``mock_aws``.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

import boto3
import pytest
from moto import mock_aws

from awsmount.config import Config
from awsmount.session.clients import ClientFactory
from awsmount.session.context import Context
from awsmount.tree.root import build_vfs
from awsmount.vfs.resolver import VFS

SEED_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "seed.py"
SEED_MODULE = "awsmount_tests_seed"


def load_seed() -> ModuleType:
    """Import ``tests/fixtures/seed.py`` once, by path."""
    module = sys.modules.get(SEED_MODULE)
    if module is not None:
        return module
    spec = importlib.util.spec_from_file_location(SEED_MODULE, SEED_PATH)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {SEED_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[SEED_MODULE] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(SEED_MODULE, None)
        raise
    return module


SEED_LIB = load_seed()
REGION: str = SEED_LIB.REGION


@dataclass
class Mount:
    """A Context + VFS over moto, with small reading helpers."""

    ctx: Context
    vfs: VFS
    account: str
    region: str

    @property
    def base(self) -> str:
        """``/<account>/<region>``."""
        return f"/{self.account}/{self.region}"

    def path(self, *parts: str) -> str:
        """Absolute path under the regional directory."""
        return "/".join([self.base, *parts])

    def gpath(self, *parts: str) -> str:
        """Absolute path under the ``global`` directory."""
        return "/".join([f"/{self.account}/global", *parts])

    def calls(self) -> int:
        """API calls charged to the budget so far."""
        return self.ctx.budget.used()

    def ls(self, path: str) -> list[str]:
        """Directory listing (sorted escaped names)."""
        return self.vfs.listdir(path)

    def read(self, path: str) -> bytes:
        """Whole file content."""
        return self.vfs.read(path)

    def text(self, path: str) -> str:
        """File content decoded as UTF-8."""
        return self.read(path).decode("utf-8")

    def json(self, path: str) -> Any:
        """File content parsed as JSON."""
        return json.loads(self.read(path))

    def readlink(self, path: str) -> str:
        """Symlink target."""
        return self.vfs.readlink(path)

    def realpath(self, path: str) -> str:
        """Physical path with every symlink resolved."""
        return self.vfs.realpath(path)

    def errors(self) -> str:
        """This account's ``_meta/errors.log``."""
        return self.text(f"/{self.account}/_meta/errors.log")

    def error_lines(self) -> list[list[str]]:
        """errors.log split into TSV fields."""
        return [line.split("\t") for line in self.errors().splitlines()]


class DeniedResponse:
    """Minimal HTTP response botocore inspects on a short-circuit."""

    status_code = 403
    headers: dict[str, str] = {}
    content = b""
    text = ""


@pytest.fixture
def aws_env(monkeypatch: pytest.MonkeyPatch,
            tmp_path: Path) -> None:
    """Isolated fake credentials; no user config or IMDS lookups."""
    for var in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SESSION_TOKEN",
                "AWS_SECURITY_TOKEN", "AWS_ENDPOINT_URL",
                "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "aws-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE",
                       str(tmp_path / "aws-credentials"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")


@pytest.fixture
def moto_aws(aws_env: None) -> Iterator[None]:
    """Every boto3 call goes to moto's in-process backend."""
    with mock_aws():
        yield


@pytest.fixture
def seedlib() -> ModuleType:
    """The seed module (constants such as FAKE_SECRET, WEB_TAGS)."""
    return SEED_LIB


@pytest.fixture
def seed(moto_aws: None) -> Any:
    """The fully seeded account (``AllSeed``)."""
    return SEED_LIB.seed_all(boto3.Session(region_name=REGION))


@pytest.fixture
def estate(seed: Any) -> Any:
    """The EC2/VPC part of the seed (``Ec2VpcSeed``)."""
    return seed.ec2_vpc


@pytest.fixture
def make_mount(moto_aws: None) -> Callable[..., Mount]:
    """Factory ``make_mount(**config_overrides) -> Mount``.

    The account is resolved (sts + iam bootstrap calls) before the
    mount is returned, so measurements start after the bootstrap.
    """

    def factory(**overrides: Any) -> Mount:
        overrides.setdefault("regions", (REGION,))
        config = Config(**overrides)
        ctx = Context.from_config(config)
        vfs = build_vfs(ctx)
        accounts = vfs.listdir("/")
        assert len(accounts) == 1, accounts
        return Mount(ctx, vfs, accounts[0], config.regions[0])

    return factory


@pytest.fixture
def mount(seed: Any, make_mount: Callable[..., Mount]) -> Mount:
    """Default (redacting) mount over the seeded account."""
    return make_mount()


@pytest.fixture
def reveal(seed: Any, make_mount: Callable[..., Mount]) -> Mount:
    """A mount with masking off (``--reveal``)."""
    return make_mount(reveal=True)


@pytest.fixture
def op_log(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """``(service, ModelOpName)`` for every call that passed the guard.

    Each entry corresponds to exactly one budget charge.
    """
    log: list[tuple[str, str]] = []
    original = ClientFactory._guard

    def recording(self: ClientFactory, service: str, model: Any) -> None:
        original(self, service, model)
        log.append((service, str(model.name)))

    monkeypatch.setattr(ClientFactory, "_guard", recording)
    return log


@pytest.fixture
def deny() -> Callable[..., list[str]]:
    """Factory making one operation fail with an AWS error code.

    ``deny(ctx, "ec2", "DescribeNetworkInterfaces")`` registers a
    ``before-call`` handler on the session's real (memoised) client. The
    handler short-circuits the request with a 403 response, so botocore
    raises the corresponding ``ClientError``. The factory returns a
    list that grows by one entry per intercepted call.
    """

    def install(ctx: Context, service: str, operation: str,
                code: str = "UnauthorizedOperation",
                region: str = REGION) -> list[str]:
        client = ctx.clients.get(None, region, service)
        hits: list[str] = []

        def handler(**_kwargs: Any) -> tuple[Any, dict[str, Any]]:
            hits.append(operation)
            return (DeniedResponse(),
                    {"Error": {"Code": code,
                               "Message": f"simulated {code}"},
                     "ResponseMetadata": {"HTTPStatusCode": 403}})

        client.meta.events.register(f"before-call.{service}.{operation}",
                                    handler)
        return hits

    return install
