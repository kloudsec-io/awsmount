"""Fixtures of the ``awsmount secrets`` tests.

The estate is created in moto with distinctive values, and the session
is the real one (``build_session``: Context, ClientFactory with the
value-read guard, store, tree). Only AWS is replaced, by moto.
"""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError

from awsmount.config import Config
from awsmount.secrets.session import SecretsSession, build_session

PROVIDERS_CONFTEST = (Path(__file__).resolve().parent.parent
                      / "providers" / "conftest.py")


def _load_providers_conftest() -> ModuleType:
    """Import tests/providers/conftest.py by path, once."""
    name = "awsmount_tests_providers_conftest"
    module = sys.modules.get(name)
    if module is not None:
        return module
    spec = importlib.util.spec_from_file_location(name, PROVIDERS_CONFTEST)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


_shared = _load_providers_conftest()
aws_env = _shared.aws_env
moto_aws = _shared.moto_aws
op_log = _shared.op_log
REGION: str = _shared.REGION
ACCOUNT = "123456789012"

PLAIN = "CANARY-plain-value"
JSON_OLD = '{"password":"CANARY-old"}'
JSON_NEW = '{"password":"CANARY-new"}'
BINARY = b"\x00\xff\n\x00end"
UNICODE = "CANARY-héllo-✓"
PENDING = "CANARY-pending-must-not-show"
SECURE = "CANARY-secure-string"
PARAMS = {
    "/app/db/host": ("String", "CANARY-host"),
    "/app/db/password": ("SecureString", SECURE),
    "/app/list": ("StringList", "CANARY-a,b,c"),
    "/app": ("String", "CANARY-app-is-also-a-prefix"),
    "/Case": ("String", "CANARY-upper"),
    "/case": ("String", "CANARY-lower"),
    "toplevel": ("String", "CANARY-toplevel"),
}


@dataclass
class Estate:
    """Names of the secrets created in moto."""

    plain: str = "team/plain"
    json: str = "team/json"
    binary: str = "team/binary"
    unicode: str = "team/unicode"
    pending: str = "team/pending"
    upper: str = "team/CaseX"
    lower: str = "team/casex"


@pytest.fixture
def estate(moto_aws: None) -> Estate:
    """Secrets and parameters with known values."""
    est = Estate()
    sm = boto3.client("secretsmanager", region_name=REGION)
    sm.create_secret(Name=est.plain, SecretString=PLAIN)
    sm.create_secret(Name=est.json, SecretString=JSON_OLD)
    sm.put_secret_value(SecretId=est.json, SecretString=JSON_NEW)
    sm.create_secret(Name=est.binary, SecretBinary=BINARY)
    sm.create_secret(Name=est.unicode, SecretString=UNICODE)
    sm.create_secret(Name=est.pending, SecretString=PLAIN)
    sm.put_secret_value(SecretId=est.pending, SecretString=PENDING,
                        VersionStages=["AWSPENDING"])
    sm.create_secret(Name=est.upper, SecretString="CANARY-upper")
    sm.create_secret(Name=est.lower, SecretString="CANARY-lower")
    ssm = boto3.client("ssm", region_name=REGION)
    for name, (kind, value) in PARAMS.items():
        ssm.put_parameter(Name=name, Type=kind, Value=value)
    return est


@pytest.fixture
def make_session(estate: Estate) -> Iterator[Callable[..., SecretsSession]]:
    """Factory ``make_session(**config_overrides)``; closed afterwards."""
    opened: list[SecretsSession] = []

    def factory(**overrides: Any) -> SecretsSession:
        overrides.setdefault("ttl", 300.0)
        config = Config(profiles=(None,), regions=(REGION,), **overrides)
        session = build_session(config)
        opened.append(session)
        return session

    yield factory
    for session in opened:
        session.close()


@pytest.fixture
def session(make_session: Callable[..., SecretsSession]) -> SecretsSession:
    """The default secrets session over the estate."""
    return make_session()


def deny_op(session: SecretsSession, service: str, op: str,
            code: str = "AccessDeniedException") -> list[str]:
    """Make ``service:op`` fail with ``code`` before any HTTP."""
    client = session.ctx.clients.get(None, REGION, service)
    service_id = client.meta.service_model.service_id.hyphenize()
    hits: list[str] = []

    def refuse(**_kwargs: Any) -> None:
        hits.append(op)
        raise ClientError(
            {"Error": {"Code": code, "Message": "denied by test"},
             "ResponseMetadata": {"HTTPStatusCode": 400}}, op)

    client.meta.events.register(f"before-call.{service_id}.{op}", refuse)
    return hits


def value_reads(log: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """The value reads among the recorded ``(service, Op)`` calls."""
    return [c for c in log if c in (("secretsmanager", "GetSecretValue"),
                                    ("ssm", "GetParameter"))]
