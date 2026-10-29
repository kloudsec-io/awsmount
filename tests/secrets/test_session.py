"""The secrets session: identity, region, its own narrow allow-list."""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable
from typing import Any

import pytest

from awsmount.config import Config
from awsmount.errors import ForbiddenOperation
from awsmount.secrets.session import (
    LIST_OPS,
    VALUE_OPS,
    SecretsError,
    SecretsSession,
    banner,
    build_session,
    resolve_region,
)
from awsmount.session.clients import BOOTSTRAP_PAIRS

from conftest import ACCOUNT, REGION  # type: ignore[import-not-found]


def test_the_session_has_no_provider_and_one_account(
        session: SecretsSession) -> None:
    assert session.ctx.registry.services() == []
    assert session.account.account_id == ACCOUNT
    assert session.region == REGION


def test_the_allow_list_is_exactly_the_four_ops_plus_bootstrap(
        session: SecretsSession) -> None:
    assert session.ctx.clients.allowed_pairs == (
        VALUE_OPS | LIST_OPS | BOOTSTRAP_PAIRS)
    assert VALUE_OPS == {("secretsmanager", "GetSecretValue"),
                         ("ssm", "GetParameter")}
    assert LIST_OPS == {("secretsmanager", "ListSecrets"),
                        ("ssm", "DescribeParameters")}


@pytest.mark.parametrize("service, method, params", [
    ("ec2", "describe_instances", {}),
    ("s3", "list_buckets", {}),
    ("iam", "list_users", {}),
    ("kms", "decrypt", {"CiphertextBlob": b"x"}),
    ("secretsmanager", "batch_get_secret_value",
     {"SecretIdList": ["a"]}),
    ("secretsmanager", "list_secret_version_ids", {"SecretId": "a"}),
    ("secretsmanager", "describe_secret", {"SecretId": "a"}),
    ("secretsmanager", "put_secret_value",
     {"SecretId": "a", "SecretString": "x"}),
    ("secretsmanager", "delete_secret", {"SecretId": "a"}),
    ("ssm", "get_parameters", {"Names": ["/a"]}),
    ("ssm", "get_parameters_by_path", {"Path": "/"}),
    ("ssm", "get_parameter_history", {"Name": "/a"}),
    ("ssm", "put_parameter", {"Name": "/a", "Value": "v",
                              "Type": "String"}),
    ("ssm", "delete_parameter", {"Name": "/a"}),
])
def test_everything_else_is_refused_in_the_secrets_session(
        session: SecretsSession, service: str, method: str,
        params: dict[str, Any]) -> None:
    client = session.ctx.clients.get(None, REGION, service)
    with pytest.raises(ForbiddenOperation):
        getattr(client, method)(**params)


def test_the_two_value_reads_are_charged_to_the_budget(
        session: SecretsSession, estate: Any) -> None:
    session.vfs.listdir("/ssm")
    before = session.ctx.budget.used()
    session.vfs.read("/ssm/toplevel")
    assert session.ctx.budget.used() == before + 1


def test_one_profile_and_one_region_only() -> None:
    with pytest.raises(SecretsError):
        build_session(Config(profiles=("a", "b"), regions=(REGION,)))
    with pytest.raises(SecretsError):
        build_session(Config(profiles=(None,), regions=()))
    with pytest.raises(SecretsError):
        build_session(Config(profiles=(None,), regions=("all",)))
    with pytest.raises(SecretsError):
        build_session(Config(profiles=(None,),
                             regions=(REGION, "eu-west-1")))


def test_unusable_credentials_stop_the_start(
        estate: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AWS_ACCESS_KEY_ID")
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY")
    with pytest.raises(SecretsError, match="cannot use these credentials"):
        build_session(Config(profiles=(None,), regions=(REGION,)))


def test_an_explicit_region_is_used_as_given() -> None:
    assert resolve_region(None, "eu-west-3") == "eu-west-3"


@pytest.mark.parametrize("bad", ["all", "nowhere", "us east 1", "a/b"])
def test_a_bad_region_is_refused(bad: str) -> None:
    with pytest.raises(SecretsError):
        resolve_region(None, bad)


def test_the_region_comes_from_the_environment_without_a_flag(
        aws_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-central-1")
    assert resolve_region(None, None) == "eu-central-1"


def test_no_region_anywhere_is_an_error_never_a_guess(
        aws_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AWS_DEFAULT_REGION")
    monkeypatch.delenv("AWS_REGION", raising=False)
    with pytest.raises(SecretsError, match="no region"):
        resolve_region(None, None)


def test_the_banner_names_the_identity_and_the_cache(
        make_session: Callable[..., SecretsSession]) -> None:
    text = banner(make_session(ttl=120.0), 120.0)
    assert "secret VALUES" in text
    assert ACCOUNT in text and REGION in text
    assert "kept in memory for 120 s" in text
    assert "not cached" in banner(make_session(ttl=0.0), 0.0)


def test_harden_process_forbids_core_dumps() -> None:
    code = ("import resource;"
            "from awsmount.secrets.session import harden_process;"
            "harden_process();"
            "print(resource.getrlimit(resource.RLIMIT_CORE))")
    out = subprocess.run([sys.executable, "-c", code], check=True,
                         capture_output=True, text=True).stdout
    assert out.strip() == "(0, 0)"


def test_every_call_carries_the_secrets_user_agent(
        session: SecretsSession) -> None:
    """CloudTrail can tell the reads of this command from other awsmount
    calls."""
    from awsmount import __version__
    for service in ("secretsmanager", "ssm", "sts"):
        client = session.ctx.clients.get(None, REGION, service)
        agent = client.meta.config.user_agent_extra
        assert agent == f"awsmount/{__version__} awsmount-secrets", agent


def test_the_normal_session_user_agent_is_unchanged(aws_env: None) -> None:
    from awsmount import __version__
    from awsmount.session.context import Context
    ctx = Context.from_config(Config(regions=(REGION,)))
    client = ctx.clients.get(None, REGION, "sts")
    assert client.meta.config.user_agent_extra == f"awsmount/{__version__}"
