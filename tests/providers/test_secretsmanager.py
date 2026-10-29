"""Secrets Manager provider against moto: metadata only, never values.

Covers escaped names, describe.json derived from the single listing,
inline tags (not redacted), the lazy resource policy, the kms-key link,
secret values never fetched (with and without ``--reveal``), the
read-only guard and AccessDenied degradation.
"""

from __future__ import annotations

import errno
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from awsmount.errors import ForbiddenOperation, PermissionDenied
from awsmount.vfs.path import escape_name
from awsmount.vfs.render import to_json_text


def _load_kit() -> ModuleType:
    """Load tests/providers/motokit.py by path (import-mode agnostic)."""
    name = "awsmount_tests_motokit"
    module = sys.modules.get(name)
    if module is not None:
        return module
    path = Path(__file__).resolve().with_name("motokit.py")
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


kit = _load_kit()
seed = kit.seed
Mount = kit.Mount
REGION: str = kit.REGION
FAKE_SECRET: str = kit.FAKE_SECRET
moto_session = kit.moto_session

SECRETS = "secretsmanager/secrets"
DB = f"{SECRETS}/{escape_name(seed.SECRET_DB_NAME)}"
PLAIN = f"{SECRETS}/{escape_name(seed.SECRET_PLAIN_NAME)}"
READ_OPS = frozenset({"ListSecrets", "GetResourcePolicy"})


@pytest.fixture(scope="module")
def secrets(moto_session: Any) -> Any:
    """The seeded secrets estate."""
    return seed.seed_secrets(moto_session)


def _canonical(obj: Any) -> Any:
    return json.loads(to_json_text(obj))


def _listed(session: Any, name: str) -> dict[str, Any]:
    client = session.client("secretsmanager", region_name=REGION)
    for page in client.get_paginator("list_secrets").paginate():
        for item in page["SecretList"]:
            if item["Name"] == name:
                return dict(item)
    raise AssertionError(f"{name} not listed by moto")


def _spy(m: Any, service: str) -> list[str]:
    """Record every operation the mount sends to ``service``."""
    client = m.ctx.clients.get(m.account.profile, REGION, service)
    ops: list[str] = []

    def record(model: Any, **_kwargs: Any) -> None:
        ops.append(str(model.name))

    client.meta.events.register("before-call.*.*", record)
    return ops


def test_names_with_slash_are_escaped(secrets: Any) -> None:
    m = Mount()
    names = m.ls(m.path(SECRETS))
    assert names == sorted([escape_name(seed.SECRET_DB_NAME),
                            seed.SECRET_PLAIN_NAME])
    assert "awsmount%2Fdb%2Fpassword" in names
    assert m.text(m.path(f"{DB}/name")) == seed.SECRET_DB_NAME + "\n"


def test_resource_dir_entries(secrets: Any) -> None:
    m = Mount()
    assert set(m.ls(m.path(DB))) == {
        "arn", "describe.json", "links", "name", "policy.json",
        "rotation-enabled", "tags", "tags.json"}
    assert "referenced-by" not in m.ls(m.path(DB))


def test_describe_is_the_listing_item(secrets: Any,
                                      moto_session: Any) -> None:
    expected = _canonical(_listed(moto_session, seed.SECRET_DB_NAME))
    revealed = Mount(reveal=True)
    assert revealed.json(revealed.path(f"{DB}/describe.json")) == expected
    m = Mount()
    assert m.json(m.path(f"{DB}/describe.json")) == expected


def test_derived_fields(secrets: Any) -> None:
    m = Mount()
    doc = m.json(m.path(f"{DB}/describe.json"))
    assert doc["Name"] == seed.SECRET_DB_NAME
    assert doc["ARN"] == secrets.secret_db_arn
    assert doc["Description"] == seed.SECRET_DB_DESCRIPTION
    assert doc["KmsKeyId"] == secrets.kms_key_arn
    assert "SecretString" not in doc
    assert "SecretBinary" not in doc
    assert m.text(m.path(f"{DB}/arn")) == secrets.secret_db_arn + "\n"
    assert m.text(m.path(f"{DB}/rotation-enabled")) == "false\n"
    assert m.text(m.path(f"{PLAIN}/arn")) == \
        secrets.secret_plain_arn + "\n"


def test_inline_tags_are_not_redacted(secrets: Any) -> None:
    m = Mount()
    assert m.json(m.path(f"{DB}/tags.json")) == dict(
        sorted(seed.SECRET_DB_TAGS.items()))
    assert m.text(m.path(f"{DB}/tags/DbPassword")) == \
        seed.TAG_SECRET_VALUE + "\n"
    assert m.text(m.path(f"{DB}/tags/team%2Fowner")) == "security\n"
    assert m.json(m.path(f"{PLAIN}/tags.json")) == {}
    assert m.ls(m.path(f"{PLAIN}/tags")) == []


def test_listing_is_one_call_and_derived_files_are_free(
        secrets: Any) -> None:
    m = Mount()
    before = m.calls()
    names = m.ls(m.path(SECRETS))
    assert m.calls() == before + 1
    for name in names:
        base = m.path(f"{SECRETS}/{name}")
        for leaf in ("describe.json", "arn", "name", "rotation-enabled",
                     "tags.json"):
            m.read(f"{base}/{leaf}")
        for tag in m.ls(f"{base}/tags"):
            m.read(f"{base}/tags/{tag}")
    assert m.calls() == before + 1
    m.json(m.path(f"{DB}/policy.json"))
    assert m.calls() == before + 2
    m.json(m.path(f"{DB}/policy.json"))
    assert m.calls() == before + 2


def test_policy_json_is_parsed_and_absent_is_null(secrets: Any) -> None:
    m = Mount()
    assert m.json(m.path(f"{DB}/policy.json")) == \
        seed.secret_policy(secrets.account_id)
    assert m.text(m.path(f"{PLAIN}/policy.json")) == "null\n"


def test_kms_key_link_is_relative_and_resolves(secrets: Any) -> None:
    m = Mount()
    links = m.path(f"{DB}/links")
    assert m.ls(links) == ["kms-key"]
    assert m.vfs.readlink(f"{links}/kms-key") == \
        f"../../../../kms/keys/{secrets.kms_key_id}"
    assert m.target(f"{links}/kms-key") == \
        m.path(f"kms/keys/{secrets.kms_key_id}")
    assert m.ls(m.path(f"{PLAIN}/links")) == []


@pytest.mark.parametrize("reveal", [False, True])
def test_secret_values_are_never_fetched(secrets: Any,
                                         reveal: bool) -> None:
    m = Mount(reveal=reveal)
    ops = _spy(m, "secretsmanager")
    assert m.grep(m.path("secretsmanager"), FAKE_SECRET) == []
    assert "ListSecrets" in ops
    assert set(ops) <= READ_OPS
    assert m.grep(m.path("secretsmanager"), seed.SECRET_DB_NAME)


def test_value_operations_are_refused_before_http(secrets: Any) -> None:
    m = Mount(reveal=True)
    client = m.ctx.clients.get(m.account.profile, REGION,
                               "secretsmanager")
    before = m.calls()
    with pytest.raises(ForbiddenOperation):
        client.get_secret_value(SecretId=secrets.secret_db_arn)
    with pytest.raises(ForbiddenOperation):
        client.batch_get_secret_value(
            SecretIdList=[secrets.secret_db_arn])
    with pytest.raises(ForbiddenOperation):
        client.describe_secret(SecretId=secrets.secret_db_arn)
    with pytest.raises(ForbiddenOperation):
        client.delete_secret(SecretId=secrets.secret_db_arn)
    assert m.calls() == before


def test_access_denied_on_listing_degrades_to_empty_dir(
        secrets: Any) -> None:
    m = Mount()
    m.deny("secretsmanager", "ListSecrets")
    assert m.ls(m.path(SECRETS)) == []
    rows = m.denied("secretsmanager", "list_secrets")
    assert len(rows) == 1
    assert rows[0][1] == secrets.account_id
    assert rows[0][2] == REGION
    assert rows[0][6] == "AccessDenied"
    assert m.ls(m.path("ssm/parameters"))
    assert secrets.kms_key_id in m.ls(m.path("kms/keys"))


def test_access_denied_on_policy_is_eacces(secrets: Any) -> None:
    m = Mount()
    m.deny("secretsmanager", "GetResourcePolicy")
    with pytest.raises(PermissionDenied) as info:
        m.read(m.path(f"{DB}/policy.json"))
    assert info.value.errno == errno.EACCES
    assert m.json(m.path(f"{DB}/describe.json"))["Name"] == \
        seed.SECRET_DB_NAME
    assert len(m.denied("secretsmanager", "get_resource_policy")) == 1


def test_seed_is_idempotent(moto_session: Any, secrets: Any) -> None:
    again = seed.seed_secrets(moto_session)
    assert again == secrets
    m = Mount()
    assert len(m.ls(m.path(SECRETS))) == 2
