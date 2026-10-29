"""SSM Parameter Store provider against moto: names and metadata only.

Covers escaped parameter names, describe.json derived from the single
DescribeParameters listing with ``Value`` redacted, lazy tags, the
kms-key link of SecureString parameters, parameter values never
fetched (with and without ``--reveal``), the read-only guard and
AccessDenied degradation.
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
from awsmount.session.redact import REDACTED
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

PARAMS = "ssm/parameters"
ALL_PARAMS = (seed.PARAM_LOG_LEVEL, seed.PARAM_DB_PASSWORD,
              seed.PARAM_API_KEY, seed.PARAM_HOSTS)
READ_OPS = frozenset({"DescribeParameters", "ListTagsForResource"})


def _dir(name: str) -> str:
    return f"{PARAMS}/{escape_name(name)}"


@pytest.fixture(scope="module")
def seeded(moto_session: Any) -> Any:
    """The seeded secrets estate (Secrets Manager + SSM)."""
    return seed.seed_secrets(moto_session)


def _listed(session: Any, name: str) -> dict[str, Any]:
    client = session.client("ssm", region_name=REGION)
    for page in client.get_paginator("describe_parameters").paginate():
        for item in page["Parameters"]:
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


def test_names_are_escaped(seeded: Any) -> None:
    m = Mount()
    names = m.ls(m.path(PARAMS))
    assert names == sorted(escape_name(n) for n in ALL_PARAMS)
    db_name = seed.PARAM_DB_PASSWORD
    assert db_name.startswith("/")
    escaped = db_name.replace("%", "%25").replace("/", "%2F")
    assert escaped in names
    assert "/" not in escaped
    assert escaped.startswith("%2F")
    assert seed.PARAM_HOSTS in names
    assert m.text(m.path(f"{_dir(seed.PARAM_DB_PASSWORD)}/name")) == \
        seed.PARAM_DB_PASSWORD + "\n"


def test_resource_dir_entries(seeded: Any) -> None:
    m = Mount()
    assert set(m.ls(m.path(_dir(seed.PARAM_LOG_LEVEL)))) == {
        "arn", "describe.json", "links", "name", "tags", "tags.json",
        "type", "version"}


def test_describe_redacts_value_and_keeps_metadata(seeded: Any) -> None:
    m = Mount()
    for name in ALL_PARAMS:
        raw = m.read(m.path(f"{_dir(name)}/describe.json"))
        assert FAKE_SECRET.encode() not in raw
        doc = json.loads(raw)
        assert doc["Name"] == name
        assert doc.get("Value", REDACTED) == REDACTED
        assert doc["Version"] == 1
    db = m.json(m.path(f"{_dir(seed.PARAM_DB_PASSWORD)}/describe.json"))
    assert db["Type"] == "SecureString"
    assert db["KeyId"] == seeded.kms_key_id
    log = m.json(m.path(f"{_dir(seed.PARAM_LOG_LEVEL)}/describe.json"))
    assert log["Description"] == seed.PARAM_DESCRIPTION


def test_reveal_describe_is_the_listing_item(seeded: Any,
                                             moto_session: Any) -> None:
    m = Mount(reveal=True)
    for name in ALL_PARAMS:
        expected = json.loads(to_json_text(_listed(moto_session, name)))
        assert m.json(m.path(f"{_dir(name)}/describe.json")) == expected


def test_derived_text_files(seeded: Any) -> None:
    m = Mount()
    db = _dir(seed.PARAM_DB_PASSWORD)
    assert m.text(m.path(f"{db}/type")) == "SecureString\n"
    assert m.text(m.path(f"{db}/version")) == "1\n"
    hosts = _dir(seed.PARAM_HOSTS)
    assert m.text(m.path(f"{hosts}/type")) == "StringList\n"
    prefix = f"arn:aws:ssm:{REGION}:{seeded.account_id}:parameter"
    db_arn = m.text(m.path(f"{db}/arn")).strip()
    assert db_arn.startswith(prefix)
    assert db_arn.endswith(seed.PARAM_DB_PASSWORD)
    assert m.text(m.path(f"{hosts}/arn")) == \
        f"{prefix}/{seed.PARAM_HOSTS}\n"


def test_kms_link_only_for_customer_key_securestring(seeded: Any) -> None:
    m = Mount()
    links = m.path(f"{_dir(seed.PARAM_DB_PASSWORD)}/links")
    assert m.ls(links) == ["kms-key"]
    assert m.vfs.readlink(f"{links}/kms-key") == \
        f"../../../../kms/keys/{seeded.kms_key_id}"
    assert m.target(f"{links}/kms-key") == \
        m.path(f"kms/keys/{seeded.kms_key_id}")
    for name in (seed.PARAM_API_KEY, seed.PARAM_LOG_LEVEL,
                 seed.PARAM_HOSTS):
        assert m.ls(m.path(f"{_dir(name)}/links")) == []


def test_tags_are_lazy_cached_and_not_redacted(seeded: Any) -> None:
    m = Mount()
    base = m.path(_dir(seed.PARAM_LOG_LEVEL))
    m.ls(m.path(PARAMS))
    before = m.calls()
    assert m.json(f"{base}/tags.json") == dict(
        sorted(seed.PARAM_TAGS.items()))
    assert m.calls() == before + 1
    assert m.text(f"{base}/tags/ApiToken") == seed.TAG_SECRET_VALUE + "\n"
    assert m.text(f"{base}/tags/team%2Fowner") == "platform\n"
    assert m.calls() == before + 1
    assert m.json(m.path(f"{_dir(seed.PARAM_HOSTS)}/tags.json")) == {}


def test_listing_is_one_call_and_derived_files_are_free(
        seeded: Any) -> None:
    m = Mount()
    before = m.calls()
    names = m.ls(m.path(PARAMS))
    assert m.calls() == before + 1
    for name in names:
        base = m.path(f"{PARAMS}/{name}")
        for leaf in ("describe.json", "arn", "name", "type", "version"):
            m.read(f"{base}/{leaf}")
    assert m.calls() == before + 1


@pytest.mark.parametrize("reveal", [False, True])
def test_parameter_values_are_never_fetched(seeded: Any,
                                            reveal: bool) -> None:
    m = Mount(reveal=reveal)
    ops = _spy(m, "ssm")
    hits = m.grep(m.path("ssm"), FAKE_SECRET)
    if not reveal:
        assert hits == []
    assert "DescribeParameters" in ops
    assert set(ops) <= READ_OPS
    assert not any(op.startswith("GetParameter") for op in ops)


def test_value_operations_are_refused_before_http(seeded: Any) -> None:
    m = Mount(reveal=True)
    client = m.ctx.clients.get(m.account.profile, REGION, "ssm")
    name = seed.PARAM_DB_PASSWORD
    before = m.calls()
    with pytest.raises(ForbiddenOperation):
        client.get_parameter(Name=name, WithDecryption=True)
    with pytest.raises(ForbiddenOperation):
        client.get_parameters(Names=[name], WithDecryption=True)
    with pytest.raises(ForbiddenOperation):
        client.get_parameters_by_path(Path="/awsmount",
                                      WithDecryption=True)
    with pytest.raises(ForbiddenOperation):
        client.get_parameter_history(Name=name, WithDecryption=True)
    with pytest.raises(ForbiddenOperation):
        client.delete_parameter(Name=name)
    assert m.calls() == before


def test_access_denied_on_listing_degrades_to_empty_dir(
        seeded: Any) -> None:
    m = Mount()
    m.deny("ssm", "DescribeParameters")
    assert m.ls(m.path(PARAMS)) == []
    rows = m.denied("ssm", "describe_parameters")
    assert len(rows) == 1
    assert rows[0][1] == seeded.account_id
    assert rows[0][2] == REGION
    assert m.ls(m.path("secretsmanager/secrets"))


def test_access_denied_on_lazy_tags(seeded: Any) -> None:
    m = Mount()
    m.deny("ssm", "ListTagsForResource")
    base = m.path(_dir(seed.PARAM_LOG_LEVEL))
    with pytest.raises(PermissionDenied) as info:
        m.read(f"{base}/tags.json")
    assert info.value.errno == errno.EACCES
    assert m.ls(f"{base}/tags") == []
    assert m.json(f"{base}/describe.json")["Name"] == seed.PARAM_LOG_LEVEL
    assert len(m.denied("ssm", "list_tags_for_resource")) == 1


def test_seed_is_idempotent(moto_session: Any, seeded: Any) -> None:
    again = seed.seed_secrets(moto_session)
    assert again == seeded
    m = Mount()
    assert len(m.ls(m.path(PARAMS))) == len(ALL_PARAMS)
