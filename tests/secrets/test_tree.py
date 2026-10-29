"""The secrets tree against moto: layout, exact bytes, laziness, errors."""

from __future__ import annotations

import errno
import json
from collections.abc import Callable
from typing import Any

import pytest

from awsmount.errors import (
    BudgetExceeded,
    NotFound,
    PermissionDenied,
)
from awsmount.secrets.session import SecretsSession
from awsmount.secrets.tree import SecretValueFile
from awsmount.vfs.node import FileNode
from awsmount.vfs.path import escape_name

from conftest import (  # type: ignore[import-not-found]
    BINARY,
    JSON_NEW,
    JSON_OLD,
    PENDING,
    PLAIN,
    SECURE,
    UNICODE,
    Estate,
    deny_op,
    value_reads,
)


def sm(name: str, *parts: str) -> str:
    """Path of a secret (and entries below it)."""
    return "/".join(["/secretsmanager", escape_name(name), *parts])


def test_root_has_the_two_services_and_nothing_else(
        session: SecretsSession) -> None:
    assert session.vfs.listdir("/") == ["secretsmanager", "ssm"]


def test_secret_directory_entries(session: SecretsSession,
                                  estate: Estate) -> None:
    assert session.vfs.listdir(sm(estate.plain)) == [
        "describe.json", "value", "versions"]


def test_names_with_a_slash_are_one_escaped_component(
        session: SecretsSession, estate: Estate) -> None:
    names = session.vfs.listdir("/secretsmanager")
    assert escape_name("team/plain") in names
    assert all("/" not in n for n in names)


def test_values_are_the_exact_bytes(session: SecretsSession,
                                    estate: Estate) -> None:
    read = session.vfs.read
    assert read(sm(estate.plain, "value")) == PLAIN.encode()
    assert read(sm(estate.binary, "value")) == BINARY
    assert read(sm(estate.unicode, "value")) == UNICODE.encode()
    assert read(sm(estate.json, "value")) == JSON_NEW.encode()


def test_versions_list_existing_stages_and_never_awspending(
        session: SecretsSession, estate: Estate) -> None:
    ls = session.vfs.listdir
    assert ls(sm(estate.json, "versions")) == ["AWSCURRENT", "AWSPREVIOUS"]
    assert ls(sm(estate.plain, "versions")) == ["AWSCURRENT"]
    assert ls(sm(estate.pending, "versions")) == ["AWSCURRENT"]
    assert session.vfs.read(sm(estate.json, "versions", "AWSPREVIOUS")) \
        == JSON_OLD.encode()
    assert session.vfs.read(sm(estate.json, "versions", "AWSCURRENT")) \
        == JSON_NEW.encode()
    assert session.vfs.read(sm(estate.pending, "value")) == PLAIN.encode()


def test_pending_value_is_unreachable_anywhere(
        session: SecretsSession, estate: Estate) -> None:
    for path, node in session.vfs.walk("/secretsmanager"):
        if isinstance(node, FileNode):
            assert PENDING.encode() not in session.vfs.read(path), path


def test_describe_json_is_metadata_without_a_value(
        session: SecretsSession, estate: Estate) -> None:
    doc = json.loads(session.vfs.read(sm(estate.json, "describe.json")))
    assert doc["Name"] == estate.json
    assert doc["ARN"].startswith("arn:aws:secretsmanager:")
    assert "SecretString" not in doc and "SecretBinary" not in doc
    assert "CANARY" not in json.dumps(doc)


def _labelled(name: str, value: str, label: str, *,
              drop_current: bool = False) -> None:
    import boto3
    client = boto3.client("secretsmanager", region_name="us-east-1")
    client.create_secret(Name=name, SecretString=value)
    version = client.get_secret_value(SecretId=name)["VersionId"]
    client.update_secret_version_stage(
        SecretId=name, VersionStage=label, MoveToVersionId=version)
    if drop_current:
        client.update_secret_version_stage(
            SecretId=name, VersionStage="AWSCURRENT",
            RemoveFromVersionId=version)


def test_custom_staging_labels_are_files_too(
        session: SecretsSession, estate: Estate) -> None:
    _labelled("team/labeled", "CANARY-labelled", "MYLABEL")
    path = sm("team/labeled", "versions")
    assert session.vfs.listdir(path) == ["AWSCURRENT", "MYLABEL"]
    assert session.vfs.read(f"{path}/MYLABEL") == b"CANARY-labelled"


def test_a_secret_without_a_current_version_has_no_value_file(
        session: SecretsSession, estate: Estate) -> None:
    _labelled("team/nocurrent", "CANARY-x", "MYLABEL", drop_current=True)
    assert session.vfs.listdir(sm("team/nocurrent")) == [
        "describe.json", "versions"]
    assert "AWSCURRENT" not in session.vfs.listdir(
        sm("team/nocurrent", "versions"))


def test_a_secret_created_without_a_value_reads_as_enoent(
        session: SecretsSession, estate: Estate) -> None:
    import boto3
    boto3.client("secretsmanager", region_name="us-east-1").create_secret(
        Name="team/empty")
    assert "value" in session.vfs.listdir(sm("team/empty"))
    with pytest.raises(NotFound):
        session.vfs.read(sm("team/empty", "value"))


def test_names_differing_only_in_case_get_distinct_directories(
        session: SecretsSession, estate: Estate) -> None:
    names = session.vfs.listdir("/secretsmanager")
    upper = [n for n in names if n.startswith("team%2FCaseX")]
    lower = [n for n in names if n.startswith("team%2Fcasex")]
    assert len(upper) == len(lower) == 1
    assert upper[0].casefold() != lower[0].casefold()
    assert session.vfs.read(f"/secretsmanager/{upper[0]}/value") \
        == b"CANARY-upper"
    assert session.vfs.read(f"/secretsmanager/{lower[0]}/value") \
        == b"CANARY-lower"


# ---------------------------------------------------------------- SSM


def test_ssm_is_nested_like_the_parameter_paths(
        session: SecretsSession) -> None:
    ls = session.vfs.listdir
    assert ls("/ssm/app/db") == ["host", "password"]
    assert "toplevel" in ls("/ssm")
    assert session.vfs.read("/ssm/app/db/host") == b"CANARY-host"
    assert session.vfs.read("/ssm/toplevel") == b"CANARY-toplevel"


def test_securestring_is_decrypted_and_stringlist_is_raw(
        session: SecretsSession) -> None:
    assert session.vfs.read("/ssm/app/db/password") == SECURE.encode()
    assert session.vfs.read("/ssm/app/list") == b"CANARY-a,b,c"


def test_a_parameter_that_is_also_a_prefix_has_an_at_value_file(
        session: SecretsSession) -> None:
    assert session.vfs.listdir("/ssm/app") == ["@value", "db", "list"]
    assert session.vfs.read("/ssm/app/@value") \
        == b"CANARY-app-is-also-a-prefix"


def test_ssm_names_differing_only_in_case_stay_apart(
        session: SecretsSession) -> None:
    names = session.vfs.listdir("/ssm")
    upper = [n for n in names if n.startswith("Case")]
    lower = [n for n in names if n.startswith("case")]
    assert len(upper) == len(lower) == 1
    assert session.vfs.read(f"/ssm/{upper[0]}") == b"CANARY-upper"
    assert session.vfs.read(f"/ssm/{lower[0]}") == b"CANARY-lower"


# ------------------------------------------------------------- laziness


def test_listing_and_stat_never_read_a_value(
        session: SecretsSession, op_log: list[tuple[str, str]]) -> None:
    for path, node in session.vfs.walk("/"):
        if isinstance(node, SecretValueFile):
            assert node.stat(render=False).size == 0
        else:
            node.stat()
    assert value_reads(op_log) == []
    assert ("secretsmanager", "ListSecrets") in op_log
    assert ("ssm", "DescribeParameters") in op_log


def test_value_files_are_lazy(session: SecretsSession,
                              estate: Estate) -> None:
    node = session.vfs.resolve(sm(estate.plain, "value"))
    assert isinstance(node, SecretValueFile)
    assert node.lazy and not node.is_rendered
    assert node.known_size() is None


def test_only_get_secret_value_and_get_parameter_read_values(
        session: SecretsSession, estate: Estate,
        op_log: list[tuple[str, str]]) -> None:
    session.vfs.read(sm(estate.plain, "value"))
    session.vfs.read("/ssm/toplevel")
    assert value_reads(op_log) == [("secretsmanager", "GetSecretValue"),
                                   ("ssm", "GetParameter")]


# ------------------------------------------------------------ the cache


def test_a_value_is_fetched_once_per_ttl_then_again(
        session: SecretsSession, estate: Estate,
        op_log: list[tuple[str, str]]) -> None:
    clock = [1000.0]
    session.store._clock = lambda: clock[0]
    path = sm(estate.plain, "value")
    session.vfs.read(path)
    session.vfs.read(path)
    assert len(value_reads(op_log)) == 1
    node = session.vfs.resolve(path)
    assert node.known_size() == len(PLAIN)
    clock[0] += 301
    assert node.known_size() is None
    session.vfs.read(path)
    assert len(value_reads(op_log)) == 2


def test_ttl_zero_fetches_every_time_and_keeps_nothing(
        make_session: Callable[..., SecretsSession], estate: Estate,
        op_log: list[tuple[str, str]]) -> None:
    session = make_session(ttl=0.0)
    path = sm(estate.plain, "value")
    session.vfs.read(path)
    session.vfs.read(path)
    assert len(value_reads(op_log)) == 2
    assert len(session.store) == 0


def test_values_never_enter_the_generic_response_cache(
        session: SecretsSession, estate: Estate) -> None:
    session.vfs.read(sm(estate.plain, "value"))
    session.vfs.read("/ssm/app/db/password")
    cache = session.ctx.cache
    for entry in list(cache._data.values()):
        assert PLAIN not in repr(entry.value)
        assert SECURE not in repr(entry.value)


def test_close_overwrites_every_held_value(session: SecretsSession,
                                           estate: Estate) -> None:
    session.vfs.read(sm(estate.plain, "value"))
    session.vfs.read("/ssm/app/db/password")
    buffers = [e.data for e in session.store._entries.values()]
    assert len(buffers) == 2
    session.close()
    assert all(bytes(b) == bytes(len(b)) for b in buffers)
    assert len(session.store) == 0


def test_invalidate_wipes_one_value(session: SecretsSession,
                                    estate: Estate) -> None:
    node = session.vfs.resolve(sm(estate.plain, "value"))
    node.content()
    assert node.is_rendered
    node.invalidate()
    assert not node.is_rendered


# --------------------------------------------------------------- errors


def test_access_denied_is_eacces_and_is_remembered_briefly(
        session: SecretsSession, estate: Estate) -> None:
    """Retrying clients (macOS retries ten times) cost one AWS call, not
    ten, and a later read asks AWS again."""
    clock = [1000.0]
    session.store._clock = lambda: clock[0]
    hits = deny_op(session, "secretsmanager", "GetSecretValue")
    path = sm(estate.plain, "value")
    for _ in range(3):
        with pytest.raises(PermissionDenied) as caught:
            session.vfs.read(path)
        assert caught.value.errno == errno.EACCES
        assert PLAIN not in str(caught.value)
    assert len(hits) == 1
    clock[0] += session.ctx.config.negative_ttl + 1
    with pytest.raises(PermissionDenied):
        session.vfs.read(path)
    assert len(hits) == 2


def test_a_transient_error_is_not_remembered(
        session: SecretsSession, estate: Estate) -> None:
    hits = deny_op(session, "secretsmanager", "GetSecretValue",
                   code="InternalServiceError")
    path = sm(estate.plain, "value")
    for _ in range(3):
        with pytest.raises(Exception):
            session.vfs.read(path)
    assert len(hits) == 3


def test_a_denied_parameter_does_not_break_the_others(
        session: SecretsSession) -> None:
    deny_op(session, "ssm", "GetParameter")
    with pytest.raises(PermissionDenied):
        session.vfs.read("/ssm/toplevel")
    assert session.vfs.listdir("/ssm/app/db") == ["host", "password"]


def test_listing_denied_is_eacces_for_that_service_only(
        session: SecretsSession) -> None:
    deny_op(session, "ssm", "DescribeParameters")
    with pytest.raises(PermissionDenied):
        session.vfs.listdir("/ssm")
    assert session.vfs.listdir("/secretsmanager")


def test_a_secret_deleted_after_listing_is_enoent(
        session: SecretsSession, estate: Estate, moto_aws: None) -> None:
    import boto3
    path = sm(estate.plain, "value")
    session.vfs.listdir(sm(estate.plain))
    boto3.client("secretsmanager", region_name="us-east-1").delete_secret(
        SecretId=estate.plain, ForceDeleteWithoutRecovery=True)
    with pytest.raises(NotFound):
        session.vfs.read(path)


def test_the_api_budget_stops_value_reads(
        make_session: Callable[..., SecretsSession],
        estate: Estate) -> None:
    session = make_session(max_api_calls=5)
    session.vfs.listdir("/secretsmanager")
    with pytest.raises(BudgetExceeded):
        for name in (estate.plain, estate.json, estate.binary,
                     estate.unicode, estate.upper, estate.lower):
            session.vfs.read(sm(name, "value"))


def test_a_denied_value_never_appears_in_any_error_text(
        session: SecretsSession, estate: Estate) -> None:
    deny_op(session, "secretsmanager", "GetSecretValue")
    with pytest.raises(PermissionDenied) as caught:
        session.vfs.read(sm(estate.plain, "value"))
    assert "CANARY" not in repr(caught.value)
    assert "CANARY" not in repr(vars(caught.value))


def _values_in_the_tree(session: SecretsSession) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for path, node in session.vfs.walk("/"):
        if isinstance(node, SecretValueFile):
            out[path] = session.vfs.read(path)
    return out


def test_every_value_file_in_the_tree_is_reachable_and_exact(
        session: SecretsSession, estate: Estate) -> None:
    values = _values_in_the_tree(session)
    # 7 secrets: a value file each plus one file per stage; 7 parameters
    assert len(values) == 7 + 8 + 7
    expected: dict[str, Any] = {
        sm(estate.plain, "value"): PLAIN.encode(),
        sm(estate.binary, "value"): BINARY,
        "/ssm/app/db/password": SECURE.encode(),
    }
    for path, want in expected.items():
        assert values[path] == want
