"""Redaction rules (ARCHITECTURE: Masking)."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from typing import Any

import pytest

from awsmount.session.context import Context
from awsmount.session.redact import (
    REDACTED,
    SAFE_SUFFIXES,
    RedactionPolicy,
)
from awsmount.tree.root import build_vfs
from awsmount.vfs.resolver import VFS

POLICY = RedactionPolicy(reveal=False)
REVEAL = RedactionPolicy(reveal=True)


def test_marker_text() -> None:
    """The redaction marker is fixed."""
    assert REDACTED == "<hidden>"


def test_lambda_env_values() -> None:
    """lambda: Environment.Variables.* values replaced, keys kept."""
    data = {"FunctionName": "f",
            "Environment": {"Variables": {"DB": "x", "MODE": "y"}}}
    out = POLICY.json("lambda", data)
    assert out == {"FunctionName": "f",
                   "Environment": {"Variables": {"DB": REDACTED,
                                                 "MODE": REDACTED}}}


def test_ecs_taskdef() -> None:
    """ecs-taskdef: env values redacted, secrets valueFrom kept."""
    arn = "arn:aws:ssm:us-east-1:123456789012:parameter/p"
    data = {"taskDefinition": {"containerDefinitions": [
        {"name": "app",
         "environment": [{"name": "A", "value": "1"},
                         {"name": "B", "value": "2"}],
         "secrets": [{"name": "S", "valueFrom": arn}]}]}}
    out: Any = POLICY.json("ecs-taskdef", data)
    cdef = out["taskDefinition"]["containerDefinitions"][0]
    assert cdef["environment"] == [{"name": "A", "value": REDACTED},
                                   {"name": "B", "value": REDACTED}]
    assert cdef["secrets"] == [{"name": "S", "valueFrom": arn}]
    assert cdef["name"] == "app"


def test_rds() -> None:
    """rds: MasterUserPassword redacted, username kept."""
    out = POLICY.json("rds", {"MasterUserPassword": "pw",
                              "MasterUsername": "admin"})
    assert out == {"MasterUserPassword": REDACTED,
                   "MasterUsername": "admin"}


def test_iam_access_keys() -> None:
    """iam: [].SecretAccessKey redacted, metadata kept."""
    data = [{"AccessKeyId": "AKIA1", "SecretAccessKey": "s",
             "Status": "Active"}]
    assert POLICY.json("iam", data) == [
        {"AccessKeyId": "AKIA1", "SecretAccessKey": REDACTED,
         "Status": "Active"}]


def test_cfn_params_in_describe() -> None:
    """cfn-params: values of secret-looking ParameterKeys."""
    data = {"Parameters": [
        {"ParameterKey": "DbPassword", "ParameterValue": "hunter2"},
        {"ParameterKey": "GitHubToken", "ParameterValue": "ghp"},
        {"ParameterKey": "Env", "ParameterValue": "prod"},
        {"ParameterKey": "AdminPassword", "UsePreviousValue": True}]}
    out: Any = POLICY.json("cfn-params", data)
    params = out["Parameters"]
    assert params[0]["ParameterValue"] == REDACTED
    assert params[1]["ParameterValue"] == REDACTED
    assert params[2]["ParameterValue"] == "prod"
    assert "ParameterValue" not in params[3]
    assert [p["ParameterKey"] for p in params] == [
        "DbPassword", "GitHubToken", "Env", "AdminPassword"]


def test_cfn_params_file_shape() -> None:
    """parameters.json is a bare list of parameters."""
    data = [{"ParameterKey": "ApiSecret", "ParameterValue": "s"},
            {"ParameterKey": "Size", "ParameterValue": "3"}]
    assert POLICY.json("cfn-params", data) == [
        {"ParameterKey": "ApiSecret", "ParameterValue": REDACTED},
        {"ParameterKey": "Size", "ParameterValue": "3"}]


def test_apigw_stage_variables() -> None:
    """apigw-stages: item[].variables.* redacted."""
    data = {"item": [{"stageName": "prod",
                      "variables": {"k": "v", "url": "u"}},
                     {"stageName": "dev"}]}
    out: Any = POLICY.json("apigw-stages", data)
    assert out["item"][0] == {"stageName": "prod",
                              "variables": {"k": REDACTED,
                                            "url": REDACTED}}
    assert out["item"][1] == {"stageName": "dev"}


def test_sns_http_endpoints() -> None:
    """sns: http/https endpoints redacted, others kept."""
    data = [{"Protocol": "https", "Endpoint": "https://u:p@x"},
            {"Protocol": "http", "Endpoint": "http://u:p@y"},
            {"Protocol": "email", "Endpoint": "a@b.c"},
            {"Protocol": "sqs",
             "Endpoint": "arn:aws:sqs:us-east-1:123456789012:q"}]
    out: Any = POLICY.json("sns", data)
    assert [e["Endpoint"] for e in out] == [
        REDACTED, REDACTED, "a@b.c",
        "arn:aws:sqs:us-east-1:123456789012:q"]
    assert [e["Protocol"] for e in out] == ["https", "http", "email",
                                            "sqs"]


def test_cloudfront_any_depth() -> None:
    """cloudfront: CustomHeaders values at any depth."""
    data = {"Distribution": {"DistributionConfig": {"Origins": {
        "Items": [{"Id": "o1", "CustomHeaders": {
            "Quantity": 1,
            "Items": [{"HeaderName": "X-Origin-Verify",
                       "HeaderValue": "s3cr3t"}]}}]}}}}
    out: Any = POLICY.json("cloudfront", data)
    item = out["Distribution"]["DistributionConfig"]["Origins"][
        "Items"][0]
    assert item["CustomHeaders"]["Items"] == [
        {"HeaderName": "X-Origin-Verify", "HeaderValue": REDACTED}]
    assert item["Id"] == "o1"
    assert item["CustomHeaders"]["Quantity"] == 1


def test_cloudfront_zero_depth() -> None:
    """'**' also matches at the top level (config.json shape)."""
    data = {"CustomHeaders": {"Items": [{"HeaderName": "h",
                                         "HeaderValue": "v"}]}}
    out: Any = POLICY.json("cloudfront", data)
    assert out["CustomHeaders"]["Items"][0]["HeaderValue"] == REDACTED


def test_elbv2_oidc_secret() -> None:
    """elbv2-listeners: OIDC client secret redacted."""
    data = [{"ListenerArn": "arn:aws:elasticloadbalancing:x",
             "DefaultActions": [{"Type": "authenticate-oidc",
                                 "AuthenticateOidcConfig": {
                                     "ClientId": "cid",
                                     "ClientSecret": "cs"}}]}]
    out: Any = POLICY.json("elbv2-listeners", data)
    cfg = out[0]["DefaultActions"][0]["AuthenticateOidcConfig"]
    assert cfg == {"ClientId": "cid", "ClientSecret": REDACTED}


def test_secrets_defensive() -> None:
    """secrets: SecretString/SecretBinary redacted, Name kept."""
    out = POLICY.json("secrets", {"Name": "db", "SecretString": "x",
                                  "SecretBinary": "eA=="})
    assert out == {"Name": "db", "SecretString": REDACTED,
                   "SecretBinary": REDACTED}


def test_ssm_defensive() -> None:
    """ssm: Value redacted, metadata kept."""
    out = POLICY.json("ssm", {"Name": "/p", "Type": "SecureString",
                              "Value": "v"})
    assert out == {"Name": "/p", "Type": "SecureString",
                   "Value": REDACTED}


@pytest.mark.parametrize("key", [
    "Password", "DbPassword", "PASSWORD", "passwd", "ClientSecret",
    "secret", "SessionToken", "ClientToken", "private_key",
    "PrivateKey", "Credential", "Credentials", "ApiKey", "api_key",
])
def test_generic_heuristic(key: str) -> None:
    """Secret-looking keys with string values are redacted."""
    out: Any = POLICY.json(None, {"nested": [{key: "value"}]})
    assert out == {"nested": [{key: REDACTED}]}


@pytest.mark.parametrize("suffix", SAFE_SUFFIXES)
def test_generic_safe_suffixes(suffix: str) -> None:
    """Keys ending with an allow-listed suffix are kept."""
    data = {f"Secret{suffix}": "value", f"Password{suffix}": "value"}
    assert POLICY.json(None, data) == data


def test_generic_suffix_list_matches_design() -> None:
    """The allow-listed suffixes are exactly the documented ones."""
    assert set(SAFE_SUFFIXES) == {
        "Arn", "ARN", "Id", "Ids", "Name", "Type", "Status", "Enabled",
        "Date", "Time", "Version", "Policy", "Required", "Length",
        "Count", "Age", "Used", "Rotation", "Configuration"}


def test_generic_exemptions() -> None:
    """arn: values, empty strings and non-strings are kept."""
    data = {"Secret": "arn:aws:secretsmanager:us-east-1:1:secret:x",
            "Password": "", "Token": None, "ApiKey": 5,
            "PasswordReset": True}
    assert POLICY.json(None, data) == data


def test_generic_recurses_into_secret_named_containers() -> None:
    """A dict under a secret-looking key is searched, not replaced."""
    data = {"Credentials": {"AccessKeyId": "AKIA",
                            "SecretAccessKey": "s",
                            "SessionToken": "t"}}
    assert POLICY.json(None, data) == {
        "Credentials": {"AccessKeyId": "AKIA",
                        "SecretAccessKey": REDACTED,
                        "SessionToken": REDACTED}}


@pytest.mark.parametrize("key, entry, expected", [
    ("environment", {"name": "A", "value": "1"},
     {"name": "A", "value": REDACTED}),
    ("Environment", {"Name": "A", "Value": "1"},
     {"Name": "A", "Value": REDACTED}),
    ("EnvironmentVariables", {"Name": "A", "Value": "1"},
     {"Name": "A", "Value": REDACTED}),
    ("environmentVariables", {"name": "A", "value": "1"},
     {"name": "A", "value": REDACTED}),
    ("environment", {"value": "1"}, {"value": "1"}),
    ("environment", {"name": "A"}, {"name": "A"}),
    ("environments", {"name": "A", "value": "1"},
     {"name": "A", "value": "1"}),
])
def test_generic_env_lists(key: str, entry: dict[str, Any],
                           expected: dict[str, Any]) -> None:
    """Name/Value env lists are redacted at any depth."""
    data = {"containers": [{key: [entry]}]}
    assert POLICY.json(None, data) == {"containers": [{key: [expected]}]}


def test_tag_values_not_redacted() -> None:
    """Tag lists keep values even for secret-looking keys."""
    data = {"Tags": [{"Key": "DbPassword", "Value": "visible"}]}
    assert POLICY.json(None, data) == data


def test_rule_and_generic_combined() -> None:
    """The generic heuristic runs after the rule set."""
    data = {"Environment": {"Variables": {"A": "1"}},
            "Config": {"Password": "x", "User": "u"}}
    assert POLICY.json("lambda", data) == {
        "Environment": {"Variables": {"A": REDACTED}},
        "Config": {"Password": REDACTED, "User": "u"}}


def test_input_not_mutated_and_copy_returned() -> None:
    """json() returns a deep copy; the cached raw data is untouched."""
    data = {"Environment": {"Variables": {"A": "1"}},
            "Password": "x", "List": [{"Token": "t"}]}
    snapshot = copy.deepcopy(data)
    out: Any = POLICY.json("lambda", data)
    assert data == snapshot
    out["List"][0]["Other"] = 1
    assert data == snapshot


def test_reveal_passthrough() -> None:
    """reveal=True returns inputs unchanged and redacts nothing."""
    data = {"Environment": {"Variables": {"A": "1"}}, "Password": "x"}
    assert REVEAL.json("lambda", data) == data
    assert REVEAL.whole_file("user-data") is False
    assert REVEAL.whole_file("template") is False
    assert REVEAL.text("user-data", "raw") == "raw"
    assert REVEAL.text("user-data", b"\x00raw") == b"\x00raw"


def test_whole_file_rules() -> None:
    """user-data and template are whole-file rules."""
    assert POLICY.whole_file("user-data") is True
    assert POLICY.whole_file("template") is True
    assert POLICY.whole_file("lambda") is False
    assert POLICY.text("user-data", "secret") == REDACTED
    assert POLICY.text("template", b"x") == REDACTED
    assert POLICY.text("lambda", "kept") == "kept"


# ---------------------------------------------------------------------
# through the tree
# ---------------------------------------------------------------------


def test_describe_json_applies_rule(vfs: VFS, fake: Any) -> None:
    """describe.json is redacted at render time."""
    data = json.loads(vfs.read(f"{fake.base}/widgets/w-1/describe.json"))
    assert data["Environment"]["Variables"] == {
        "DB_PASSWORD": REDACTED, "MODE": REDACTED}
    assert data["Color"] == "red"


def test_describe_json_reveal(make_ctx: Callable[..., Context],
                              fake: Any) -> None:
    """--reveal shows raw values."""
    vfs = build_vfs(make_ctx(reveal=True))
    data = json.loads(vfs.read(f"{fake.base}/widgets/w-1/describe.json"))
    assert data["Environment"]["Variables"] == {
        "DB_PASSWORD": "hunter2", "MODE": "prod"}


def test_user_data_redacted_without_api_call(vfs: VFS, backend: Any,
                                             fake: Any) -> None:
    """Whole-file redaction: marker content, size, no API call."""
    path = f"{fake.base}/widgets/w-1/user-data"
    assert vfs.stat(path).size == len(REDACTED) + 1
    assert vfs.read(path) == (REDACTED + "\n").encode()
    assert backend.count("fake", "get_widget_user_data") == 0


def test_user_data_reveal_fetches_raw_bytes(
        make_ctx: Callable[..., Context], backend: Any,
        fake: Any) -> None:
    """With --reveal: one call, base64-decoded raw bytes."""
    vfs = build_vfs(make_ctx(reveal=True))
    path = f"{fake.base}/widgets/w-1/user-data"
    assert vfs.read(path) == fake.user_data
    assert vfs.stat(path).size == len(fake.user_data)
    assert backend.count("fake", "get_widget_user_data") == 1


def test_tags_not_redacted_in_tree(vfs: VFS, fake: Any) -> None:
    """tags.json and tags/<Key> keep values (documented)."""
    w1 = f"{fake.base}/widgets/w-1"
    tags = json.loads(vfs.read(f"{w1}/tags.json"))
    assert tags == {"ApiToken": "tag-value-kept", "Name": "first",
                    "team/owner": "ops"}
    assert list(tags) == sorted(tags)
    assert vfs.listdir(f"{w1}/tags") == ["ApiToken", "Name",
                                         "team%2Fowner"]
    assert vfs.read(f"{w1}/tags/ApiToken") == b"tag-value-kept\n"
    assert vfs.read(f"{w1}/tags/team%2Fowner") == b"ops\n"
