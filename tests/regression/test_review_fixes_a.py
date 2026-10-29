"""Regression tests for review findings A (security / redaction).

Each test reproduces one finding against real moto resources (or real
awsmount objects) and fails on the code before the fix:

* AWSM-001: CloudFormation outputs with secret-looking keys were served
  in clear in ``outputs.json`` and ``describe.json``.
* AWSM-005: parameters/outputs named ``DBPass``, ``AdminPwd``,
  ``MasterPass``, ``SlackWebhookKey``... escaped the secret-name check.
* AWSM-015: the op allow-list was not client-scoped (``GetPolicy``
  declared for lambda also passed for iam, ...).
* AWSM-002: the EKS Connector ``activationCode`` was not redacted.
* AWSM-016: docs claimed the WebDAV URL token was secret; it is not,
  and HTTP auth must stay mandatory.
"""

from __future__ import annotations

import http.client
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from botocore.exceptions import ClientError

from awsmount.errors import ForbiddenOperation
from awsmount.providers import ProviderRegistry
from awsmount.session.redact import (
    REDACTED,
    RedactionPolicy,
    is_secret_name,
)

_TESTS = Path(__file__).resolve().parents[1]
_REPO = _TESTS.parent


def _load_kit() -> ModuleType:
    """Load tests/providers/motokit.py by path (any import mode)."""
    name = "awsmount_tests_motokit"
    module = sys.modules.get(name)
    if module is not None:
        return module
    spec = importlib.util.spec_from_file_location(
        name, _TESTS / "providers" / "motokit.py")
    if spec is None or spec.loader is None:
        raise ImportError("cannot load motokit")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        del sys.modules[name]
        raise
    return module


kit = _load_kit()
moto_session = kit.moto_session
Mount = kit.Mount
REGION: str = kit.REGION
FAKE_SECRET: str = kit.FAKE_SECRET

# -- CloudFormation (AWSM-001, AWSM-005) ------------------------------

CFN_STACK = "awsm-001-outputs"
SECRET_PARAMS = ("DBPass", "AdminPwd", "MasterPass", "SlackWebhookKey",
                 "ClusterPsk")
SECRET_OUTPUTS = ("SecretKey", "DBPass", "AdminPwd", "SlackWebhookKey")
VISIBLE_PARAM = "Environment"
VISIBLE_PARAM_VALUE = "prod-visible"
VISIBLE_OUTPUT = "PublicEndpoint"
VISIBLE_OUTPUT_VALUE = "https://app.example.invalid/"


def _secret(kind: str, key: str) -> str:
    return f"{FAKE_SECRET}-{kind}-{key}"


@pytest.fixture(scope="module")
def cfn_stack(moto_session: Any) -> str:
    """A stack whose parameters and outputs carry secret values."""
    cfn = moto_session.client("cloudformation", region_name=REGION)
    parameters: dict[str, Any] = {k: {"Type": "String"}
                                  for k in SECRET_PARAMS}
    parameters[VISIBLE_PARAM] = {"Type": "String"}
    outputs: dict[str, Any] = {k: {"Value": _secret("output", k)}
                               for k in SECRET_OUTPUTS}
    outputs[VISIBLE_OUTPUT] = {"Value": VISIBLE_OUTPUT_VALUE}
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": parameters,
        "Resources": {"Handle": {
            "Type": "AWS::CloudFormation::WaitConditionHandle"}},
        "Outputs": outputs,
    }
    values = [{"ParameterKey": k, "ParameterValue": _secret("param", k)}
              for k in SECRET_PARAMS]
    values.append({"ParameterKey": VISIBLE_PARAM,
                   "ParameterValue": VISIBLE_PARAM_VALUE})
    cfn.create_stack(StackName=CFN_STACK,
                     TemplateBody=json.dumps(template, sort_keys=True),
                     Parameters=values)
    return CFN_STACK


def _by(items: list[dict[str, Any]], key: str,
        value: str) -> dict[str, Any]:
    return {str(i[key]): i.get(value) for i in items}


def test_awsm_001_outputs_redacted_everywhere(moto_session: Any,
                                              cfn_stack: str) -> None:
    """Secret outputs are redacted in outputs.json and describe.json."""
    m = Mount()
    base = m.path(f"cloudformation/stacks/{cfn_stack}")
    outputs = _by(m.json(f"{base}/outputs.json"), "OutputKey",
                  "OutputValue")
    described = _by(m.json(f"{base}/describe.json")["Outputs"],
                    "OutputKey", "OutputValue")
    for rendered in (outputs, described):
        for key in SECRET_OUTPUTS:
            assert rendered[key] == REDACTED, key
        assert rendered[VISIBLE_OUTPUT] == VISIBLE_OUTPUT_VALUE
    assert FAKE_SECRET not in m.text(f"{base}/outputs.json")
    assert FAKE_SECRET not in m.text(f"{base}/describe.json")
    assert m.grep(base, FAKE_SECRET) == []


def test_awsm_001_outputs_revealed_with_reveal(moto_session: Any,
                                               cfn_stack: str) -> None:
    """``--reveal`` still shows the real output values."""
    m = Mount(reveal=True)
    base = m.path(f"cloudformation/stacks/{cfn_stack}")
    outputs = _by(m.json(f"{base}/outputs.json"), "OutputKey",
                  "OutputValue")
    for key in SECRET_OUTPUTS:
        assert outputs[key] == _secret("output", key)


def test_awsm_005_parameter_names_widened(moto_session: Any,
                                          cfn_stack: str) -> None:
    """DBPass/AdminPwd/MasterPass/SlackWebhookKey/...Psk are redacted."""
    m = Mount()
    base = m.path(f"cloudformation/stacks/{cfn_stack}")
    params = _by(m.json(f"{base}/parameters.json"), "ParameterKey",
                 "ParameterValue")
    described = _by(m.json(f"{base}/describe.json")["Parameters"],
                    "ParameterKey", "ParameterValue")
    for rendered in (params, described):
        for key in SECRET_PARAMS:
            assert rendered[key] == REDACTED, key
        assert rendered[VISIBLE_PARAM] == VISIBLE_PARAM_VALUE
    assert FAKE_SECRET not in m.text(f"{base}/parameters.json")


def test_awsm_005_secret_name_matcher() -> None:
    """The CFN name matcher covers pass/pwd/psk/webhook/key suffix."""
    for name in ("DBPass", "AdminPwd", "MasterPass", "SlackWebhookKey",
                 "ClusterPsk", "SecretKey", "DbPassword", "ApiToken",
                 "SigningKey", "AccessKeys"):
        assert is_secret_name(name), name
    for name in ("Environment", "VpcId", "InstanceType",
                 "PublicEndpoint", "WebSGId"):
        assert not is_secret_name(name), name
    policy = RedactionPolicy(False)
    rows = [{"OutputKey": "DBPass", "OutputValue": "x1"},
            {"OutputKey": "VpcId", "OutputValue": "vpc-1"}]
    out = policy.json("cfn-params", rows)
    assert out == [{"OutputKey": "DBPass", "OutputValue": REDACTED},
                   {"OutputKey": "VpcId", "OutputValue": "vpc-1"}]
    assert rows[0]["OutputValue"] == "x1"


# -- client-scoped allow-list (AWSM-015) ------------------------------


def test_awsm_015_allow_list_is_client_scoped(moto_session: Any) -> None:
    """Same-named ops declared for another client are refused."""
    m = Mount()
    profile = m.account.profile
    clients = m.ctx.clients
    before = m.calls()
    iam = clients.get(profile, REGION, "iam")
    with pytest.raises(ForbiddenOperation):
        iam.get_policy(
            PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess")
    ecs = clients.get(profile, REGION, "ecs")
    with pytest.raises(ForbiddenOperation):
        ecs.list_tags_for_resource(
            resourceArn=f"arn:aws:ecs:{REGION}:"
                        f"{m.account.account_id}:cluster/none")
    apigw2 = clients.get(profile, REGION, "apigatewayv2")
    with pytest.raises(ForbiddenOperation):
        apigw2.get_stages(ApiId="abc123")
    assert m.calls() == before
    lam = clients.get(profile, REGION, "lambda")
    try:
        lam.get_policy(FunctionName="awsm-015-does-not-exist")
    except ForbiddenOperation:
        pytest.fail("lambda:GetPolicy is declared and must pass")
    except ClientError:
        pass
    pairs = ProviderRegistry().allowed_pairs()
    assert ("lambda", "GetPolicy") in pairs
    assert ("iam", "GetPolicy") not in pairs
    assert ("sts", "GetCallerIdentity") in clients.allowed_pairs
    assert not clients.is_allowed("iam", "GetPolicy")
    assert clients.is_allowed("lambda", "GetPolicy")


# -- EKS connector activation code (AWSM-002) -------------------------

EKS_NAME = "awsm-002-connector"
ACTIVATION_ID = "awsm002-activation-id"
ACTIVATION_CODE = "awsm002ActivationCodeDoNotLeak"
CONNECTOR: dict[str, str] = {
    "activationId": ACTIVATION_ID,
    "activationCode": ACTIVATION_CODE,
    "provider": "OTHER",
    "roleArn": "arn:aws:iam::123456789012:role/eks-connector",
}


@pytest.fixture(scope="module")
def eks_cluster(moto_session: Any) -> str:
    """A real moto EKS cluster."""
    ec2 = moto_session.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.99.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.99.1.0/24",
                               AvailabilityZone=f"{REGION}a")
    subnet_id = subnet["Subnet"]["SubnetId"]
    account = moto_session.client(
        "sts", region_name=REGION).get_caller_identity()["Account"]
    eks = moto_session.client("eks", region_name=REGION)
    eks.create_cluster(
        name=EKS_NAME, roleArn=f"arn:aws:iam::{account}:role/awsm-002",
        resourcesVpcConfig={"subnetIds": [subnet_id]})
    return EKS_NAME


def _inject_connector(m: Any) -> None:
    """Add connectorConfig to DescribeCluster (moto lacks the field)."""
    client = m.ctx.clients.get(m.account.profile, REGION, "eks")

    def inject(parsed: Any = None, **_kwargs: Any) -> None:
        if isinstance(parsed, dict) and \
                isinstance(parsed.get("cluster"), dict):
            parsed["cluster"]["connectorConfig"] = dict(CONNECTOR)

    client.meta.events.register("after-call.eks.DescribeCluster", inject)


def test_awsm_002_eks_activation_code_redacted(moto_session: Any,
                                               eks_cluster: str) -> None:
    """activationCode is redacted; activationId is kept."""
    m = Mount()
    _inject_connector(m)
    base = m.path(f"eks/clusters/{eks_cluster}")
    text = m.text(f"{base}/describe.json")
    assert ACTIVATION_CODE not in text
    connector = json.loads(text)["cluster"]["connectorConfig"]
    assert connector["activationCode"] == REDACTED
    assert connector["activationId"] == ACTIVATION_ID
    assert m.grep(base, ACTIVATION_CODE) == []


def test_awsm_002_eks_activation_code_reveal(moto_session: Any,
                                             eks_cluster: str) -> None:
    """With ``--reveal`` the activation code is shown."""
    m = Mount(reveal=True)
    _inject_connector(m)
    data = m.json(m.path(f"eks/clusters/{eks_cluster}/describe.json"))
    assert data["cluster"]["connectorConfig"]["activationCode"] == \
        ACTIVATION_CODE


# -- WebDAV token is not a secret (AWSM-016) --------------------------


def _get(port: int, path: str,
         headers: dict[str, str] | None = None) -> tuple[int, bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    try:
        conn.request("GET", path, headers=headers or {})
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def test_awsm_016_token_alone_grants_nothing(make_tree: Any) -> None:
    """Knowing the (public) token without the password gives 401."""
    pytest.importorskip("wsgidav")
    pytest.importorskip("cheroot")
    from awsmount.adapters.webdav.server import WebDavServer

    vfs = make_tree({"hello.txt": "world"})
    with WebDavServer(vfs, port=0) as server:
        creds = server.credentials
        path = f"{creds.prefix}/hello.txt"
        status, _body = _get(server.port, path)
        assert status == 401
        status, body = _get(server.port, path,
                            {"Authorization": creds.basic_header()})
        assert status == 200
        assert body == b"world\n"


def test_awsm_016_docs_treat_token_as_public() -> None:
    """Docs say the token is not secret; the password never hits argv."""
    pytest.importorskip("wsgidav")
    from awsmount.adapters.webdav import auth, macos

    assert auth.__doc__ is not None and "not a secret" in auth.__doc__
    assert macos.__doc__ is not None and "not a secret" in macos.__doc__
    creds = auth.Credentials.generate()
    argv = macos.mount_command(f"http://127.0.0.1:1{creds.prefix}/",
                               "/tmp/awsm-016")
    assert any(creds.token in arg for arg in argv)
    assert not any(creds.password in arg for arg in argv)
    assert creds.password not in repr(creds)
    for rel in ("README.md", "docs/security.md",
                "docs/mounting-macos.md"):
        text = (_REPO / rel).read_text(encoding="utf-8")
        assert "not a secret" in text, rel
