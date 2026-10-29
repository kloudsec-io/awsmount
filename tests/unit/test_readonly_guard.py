"""The read-only guard on every boto3 client (ARCHITECTURE: Read-only guard).

Nothing here reaches the network: the endpoint is a closed local port,
and a ``before-send`` spy proves whether a request would have left the
process. Forbidden operations must fail in ``before-call``, before any
request is built or sent.
"""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from awsmount.config import Config
from awsmount.errors import BudgetExceeded, ForbiddenOperation
from awsmount.providers import ProviderRegistry
from awsmount.providers.base import CollectionSpec, ServiceSpec
from awsmount.session.budget import ApiBudget
from awsmount.session.clients import (
    BOOTSTRAP_OPS,
    DENIED_OPS,
    READ_PREFIXES,
    ClientFactory,
    is_read_only_op,
)
from awsmount.session.progress import Progress

ENDPOINT = "http://127.0.0.1:9"
TESTS_DIR = Path(__file__).resolve().parent.parent

EXPECTED_DENIED = frozenset({
    "GetSecretValue", "BatchGetSecretValue", "GetParameter",
    "GetParameters", "GetParametersByPath", "GetParameterHistory",
    "GetObject", "GetObjectTorrent", "SelectObjectContent",
    "GetObjectAttributes", "Decrypt", "GenerateDataKey",
    "GenerateDataKeyWithoutPlaintext", "GetPasswordData",
    "GetAuthorizationToken", "GetSessionToken", "GetFederationToken",
    "GetFunction", "GetLayerVersion", "ExportCertificate",
    "GetLogEvents", "FilterLogEvents", "GetQueryResults",
    "GetConsoleOutput", "GetConsoleScreenshot", "GetLaunchTemplateData",
    "GetApiKey", "GetApiKeys", "GetExport", "GetSdk",
})

WRITE_OPS = (
    "DeleteBucket", "PutObject", "CreateBucket", "CopyObject",
    "RestoreObject", "PutBucketPolicy", "RunInstances",
    "TerminateInstances", "StopInstances", "StartInstances",
    "RebootInstances", "CreateTags", "DeleteTags",
    "ModifyInstanceAttribute", "AuthorizeSecurityGroupIngress",
    "RevokeSecurityGroupEgress", "AttachVolume", "DetachVolume",
    "CreateUser", "DeleteUser", "DeleteRole", "AttachRolePolicy",
    "PutRolePolicy", "UpdateAssumeRolePolicy", "CreateAccessKey",
    "Invoke", "InvokeAsync", "UpdateFunctionCode",
    "UpdateFunctionConfiguration", "AddPermission", "SendMessage",
    "ReceiveMessage", "PurgeQueue", "SetQueueAttributes",
    "ChangeMessageVisibility", "Publish", "Subscribe",
    "SetTopicAttributes", "PutSecretValue", "RestoreSecret",
    "RotateSecret", "PutParameter", "Encrypt", "ReEncrypt",
    "ScheduleKeyDeletion", "EnableKeyRotation", "DisableKey",
    "PutItem", "BatchWriteItem", "BatchGetItem", "Scan", "Query",
    "ExecuteStatement", "CreateStack", "UpdateStack", "DeleteStack",
    "ExecuteChangeSet", "AssumeRole", "AssumeRoleWithWebIdentity",
    "TagResource", "UntagResource", "StartQuery", "RequestCertificate",
    "ImportCertificate", "ChangeResourceRecordSets",
    "CreateInvalidation", "CreateDeployment",
)

READ_OPS = (
    "DescribeInstances", "ListBuckets", "GetBucketPolicy",
    "ListFunctions", "GetRolePolicy", "SearchResources", "LookupEvents",
    "DescribeLogGroups", "ListSecrets", "DescribeParameters",
)

UNLISTED_READ_OPS = (
    "DescribeVolumes", "ListUsers", "GetBucketAcl",
    "LookupDeveloperIdentity", "SearchProducts", "Describe",
)

SNEAKY_OPS = ("describeInstances", "listBuckets", "")

ALLOWED = (frozenset(WRITE_OPS) | DENIED_OPS | frozenset(READ_OPS)
           | frozenset(SNEAKY_OPS))


class _Sent(Exception):
    """Raised by the before-send spy: a request would leave."""


class _Model:
    """Operation model stand-in carrying an arbitrary name.

    botocore's own ``before-call`` handlers run after the guard and read
    attributes of the operation model, so every attribute other than
    ``name`` is taken from a real STS operation model.
    """

    is_endpoint_discovery_operation = False

    def __init__(self, name: str, service_model: Any) -> None:
        self.name = name
        self.service_model = service_model
        self._real = service_model.operation_model("GetCallerIdentity")

    def __getattr__(self, attr: str) -> Any:
        return getattr(self._real, attr)


def _fake_service() -> ServiceSpec:
    """Locate the in-memory fake provider defined by a test conftest.

    pytest imports every ``conftest.py`` under the same module name, so
    ``import conftest`` returns whichever one was loaded last. Look for
    an already-loaded test conftest defining ``FAKE_SERVICE`` first,
    then load the candidates by file path under private names.
    """
    for module in list(sys.modules.values()):
        file = getattr(module, "__file__", None) or ""
        if (Path(file).name == "conftest.py"
                and hasattr(module, "FAKE_SERVICE")):
            return module.FAKE_SERVICE  # type: ignore[no-any-return]
    candidates = (TESTS_DIR / "unit" / "conftest.py",
                  TESTS_DIR / "conftest.py")
    for index, path in enumerate(candidates):
        if not path.is_file():
            continue
        name = f"awsmount_tests_fake_conftest_{index}"
        module = sys.modules.get(name)
        if module is None:
            spec = importlib.util.spec_from_file_location(name, path)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            try:
                spec.loader.exec_module(module)
            except BaseException:
                sys.modules.pop(name, None)
                raise
        if hasattr(module, "FAKE_SERVICE"):
            return module.FAKE_SERVICE  # type: ignore[no-any-return]
    raise LookupError("no test conftest defines FAKE_SERVICE")


def _fake_env(mp: pytest.MonkeyPatch, home: Path) -> None:
    mp.setenv("AWS_ACCESS_KEY_ID", "testing")
    mp.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    mp.setenv("AWS_DEFAULT_REGION", "us-east-1")
    mp.setenv("AWS_CONFIG_FILE", str(home / "config"))
    mp.setenv("AWS_SHARED_CREDENTIALS_FILE", str(home / "credentials"))
    mp.setenv("AWS_EC2_METADATA_DISABLED", "true")
    mp.delenv("AWS_PROFILE", raising=False)
    mp.delenv("AWS_SESSION_TOKEN", raising=False)


def _factory(allowed: frozenset[str], limit: int = 0
             ) -> tuple[ClientFactory, ApiBudget]:
    budget = ApiBudget(limit, 0)
    config = Config(endpoint_url=ENDPOINT, max_attempts=1)
    return ClientFactory(config, budget, Progress(False), allowed), budget


def _spy(client: Any) -> list[str]:
    sent: list[str] = []

    def before_send(request: Any, **_kwargs: Any) -> None:
        sent.append(str(request.url))
        raise _Sent(str(request.url))

    client.meta.events.register("before-send", before_send)
    return sent


@pytest.fixture
def aws_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Fake credentials, no shared config, no IMDS."""
    _fake_env(monkeypatch, tmp_path)


@pytest.fixture(scope="module")
def guarded(tmp_path_factory: pytest.TempPathFactory
            ) -> Iterator[tuple[Any, ApiBudget]]:
    """One guarded STS client whose allow-list includes bad ops."""
    with pytest.MonkeyPatch.context() as mp:
        _fake_env(mp, tmp_path_factory.mktemp("aws"))
        factory, budget = _factory(ALLOWED)
        yield factory.get(None, "us-east-1", "sts"), budget


def _emit(client: Any, name: str) -> None:
    params = {"headers": {}, "body": b"", "url_path": "/",
              "query_string": {}, "method": "POST",
              "url": ENDPOINT + "/", "context": {}}
    client.meta.events.emit(
        f"before-call.sts.{name or 'Empty'}",
        model=_Model(name, client.meta.service_model),
        params=params, request_signer=None, context={})


# ---------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------


def test_denied_ops_are_the_documented_set() -> None:
    """DENIED_OPS is exactly the documented set."""
    assert DENIED_OPS == EXPECTED_DENIED


def test_prefixes_and_bootstrap_match_design() -> None:
    """READ_PREFIXES and BOOTSTRAP_OPS are as designed."""
    assert READ_PREFIXES == ("Describe", "List", "Get", "Search",
                             "Lookup")
    assert BOOTSTRAP_OPS == frozenset({"GetCallerIdentity",
                                       "ListAccountAliases",
                                       "DescribeRegions"})


@pytest.mark.parametrize("name", WRITE_OPS + SNEAKY_OPS)
def test_is_read_only_rejects_writes(name: str) -> None:
    """Write-ish names fail the prefix check."""
    assert not is_read_only_op(name)


@pytest.mark.parametrize("name", sorted(EXPECTED_DENIED))
def test_is_read_only_rejects_denied(name: str) -> None:
    """Data-plane reads are denied despite read prefixes."""
    assert not is_read_only_op(name)


@pytest.mark.parametrize("name", READ_OPS + UNLISTED_READ_OPS)
def test_is_read_only_accepts_reads(name: str) -> None:
    """Describe/List/Get/Search/Lookup names pass."""
    assert is_read_only_op(name)


def test_registry_allow_lists_are_read_only() -> None:
    """Every op in the shipped and fake registries is read-only."""
    fake = _fake_service()
    for registry in (ProviderRegistry(), ProviderRegistry((fake,))):
        for op in registry.allowed_ops():
            assert op.startswith(READ_PREFIXES), op
            assert op not in DENIED_OPS, op
        assert registry.validate() == []


def test_registry_validate_flags_bad_ops() -> None:
    """validate() reports write and denied ops in a spec."""
    spec = CollectionSpec(
        name="things", client="fake", lister=lambda lc: [],
        key=lambda i: str(i["Id"]),
        ops=frozenset({"DeleteThing", "GetSecretValue", "ListThings"}))
    problems = ProviderRegistry(
        (ServiceSpec("bad", "region", (spec,)),)).validate()
    assert any("DeleteThing" in p for p in problems)
    assert any("GetSecretValue" in p for p in problems)
    assert not any("ListThings" in p for p in problems)


# ---------------------------------------------------------------------
# guard via the before-call event
# ---------------------------------------------------------------------


@pytest.mark.parametrize("name", WRITE_OPS)
def test_guard_rejects_write_ops_even_if_allow_listed(
        guarded: tuple[Any, ApiBudget], name: str) -> None:
    """Write ops are refused even when a buggy spec lists them."""
    client, budget = guarded
    used = budget.used()
    with pytest.raises(ForbiddenOperation):
        _emit(client, name)
    assert budget.used() == used


@pytest.mark.parametrize("name", sorted(EXPECTED_DENIED))
def test_guard_rejects_denied_ops_even_if_allow_listed(
        guarded: tuple[Any, ApiBudget], name: str) -> None:
    """DENIED_OPS are refused even when allow-listed."""
    client, budget = guarded
    used = budget.used()
    with pytest.raises(ForbiddenOperation):
        _emit(client, name)
    assert budget.used() == used


@pytest.mark.parametrize("name", SNEAKY_OPS)
def test_guard_prefix_is_case_sensitive(
        guarded: tuple[Any, ApiBudget], name: str) -> None:
    """'describeInstances' or '' do not pass the prefix check."""
    client, _budget = guarded
    with pytest.raises(ForbiddenOperation):
        _emit(client, name)


@pytest.mark.parametrize("name", UNLISTED_READ_OPS)
def test_guard_rejects_reads_not_allow_listed(
        guarded: tuple[Any, ApiBudget], name: str) -> None:
    """A read op outside the allow-list is refused."""
    client, _budget = guarded
    with pytest.raises(ForbiddenOperation):
        _emit(client, name)


@pytest.mark.parametrize("name", READ_OPS)
def test_guard_allows_listed_reads_and_charges(
        guarded: tuple[Any, ApiBudget], name: str) -> None:
    """Allow-listed read ops pass and cost one budget unit."""
    client, budget = guarded
    used = budget.used()
    _emit(client, name)
    assert budget.used() == used + 1


@pytest.mark.parametrize("name", sorted(BOOTSTRAP_OPS))
def test_guard_allows_bootstrap_without_allow_list(
        aws_env: None, name: str) -> None:
    """Bootstrap ops pass with an empty allow-list."""
    factory, budget = _factory(frozenset())
    client = factory.get(None, "us-east-1", "sts")
    _emit(client, name)
    assert budget.used() == 1
    with pytest.raises(ForbiddenOperation):
        _emit(client, "ListBuckets")


# ---------------------------------------------------------------------
# guard on real client method calls
# ---------------------------------------------------------------------

FORBIDDEN_CALLS = [
    ("s3", "delete_bucket", {"Bucket": "awsmount-test"}),
    ("s3", "put_object", {"Bucket": "awsmount-test", "Key": "k",
                          "Body": b"x"}),
    ("s3", "get_object", {"Bucket": "awsmount-test", "Key": "k"}),
    ("secretsmanager", "get_secret_value", {"SecretId": "s"}),
    ("secretsmanager", "put_secret_value", {"SecretId": "s",
                                            "SecretString": "x"}),
    ("ssm", "get_parameter", {"Name": "/p"}),
    ("ssm", "put_parameter", {"Name": "/p", "Value": "v",
                              "Type": "String"}),
    ("ec2", "run_instances", {"ImageId": "ami-12345678", "MinCount": 1,
                              "MaxCount": 1}),
    ("ec2", "terminate_instances", {"InstanceIds": ["i-12345678"]}),
    ("ec2", "get_password_data", {"InstanceId": "i-12345678"}),
    ("lambda", "invoke", {"FunctionName": "fn"}),
    ("lambda", "get_function", {"FunctionName": "fn"}),
    ("iam", "create_user", {"UserName": "someone"}),
    ("kms", "decrypt", {"CiphertextBlob": b"blob"}),
    ("sts", "assume_role", {
        "RoleArn": "arn:aws:iam::123456789012:role/r",
        "RoleSessionName": "session"}),
    ("dynamodb", "scan", {"TableName": "table-name"}),
]


@pytest.mark.parametrize(
    "service, method, params", FORBIDDEN_CALLS,
    ids=[f"{s}.{m}" for s, m, _p in FORBIDDEN_CALLS])
def test_real_calls_refused_before_http(
        aws_env: None, service: str, method: str,
        params: dict[str, Any]) -> None:
    """Forbidden boto3 calls raise before any request is sent."""
    factory, budget = _factory(ALLOWED)
    client = factory.get(None, "us-east-1", service)
    sent = _spy(client)
    with pytest.raises(ForbiddenOperation):
        getattr(client, method)(**params)
    assert sent == []
    assert budget.used() == 0


def test_allowed_call_reaches_send_and_is_charged(aws_env: None) -> None:
    """An allow-listed read gets past the guard and is charged once."""
    factory, budget = _factory(frozenset({"ListBuckets"}))
    client = factory.get(None, "us-east-1", "s3")
    sent = _spy(client)
    with pytest.raises(_Sent):
        client.list_buckets()
    assert len(sent) == 1
    assert sent[0].startswith(ENDPOINT)
    assert budget.used() == 1


def test_bootstrap_call_reaches_send(aws_env: None) -> None:
    """get_caller_identity is allowed with an empty allow-list."""
    factory, budget = _factory(frozenset())
    client = factory.get(None, "us-east-1", "sts")
    sent = _spy(client)
    with pytest.raises(_Sent):
        client.get_caller_identity()
    assert len(sent) == 1
    assert budget.used() == 1


def test_read_not_allow_listed_refused(aws_env: None) -> None:
    """A real read call outside the allow-list is refused."""
    factory, budget = _factory(frozenset({"ListBuckets"}))
    client = factory.get(None, "us-east-1", "s3")
    sent = _spy(client)
    with pytest.raises(ForbiddenOperation):
        client.get_bucket_policy(Bucket="awsmount-test")
    assert sent == []
    assert budget.used() == 0


def test_budget_exhaustion_blocks_before_http(aws_env: None) -> None:
    """Past the budget the guard raises BudgetExceeded, nothing sent."""
    factory, budget = _factory(frozenset({"ListBuckets"}), limit=1)
    client = factory.get(None, "us-east-1", "s3")
    sent = _spy(client)
    with pytest.raises(_Sent):
        client.list_buckets()
    with pytest.raises(BudgetExceeded):
        client.list_buckets()
    assert len(sent) == 1
    assert budget.used() == 1


def test_clients_memoised_and_configured(aws_env: None) -> None:
    """One client per (profile, region, service); adaptive retries."""
    factory, _budget = _factory(frozenset())
    a = factory.get(None, "us-east-1", "s3")
    assert factory.get(None, "us-east-1", "s3") is a
    assert factory.get(None, "eu-west-1", "s3") is not a
    assert a.meta.endpoint_url.startswith(ENDPOINT)
    cfg = factory.botocore_config("ec2")
    assert cfg.retries == {"mode": "adaptive", "max_attempts": 1}
    assert cfg.max_pool_connections == 10
    assert "awsmount/1.0.0" in (cfg.user_agent_extra or "")


# ---------------------------------------------------------------------
# value reads: allowed only by `awsmount secrets`, only as exact pairs
# ---------------------------------------------------------------------

VALUE_PAIRS = frozenset({("secretsmanager", "GetSecretValue"),
                         ("ssm", "GetParameter")})
VALUE_CALLS = [
    ("secretsmanager", "get_secret_value", {"SecretId": "s"}),
    ("ssm", "get_parameter", {"Name": "/p", "WithDecryption": True}),
]
STILL_DENIED_CALLS = [
    ("secretsmanager", "batch_get_secret_value", {"SecretIdList": ["s"]}),
    ("ssm", "get_parameters", {"Names": ["/p"]}),
    ("ssm", "get_parameters_by_path", {"Path": "/"}),
    ("ssm", "get_parameter_history", {"Name": "/p"}),
    ("kms", "decrypt", {"CiphertextBlob": b"blob"}),
    ("s3", "get_object", {"Bucket": "awsmount-test", "Key": "k"}),
]


def _value_factory(allowed: set[tuple[str, str]],
                   values: frozenset[tuple[str, str]] = VALUE_PAIRS
                   ) -> tuple[ClientFactory, ApiBudget]:
    budget = ApiBudget(0, 0)
    config = Config(endpoint_url=ENDPOINT, max_attempts=1)
    return ClientFactory(config, budget, Progress(False), allowed,
                         value_ops=values), budget


@pytest.mark.parametrize(
    "service, method, params", VALUE_CALLS,
    ids=[f"{s}.{m}" for s, m, _p in VALUE_CALLS])
def test_value_ops_are_refused_when_no_value_ops_are_passed(
        aws_env: None, service: str, method: str,
        params: dict[str, Any]) -> None:
    """Every normal session: allow-listing a value op changes nothing."""
    factory, budget = _factory(frozenset(VALUE_PAIRS))
    client = factory.get(None, "us-east-1", service)
    sent = _spy(client)
    with pytest.raises(ForbiddenOperation):
        getattr(client, method)(**params)
    assert sent == [] and budget.used() == 0


@pytest.mark.parametrize(
    "service, method, params", VALUE_CALLS,
    ids=[f"{s}.{m}" for s, m, _p in VALUE_CALLS])
def test_value_ops_pass_when_passed_as_value_ops(
        aws_env: None, service: str, method: str,
        params: dict[str, Any]) -> None:
    factory, budget = _value_factory(set(VALUE_PAIRS))
    client = factory.get(None, "us-east-1", service)
    sent = _spy(client)
    with pytest.raises(_Sent):
        getattr(client, method)(**params)
    assert len(sent) == 1 and budget.used() == 1


@pytest.mark.parametrize(
    "service, method, params", STILL_DENIED_CALLS,
    ids=[f"{s}.{m}" for s, m, _p in STILL_DENIED_CALLS])
def test_other_value_ops_stay_denied_in_the_secrets_session(
        aws_env: None, service: str, method: str,
        params: dict[str, Any]) -> None:
    """Only the two exact pairs pass; the other readers stay blocked."""
    op = "".join(p.capitalize() for p in method.split("_"))
    allowed = set(VALUE_PAIRS) | {(service, op)}
    factory, budget = _value_factory(allowed)
    client = factory.get(None, "us-east-1", service)
    sent = _spy(client)
    with pytest.raises(ForbiddenOperation):
        getattr(client, method)(**params)
    assert sent == [] and budget.used() == 0


def test_a_value_op_must_be_on_the_allow_list(aws_env: None) -> None:
    with pytest.raises(ValueError):
        _value_factory({("ssm", "GetParameter")},
                       frozenset({("secretsmanager", "GetSecretValue")}))


def test_value_pairs_are_bound_to_their_client(aws_env: None) -> None:
    """GetParameter passes on ssm only, not on another client."""
    factory, _budget = _value_factory(set(VALUE_PAIRS))
    assert factory.is_allowed("ssm", "GetParameter")
    assert factory.is_allowed("secretsmanager", "GetSecretValue")
    assert not factory.is_allowed("secretsmanager", "GetParameter")
    assert not factory.is_allowed("ssm", "GetSecretValue")
    assert not factory.is_allowed("kms", "GetParameter")


def test_a_default_session_never_allows_a_value_op(aws_env: None) -> None:
    factory, _budget = _factory(ALLOWED)
    for service, name in VALUE_PAIRS:
        assert not factory.is_allowed(service, name)
    for name in EXPECTED_DENIED:
        assert not factory.is_allowed("secretsmanager", name)
        assert not factory.is_allowed("ssm", name)
