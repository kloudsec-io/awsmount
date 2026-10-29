"""Regression tests for review findings B (correctness).

Each test reproduces one finding against real moto resources (or real
awsmount objects) and fails on the code before the fix:

* AWSM-003: a transient identity failure (or BudgetExceeded) was
  memoised as a failed account for the whole session.
* AWSM-004: FUSE metadata operations rendered lazy files (API calls).
* AWSM-006: KMS/S3 marker loops spun forever on a repeated marker.
* AWSM-007: collision suffixes pushed names past NAME_MAX (255 bytes).
* AWSM-008: collections without ``display`` had no casefold collision
  handling.
* AWSM-009: links to absent targets were emitted (dangling), and
  cross-account security group peers pointed into the own account.
* AWSM-010: ``refresh`` of a resource kept the stale listing item.
* AWSM-011: reserved / malformed region names crashed the tree.
* AWSM-012: ``umount`` of a non-mount point reported success.
* AWSM-013: exported subtree symlinks escaped the export directory.
* AWSM-014: budget exhaustion never appeared in any errors.log.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
import threading
import zipfile
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from botocore.exceptions import ClientError
from click.testing import CliRunner

from awsmount import platform as platform_mod
from awsmount.adapters.export import export
from awsmount.adapters.fuse.operations import AwsFuse
from awsmount.adapters.shell.commands import Shell
from awsmount.cli import cli
from awsmount.config import Config
from awsmount.errors import BudgetExceeded
from awsmount.providers import refs
from awsmount.providers import vpc as vpc_mod
from awsmount.providers.base import ResourceCtx
from awsmount.session.context import Context, Scope
from awsmount.session.errorlog import ErrorLog
from awsmount.tree.root import build_vfs
from awsmount.vfs.node import DirNode, SymlinkNode
from awsmount.vfs.path import MAX_NAME_BYTES, assign_names

_TESTS = Path(__file__).resolve().parents[1]


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


def _account_id(session: Any) -> str:
    sts = session.client("sts", region_name=REGION)
    return str(sts.get_caller_identity()["Account"])


def _bounded(fn: Callable[[], Any], timeout: float = 30.0) -> Any:
    """Run ``fn`` in a thread; fail (instead of hanging) on timeout."""
    box: dict[str, Any] = {}

    def run() -> None:
        try:
            box["value"] = fn()
        except BaseException as exc:
            box["error"] = exc

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout)
    assert not thread.is_alive(), "operation hung (marker loop)"
    if "error" in box:
        raise box["error"]
    return box.get("value")


def _shell(m: Any) -> Shell:
    return Shell(m.vfs, m.ctx, out=io.BytesIO(), err=io.StringIO(),
                 color=False)


# -- AWSM-003 ---------------------------------------------------------


def _flaky_identity(ctx: Context, failures: int) -> dict[str, int]:
    """Make the next ``failures`` GetCallerIdentity calls fail."""
    client = ctx.clients.get(None, REGION, "sts")
    state = {"left": failures}

    def refuse(**_kwargs: Any) -> None:
        if state["left"] > 0:
            state["left"] -= 1
            raise ClientError(
                {"Error": {"Code": "Throttling", "Message": "transient"},
                 "ResponseMetadata": {"HTTPStatusCode": 400}},
                "GetCallerIdentity")

    client.meta.events.register("before-call.sts.GetCallerIdentity",
                                refuse)
    return state


def test_awsm_003_failed_identity_is_retried(moto_session: Any) -> None:
    """A transient identity failure is retried after negative_ttl."""
    ctx = Context.from_config(Config(regions=(REGION,), negative_ttl=0.0,
                                     max_attempts=2))
    _flaky_identity(ctx, 1)
    vfs = build_vfs(ctx)
    assert vfs.listdir("/") == ["profile-default"]
    account = _account_id(moto_session)
    assert vfs.listdir("/") == [account]
    assert REGION in vfs.listdir(f"/{account}")


def test_awsm_003_budget_exceeded_not_memoised(moto_session: Any) -> None:
    """BudgetExceeded propagates instead of a memoised failed account."""
    ctx = Context.from_config(Config(regions=(REGION,), max_api_calls=3,
                                     max_attempts=2))
    for _ in range(3):
        ctx.budget.charge("test:prefill")
    with pytest.raises(BudgetExceeded):
        ctx.accounts.accounts()
    ctx.budget.reset()
    infos = ctx.accounts.accounts()
    assert len(infos) == 1
    assert infos[0].error is None
    assert infos[0].account_id == _account_id(moto_session)


def test_awsm_003_refresh_resets_accounts(moto_session: Any) -> None:
    """Shell ``refresh`` re-resolves a failed account."""
    ctx = Context.from_config(Config(regions=(REGION,),
                                     negative_ttl=600.0, max_attempts=2))
    _flaky_identity(ctx, 1)
    vfs = build_vfs(ctx)
    assert vfs.listdir("/") == ["profile-default"]
    sh = Shell(vfs, ctx, out=io.BytesIO(), err=io.StringIO(),
               color=False)
    assert sh.run_line("refresh") == 0
    assert vfs.listdir("/") == [_account_id(moto_session)]


# -- AWSM-004 ---------------------------------------------------------


def test_awsm_004_defaults_zero_for_fuse() -> None:
    """Config and ``--lazy-size`` default to zero (FUSE only)."""
    assert Config().lazy_size == "zero"
    mount = cli.commands["mount"]
    params = {p.name: p for p in mount.params}
    assert params["lazy_size"].default == "zero"


def test_awsm_004_fuse_getattr_no_api_calls(moto_session: Any) -> None:
    """getattr of lazy files is free; open/read gives full content."""
    sqs = moto_session.client("sqs", region_name=REGION)
    sqs.create_queue(QueueName="awsm-004-queue")
    m = Mount()
    base = m.path("sqs/queues/awsm-004-queue")
    names = m.ls(base)
    assert "describe.json" in names
    ops = AwsFuse(m.vfs, lazy_size=m.ctx.config.lazy_size)
    before = m.calls()
    sizes = {name: ops.getattr(f"{base}/{name}")["st_size"]
             for name in names}
    assert m.calls() == before
    assert sizes["describe.json"] == 0
    path = f"{base}/describe.json"
    fid = ops.open(path, os.O_RDONLY)
    try:
        data = ops.read(path, 1 << 20, 0, fid)
    finally:
        ops.release(path, fid)
    doc = json.loads(data)
    assert doc["Attributes"]["QueueArn"].endswith(":awsm-004-queue")
    assert data == m.read(path)


# -- AWSM-006 ---------------------------------------------------------


def test_awsm_006_kms_repeated_marker(moto_session: Any) -> None:
    """A repeated NextMarker no longer spins the tag loop forever."""
    kms = moto_session.client("kms", region_name=REGION)
    key = kms.create_key(
        Description="awsm-006",
        Tags=[{"TagKey": "team", "TagValue": "ops"}])["KeyMetadata"]
    key_id = str(key["KeyId"])
    m = Mount()
    client = m.ctx.clients.get(m.account.profile, REGION, "kms")

    def loop(parsed: Any = None, **_kwargs: Any) -> None:
        if isinstance(parsed, dict):
            parsed["Truncated"] = True
            parsed["NextMarker"] = "awsm-006-same-marker"

    client.meta.events.register("after-call.kms.ListResourceTags", loop)
    tags = _bounded(lambda: m.json(
        m.path(f"kms/keys/{key_id}/tags.json")))
    assert tags == {"team": "ops"}


def test_awsm_006_s3_repeated_token(moto_session: Any) -> None:
    """A repeated continuation token no longer spins the object loop."""
    s3 = moto_session.client("s3", region_name=REGION)
    bucket = "awsm-006-objects"
    s3.create_bucket(Bucket=bucket)
    for key in ("a", "b", "c"):
        s3.put_object(Bucket=bucket, Key=key, Body=b"x")
    # moto only accepts continuation tokens it issued: get a real one.
    token = s3.list_objects_v2(Bucket=bucket, MaxKeys=1)[
        "NextContinuationToken"]
    m = Mount(s3_objects=10)
    client = m.ctx.clients.get(m.account.profile, REGION, "s3")

    def loop(parsed: Any = None, **_kwargs: Any) -> None:
        if isinstance(parsed, dict):
            parsed["IsTruncated"] = True
            parsed["NextContinuationToken"] = token

    client.meta.events.register("after-call.s3.ListObjectsV2", loop)
    listing = _bounded(lambda: m.json(
        m.path(f"s3/buckets/{bucket}/objects-listing.json")))
    # The point: a server that keeps answering "truncated, same token"
    # must end the loop (it used to spin forever without any API call).
    assert {o["Key"] for o in listing} == {"a", "b", "c"}


# -- AWSM-007 ---------------------------------------------------------

LONG_A = "Logs/" + "A" * 290 + ".json"
LONG_B = LONG_A.lower()


def test_awsm_007_assign_names_respects_name_max() -> None:
    """Colliding long names stay within 255 bytes and unique."""
    names = assign_names([(LONG_A, LONG_A), (LONG_B, LONG_B)])
    assert len(names) == 2
    for name in names.values():
        assert len(name.encode("utf-8")) <= MAX_NAME_BYTES
    assert len({n.casefold() for n in names.values()}) == 2
    short = assign_names([("Q", "Q"), ("q", "q")])
    assert len({n.casefold() for n in short.values()}) == 2


def test_awsm_007_s3_object_names(moto_session: Any) -> None:
    """Long case-colliding S3 keys give valid, readable entries."""
    s3 = moto_session.client("s3", region_name=REGION)
    bucket = "awsm-007-long"
    s3.create_bucket(Bucket=bucket)
    for key in (LONG_A, LONG_B):
        s3.put_object(Bucket=bucket, Key=key, Body=b"x")
    m = Mount(s3_objects=10)
    objdir = m.path(f"s3/buckets/{bucket}/objects")
    names = m.ls(objdir)
    assert len(names) == 2
    for name in names:
        assert len(name.encode("utf-8")) <= MAX_NAME_BYTES
    assert len({n.casefold() for n in names}) == 2
    keys = {m.json(f"{objdir}/{name}")["Key"] for name in names}
    assert keys == {LONG_A, LONG_B}


# -- AWSM-008 ---------------------------------------------------------


def test_awsm_008_case_collisions_without_display(
        moto_session: Any) -> None:
    """SQS queues differing only by case get distinct names."""
    sqs = moto_session.client("sqs", region_name=REGION)
    urls = {sqs.create_queue(QueueName=q)["QueueUrl"]
            for q in ("awsm-008-Orders", "awsm-008-orders")}
    m = Mount()
    queues = m.path("sqs/queues")
    names = [n for n in m.ls(queues)
             if n.casefold().startswith("awsm-008-orders")]
    assert len(names) == 2
    assert len({n.casefold() for n in names}) == 2
    seen = {m.text(f"{queues}/{n}/url").strip() for n in names}
    assert seen == urls


# -- AWSM-009 ---------------------------------------------------------

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow",
                   "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}]})


def _lambda_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("handler.py",
                         "def handler(event, context):\n    return 1\n")
    return buffer.getvalue()


def _assert_no_dangling(m: Any, path: str) -> None:
    for name in m.ls(path):
        child = f"{path}/{name}"
        node = m.vfs.resolve(child, follow=False)
        if isinstance(node, SymlinkNode):
            m.vfs.resolve(child, follow=True)
        elif isinstance(node, DirNode):
            _assert_no_dangling(m, child)


def test_awsm_009_no_dangling_links(moto_session: Any) -> None:
    """A deleted role (and missing log group) gives no link at all."""
    iam = moto_session.client("iam", region_name=REGION)
    lam = moto_session.client("lambda", region_name=REGION)
    arns = {}
    for role in ("awsm-009-gone", "awsm-009-kept"):
        arns[role] = iam.create_role(
            RoleName=role, AssumeRolePolicyDocument=_TRUST)["Role"]["Arn"]
    code = {"ZipFile": _lambda_zip()}
    for fn, role in (("awsm-009-orphan", "awsm-009-gone"),
                     ("awsm-009-ok", "awsm-009-kept")):
        lam.create_function(FunctionName=fn, Runtime="python3.12",
                            Role=arns[role], Handler="handler.handler",
                            Code=code)
    iam.delete_role(RoleName="awsm-009-gone")
    m = Mount()
    orphan = m.path("lambda/functions/awsm-009-orphan/links")
    assert "role" not in m.ls(orphan)
    _assert_no_dangling(m, orphan)
    ok = m.path("lambda/functions/awsm-009-ok/links")
    assert "role" in m.ls(ok)
    assert m.target(f"{ok}/role") == m.gpath("iam/roles/awsm-009-kept")
    _assert_no_dangling(m, ok)


def test_awsm_009_cross_account_sg_peer(moto_session: Any) -> None:
    """Peer-account groups are account-qualified and never misrouted."""
    ec2 = moto_session.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.109.0.0/16")["Vpc"]["VpcId"]
    real = ec2.create_security_group(
        GroupName="awsm-009-real", Description="awsm-009",
        VpcId=vpc)["GroupId"]
    m = Mount()
    scope = Scope(m.account, REGION, False)
    peer = "sg-0abcdef0123456789"
    item = {"GroupId": real, "IpPermissionsEgress": [],
            "IpPermissions": [{
                "IpProtocol": "tcp", "FromPort": 1, "ToPort": 1,
                "UserIdGroupPairs": [
                    {"GroupId": peer, "UserId": "999999999999"},
                    {"GroupId": real, "UserId": m.account.account_id}],
            }]}
    rc = ResourceCtx(ctx=m.ctx, scope=scope, spec=vpc_mod.SECURITY_GROUPS,
                     item=item, key=real, dirname=real, path="/x",
                     parent=None)
    values = vpc_mod._referenced_groups(rc)
    peer_arn = f"arn:aws:ec2:{REGION}:999999999999:security-group/{peer}"
    assert values == sorted([peer_arn, real])
    links = m.ctx.links
    assert links.dirpath(scope, refs.SECURITY_GROUPS, peer_arn) is None
    assert links.dirpath(scope, refs.SECURITY_GROUPS, peer) is None
    found = links.dirpath(scope, refs.SECURITY_GROUPS, real)
    assert found == m.path(f"vpc/security-groups/{real}")


# -- AWSM-010 ---------------------------------------------------------


def _name_tag(ec2: Any, resource: str, value: str) -> None:
    ec2.create_tags(Resources=[resource],
                    Tags=[{"Key": "Name", "Value": value}])


def test_awsm_010_refresh_resource_refetches_item(
        moto_session: Any) -> None:
    """refresh on a resource dir (or a file in it) shows fresh data."""
    ec2 = moto_session.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.110.0.0/16")["Vpc"]["VpcId"]
    _name_tag(ec2, vpc, "awsm-010-before")
    m = Mount()
    base = m.path(f"vpc/vpcs/{vpc}")
    assert m.json(f"{base}/tags.json")["Name"] == "awsm-010-before"
    sh = _shell(m)
    _name_tag(ec2, vpc, "awsm-010-after")
    assert sh.run_line(f"refresh {base}") == 0
    assert m.json(f"{base}/tags.json")["Name"] == "awsm-010-after"
    assert m.text(f"{base}/name").strip() == "awsm-010-after"
    _name_tag(ec2, vpc, "awsm-010-file")
    assert sh.run_line(f"refresh {base}/tags.json") == 0
    assert m.json(f"{base}/tags.json")["Name"] == "awsm-010-file"


# -- AWSM-011 ---------------------------------------------------------


@pytest.mark.parametrize("region", ["global", "_meta", "us-east-1/x",
                                    "US-EAST-1", "nowhere", ""])
def test_awsm_011_bad_region_rejected(region: str) -> None:
    """Reserved or malformed region names fail validation."""
    with pytest.raises(ValueError):
        Config(regions=(region,))


def test_awsm_011_good_regions_accepted() -> None:
    """Real region names and ``all`` stay valid."""
    Config(regions=("all",))
    Config(regions=("us-east-1", "us-gov-west-1", "cn-north-1",
                    "eu-west-1", "ap-southeast-2"))


def test_awsm_011_cli_usage_error(moto_session: Any) -> None:
    """``--region global`` is a usage error (exit 2), not a crash."""
    result = CliRunner().invoke(cli, ["ls", "--region", "global", "/"])
    assert result.exit_code == 2, result.output
    result = CliRunner().invoke(
        cli, ["ls", "--region", "us-east-1,us-east-1/x", "/"])
    assert result.exit_code == 2, result.output


# -- AWSM-012 ---------------------------------------------------------


def test_awsm_012_umount_not_a_mount_point(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Unmounting a plain directory fails and runs no command."""
    ran: list[Any] = []

    def fake_run(*args: Any, **kwargs: Any) -> Any:
        ran.append(args)
        return subprocess.CompletedProcess(args, 0, b"", b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert platform_mod.unmount(tmp_path) is False
    assert ran == []
    result = CliRunner().invoke(cli, ["umount", str(tmp_path)])
    assert result.exit_code == 1
    text = result.output
    try:
        text += result.stderr
    except (ValueError, AttributeError):
        pass
    assert "not a mount point" in text
    assert ran == []


# -- AWSM-013 ---------------------------------------------------------


def test_awsm_013_export_keeps_only_internal_links(
        moto_session: Any, tmp_path: Path) -> None:
    """Subtree exports never contain links escaping the export."""
    ec2 = moto_session.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.113.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.113.1.0/24",
                               AvailabilityZone=f"{REGION}a")
    subnet_id = subnet["Subnet"]["SubnetId"]
    m = Mount(services=frozenset({"vpc"}))
    sub_root = m.path("vpc/subnets")
    dest = tmp_path / "snap"
    report = export(m.vfs, sub_root, dest)
    real_dest = os.path.realpath(dest)
    for root, dirs, files in os.walk(dest):
        for name in dirs + files:
            entry = os.path.join(root, name)
            if os.path.islink(entry):
                resolved = os.path.realpath(entry)
                assert resolved.startswith(real_dest + os.sep), entry
    link_file = dest / subnet_id / "links" / "vpc"
    assert link_file.is_file() and not link_file.is_symlink()
    expected = m.vfs.readlink(f"{sub_root}/{subnet_id}/links/vpc")
    assert link_file.read_text(encoding="utf-8").strip() == expected
    assert report.external >= 1

    whole = tmp_path / "region"
    report2 = export(m.vfs, m.region_root, whole)
    kept = whole / "vpc" / "subnets" / subnet_id / "links" / "vpc"
    assert kept.is_symlink()
    assert os.path.realpath(kept) == os.path.realpath(
        whole / "vpc" / "vpcs" / vpc)
    assert report2.links >= 1


# -- AWSM-014 ---------------------------------------------------------


def test_awsm_014_budget_event_in_errors_log(moto_session: Any) -> None:
    """Budget exhaustion is visible in the account's errors.log."""
    m = Mount(max_api_calls=3)
    for rel in ("vpc/vpcs", "vpc/subnets", "vpc/security-groups",
                "ec2/instances", "ec2/volumes"):
        try:
            m.ls(m.path(rel))
        except BudgetExceeded:
            break
    else:
        pytest.fail("budget never exhausted")
    rows = m.error_lines()
    assert any(len(cols) >= 6 and cols[5] == "budget" for cols in rows)


def test_awsm_014_render_unscoped_rows() -> None:
    """Session-wide rows are kept by the per-account filter on demand."""
    log = ErrorLog()
    log.record(None, "awsmount", "budget", BudgetExceeded("exhausted"))
    assert log.render("123456789012") == b""
    text = log.render("123456789012", include_unscoped=True)
    assert b"\tbudget\t" in text
