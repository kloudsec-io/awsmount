"""AccessDenied and budget degradation.

See ARCHITECTURE: Budget and limits, Error log.
"""

from __future__ import annotations

import errno
from collections.abc import Callable
from typing import Any

import pytest

from awsmount.errors import BudgetExceeded, PermissionDenied


def test_denied_listing_is_empty_with_one_log_line(
        mount: Any, estate: Any,
        deny: Callable[..., list[str]]) -> None:
    """ENI listing denied: empty dir, one TSV line, mount still works."""
    hits = deny(mount.ctx, "ec2", "DescribeNetworkInterfaces")
    assert mount.ls(mount.path("ec2", "network-interfaces")) == []
    assert hits
    lines = mount.error_lines()
    assert len(lines) == 1, lines
    fields = lines[0]
    assert len(fields) == 8
    assert fields[1] == estate.account_id
    assert fields[2] == mount.region
    assert fields[3] == "ec2"
    assert fields[4] == "describe_network_interfaces"
    assert fields[5] == "access-denied"
    assert fields[6] == "UnauthorizedOperation"
    assert estate.instance_web in mount.ls(mount.path("ec2", "instances"))
    assert estate.vpc_main in mount.ls(mount.path("vpc", "vpcs"))
    mount.ls(mount.path("ec2", "network-interfaces"))
    assert len(mount.error_lines()) == 1


@pytest.mark.parametrize("code", ["AuthFailure", "OptInRequired",
                                  "AccessDenied"])
def test_access_denied_codes(mount: Any, code: str,
                             deny: Callable[..., list[str]]) -> None:
    """Every access-denied code degrades the same way."""
    deny(mount.ctx, "ec2", "DescribeVolumes", code=code)
    assert mount.ls(mount.path("ec2", "volumes")) == []
    (fields,) = mount.error_lines()
    assert fields[5] == "access-denied"
    assert fields[6] == code


def test_other_listing_error_is_logged_as_other(
        mount: Any, deny: Callable[..., list[str]]) -> None:
    """Non-auth failures also give an empty dir plus a log entry."""
    deny(mount.ctx, "ec2", "DescribeSubnets", code="InternalError")
    assert mount.ls(mount.path("vpc", "subnets")) == []
    (fields,) = mount.error_lines()
    assert fields[5] == "other"
    assert fields[6] == "InternalError"


def test_denied_source_skipped_in_referenced_by(
        mount: Any, estate: Any,
        deny: Callable[..., list[str]]) -> None:
    """A denied source collection simply contributes no entries."""
    deny(mount.ctx, "ec2", "DescribeNetworkInterfaces")
    base = mount.path("vpc", "security-groups", estate.sg_app,
                      "referenced-by")
    entries = mount.ls(base)
    assert f"ec2-instances-{estate.instance_app}" in entries
    assert f"vpc-security-groups-{estate.sg_web}" in entries
    assert not any(e.startswith("ec2-network-interfaces-")
                   for e in entries)


def test_denied_lazy_file_is_eacces(
        seed: Any, estate: Any, make_mount: Callable[..., Any],
        deny: Callable[..., list[str]]) -> None:
    """Lazy user-data denied (with --reveal): EACCES + log, no crash."""
    m = make_mount(reveal=True)
    deny(m.ctx, "ec2", "DescribeInstanceAttribute")
    base = m.path("ec2", "instances", estate.instance_web)
    with pytest.raises(PermissionDenied) as info:
        m.read(f"{base}/user-data")
    assert info.value.errno == errno.EACCES
    with pytest.raises(PermissionDenied):
        m.read(f"{base}/user-data")
    lines = m.error_lines()
    assert len(lines) == 1, lines
    assert lines[0][4] == "describe_instance_attribute"
    assert lines[0][5] == "access-denied"
    assert estate.instance_web in m.text(f"{base}/describe.json")


def test_denied_redacted_lazy_file_is_never_called(
        mount: Any, estate: Any,
        deny: Callable[..., list[str]]) -> None:
    """Redacted user-data makes no call, so a denial is invisible."""
    hits = deny(mount.ctx, "ec2", "DescribeInstanceAttribute")
    data = mount.read(mount.path("ec2", "instances", estate.instance_web,
                                 "user-data"))
    assert data == b"<hidden>\n"
    assert hits == []
    assert mount.errors() == ""


def test_budget_exhaustion_is_eio_and_logged_once(
        seed: Any, estate: Any, make_mount: Callable[..., Any]) -> None:
    """Over budget: EIO with a clear message; cached data still served."""
    m = make_mount(max_api_calls=3)
    assert m.calls() == 2
    instances = m.path("ec2", "instances")
    assert estate.instance_web in m.ls(instances)
    with pytest.raises(BudgetExceeded) as info:
        m.ls(m.path("vpc", "vpcs"))
    assert info.value.errno == errno.EIO
    assert "API call budget exhausted" in str(info.value)
    with pytest.raises(BudgetExceeded):
        m.ls(m.path("vpc", "subnets"))
    budget_lines = [line for line in
                    m.ctx.errors.render().decode().splitlines()
                    if "\tbudget\t" in line]
    assert len(budget_lines) == 1, budget_lines
    assert estate.instance_web in m.ls(instances)
    describe = m.text(f"{instances}/{estate.instance_web}/describe.json")
    assert estate.instance_web in describe
