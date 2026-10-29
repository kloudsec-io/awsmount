"""Step Functions provider (state machines) over the seeded estate.

The seeded definition holds the fake secret in a task parameter. It must
stay hidden in ``describe.json`` and in ``definition.json``, and
``--reveal`` shows it.
"""

from __future__ import annotations

import errno
from collections.abc import Callable
from typing import Any

import pytest

from awsmount.errors import PermissionDenied
from awsmount.vfs import walk

MACHINES = "stepfunctions/state-machines"


def test_listing_one_call_and_lazy_describe(mount: Any, seed: Any) -> None:
    name = seed.services.sfn_name
    before = mount.calls()
    assert mount.ls(mount.path(MACHINES)) == [name]
    assert mount.calls() - before == 1
    d = mount.path(f"{MACHINES}/{name}")
    mount.ls(d)
    assert mount.calls() - before == 1
    doc = mount.json(f"{d}/describe.json")
    assert mount.calls() - before == 2
    assert doc["roleArn"] == seed.services.sfn_role_arn
    assert mount.text(f"{d}/arn") == seed.services.sfn_arn + "\n"
    assert mount.json(f"{d}/tags.json")["team"] == "platform"


def test_definition_is_hidden_in_describe_and_masked_in_definition_json(
        mount: Any, seed: Any) -> None:
    d = mount.path(f"{MACHINES}/{seed.services.sfn_name}")
    assert mount.json(f"{d}/describe.json")["definition"] == "<hidden>"
    params = mount.json(f"{d}/definition.json")["States"]["Call"][
        "Parameters"]
    assert params["ApiKey"] == "<hidden>"
    assert params["mode"] == "visible"


def test_reveal_shows_the_definition(reveal: Any, seed: Any,
                                     seedlib: Any) -> None:
    d = reveal.path(f"{MACHINES}/{seed.services.sfn_name}")
    params = reveal.json(f"{d}/definition.json")["States"]["Call"][
        "Parameters"]
    assert params["ApiKey"] == seedlib.FAKE_SECRET


def test_secret_is_nowhere_in_the_masked_tree(mount: Any,
                                              seedlib: Any) -> None:
    root = mount.path("stepfunctions")
    hits = walk.grep(mount.vfs, seedlib.FAKE_SECRET, [root],
                     recursive=True, files_only=True,
                     on_error=lambda *_: None)
    assert list(hits) == []


def test_links(mount: Any, seed: Any) -> None:
    d = mount.path(f"{MACHINES}/{seed.services.sfn_name}/links")
    assert mount.realpath(f"{d}/role") == mount.gpath(
        "iam/roles/awsmount-sfn-role")
    functions = mount.ls(f"{d}/lambda-functions")
    assert len(functions) == 1
    assert mount.realpath(
        f"{d}/lambda-functions/{functions[0]}") == mount.path(
        f"lambda/functions/{functions[0]}")


def test_access_denied_on_describe_is_eacces(
        make_mount: Callable[..., Any], seed: Any,
        deny: Callable[..., Any]) -> None:
    m = make_mount()
    deny(m.ctx, "stepfunctions", "DescribeStateMachine", "AccessDenied")
    d = m.path(f"{MACHINES}/{seed.services.sfn_name}")
    with pytest.raises(PermissionDenied) as info:
        m.read(f"{d}/describe.json")
    assert info.value.errno == errno.EACCES
    assert "describe_state_machine" in m.errors()
