"""ECR provider (repositories) over the seeded estate."""

from __future__ import annotations

from typing import Any

REPOSITORIES = "ecr/repositories"
WITH_POLICIES = "awsmount%2Fapp"  # the repository "awsmount/app"
WITHOUT_POLICIES = "awsmount-plain"


def test_listing_is_one_call_and_names_are_escaped(mount: Any) -> None:
    before = mount.calls()
    names = mount.ls(mount.path(REPOSITORIES))
    assert mount.calls() - before == 1
    assert sorted(names) == [WITH_POLICIES, WITHOUT_POLICIES]


def test_repository_files(mount: Any) -> None:
    d = mount.path(f"{REPOSITORIES}/{WITH_POLICIES}")
    doc = mount.json(f"{d}/describe.json")
    assert doc["repositoryName"] == "awsmount/app"
    assert mount.text(f"{d}/arn") == doc["repositoryArn"] + "\n"
    assert mount.text(f"{d}/uri") == doc["repositoryUri"] + "\n"
    assert mount.json(f"{d}/tags.json")["team"] == "platform"


def test_policies(mount: Any) -> None:
    d = mount.path(f"{REPOSITORIES}/{WITH_POLICIES}")
    policy = mount.json(f"{d}/policy.json")
    assert policy["Statement"][0]["Sid"] == "AllowPull"
    lifecycle = mount.json(f"{d}/lifecycle-policy.json")
    assert lifecycle["rules"][0]["action"]["type"] == "expire"


def test_policies_are_lazy(mount: Any) -> None:
    d = mount.path(f"{REPOSITORIES}/{WITH_POLICIES}")
    mount.ls(d)
    before = mount.calls()
    mount.read(f"{d}/policy.json")
    assert mount.calls() - before == 1
    mount.read(f"{d}/policy.json")
    assert mount.calls() - before == 1


def test_missing_policies_give_null_without_noise(mount: Any) -> None:
    d = mount.path(f"{REPOSITORIES}/{WITHOUT_POLICIES}")
    assert mount.text(f"{d}/policy.json") == "null\n"
    assert mount.text(f"{d}/lifecycle-policy.json") == "null\n"
    assert "NotFoundException" not in mount.errors()
