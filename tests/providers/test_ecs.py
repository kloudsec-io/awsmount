"""ECS provider against moto (rule ``ecs-taskdef``)."""

from __future__ import annotations

import errno
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from awsmount.errors import PermissionDenied
from awsmount.providers import refs
from awsmount.session.redact import REDACTED


def _load_kit() -> ModuleType:
    """Load tests/providers/motokit.py by path (any import mode)."""
    name = "awsmount_tests_motokit"
    module = sys.modules.get(name)
    if module is None:
        path = Path(__file__).resolve().with_name("motokit.py")
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return module


kit = _load_kit()
seed = kit.seed
moto_session = kit.moto_session
compute = kit.compute

CLUSTERS = "ecs/clusters"
CLUSTER = f"{CLUSTERS}/{seed.ECS_CLUSTER}"
SERVICES = f"{CLUSTER}/services"
SERVICE = f"{SERVICES}/{seed.ECS_SERVICE}"
TASKDEFS = "ecs/task-definitions"
TASKDEF_NAME = f"{seed.ECS_FAMILY}:1"
TASKDEF = f"{TASKDEFS}/{TASKDEF_NAME}"


def _env(doc: dict[str, Any]) -> list[dict[str, Any]]:
    return doc["taskDefinition"]["containerDefinitions"][0]["environment"]


def test_clusters_listing_is_one_list_plus_one_batch(
        compute: Any) -> None:
    m = kit.Mount()
    before = m.calls()
    assert m.ls(m.path(CLUSTERS)) == [seed.ECS_CLUSTER]
    assert m.calls() - before == 2
    listed = m.calls()
    doc = m.json(m.path(f"{CLUSTER}/describe.json"))
    assert doc["clusterName"] == seed.ECS_CLUSTER
    assert doc["clusterArn"] == compute.ecs_cluster_arn
    assert m.calls() == listed


def test_cluster_files_and_inline_tags(compute: Any) -> None:
    m = kit.Mount()
    assert m.text(m.path(f"{CLUSTER}/status")) == "ACTIVE\n"
    assert m.json(m.path(f"{CLUSTER}/tags.json")) == dict(
        sorted(seed.ECS_TAGS.items()))
    assert m.text(m.path(f"{CLUSTER}/tags/team")) == "payments\n"


def test_nested_service(compute: Any) -> None:
    m = kit.Mount()
    assert m.ls(m.path(SERVICES)) == [seed.ECS_SERVICE]
    doc = m.json(m.path(f"{SERVICE}/describe.json"))
    assert doc["serviceName"] == seed.ECS_SERVICE
    assert doc["serviceArn"] == compute.ecs_service_arn
    assert m.text(m.path(f"{SERVICE}/status")) == "ACTIVE\n"
    assert m.text(m.path(f"{SERVICE}/desired-count")) == "2\n"


def test_service_links(compute: Any) -> None:
    m = kit.Mount()
    links = m.path(f"{SERVICE}/links")
    assert m.target(f"{links}/cluster") == m.path(CLUSTER)
    assert m.target(f"{links}/task-definition") == m.path(TASKDEF)
    assert m.targets(f"{links}/target-groups") == {
        m.path(f"elbv2/target-groups/{seed.TG_NAME}")}
    assert not m.vfs.readlink(f"{links}/cluster").startswith("/")


def test_task_definition_listing_and_lazy_describe(compute: Any) -> None:
    m = kit.Mount()
    before = m.calls()
    assert m.ls(m.path(TASKDEFS)) == [TASKDEF_NAME]
    assert m.calls() - before == 1
    m.ls(m.path(TASKDEF))
    loaded = m.calls()
    doc = m.json(m.path(f"{TASKDEF}/describe.json"))
    assert m.calls() - loaded == 1
    assert doc["taskDefinition"]["family"] == seed.ECS_FAMILY
    assert doc["taskDefinition"]["revision"] == 1
    assert doc["taskDefinition"]["taskDefinitionArn"] == \
        compute.task_definition_arn
    cached = m.calls()
    m.read(m.path(f"{TASKDEF}/describe.json"))
    assert m.calls() == cached


def test_task_definition_environment_redacted(compute: Any) -> None:
    m = kit.Mount()
    text = m.text(m.path(f"{TASKDEF}/describe.json"))
    assert kit.FAKE_SECRET not in text
    doc = json.loads(text)
    env = _env(doc)
    assert sorted(e["name"] for e in env) == sorted(seed.ECS_ENV)
    assert {e["value"] for e in env} == {REDACTED}
    secrets = doc["taskDefinition"]["containerDefinitions"][0]["secrets"]
    assert secrets == [{"name": "API_KEY",
                        "valueFrom": compute.ecs_secret_arn}]
    assert m.grep(m.path(TASKDEF), kit.FAKE_SECRET) == []


def test_task_definition_reveal(compute: Any) -> None:
    m = kit.Mount(reveal=True)
    env = _env(m.json(m.path(f"{TASKDEF}/describe.json")))
    assert {e["name"]: e["value"] for e in env} == seed.ECS_ENV


def test_task_definition_tags_from_describe(compute: Any) -> None:
    m = kit.Mount()
    m.read(m.path(f"{TASKDEF}/describe.json"))
    assert m.text(m.path(f"{TASKDEF}/tags/team")) == "payments\n"
    assert m.json(m.path(f"{TASKDEF}/tags.json")) == dict(
        sorted(seed.ECS_TAGS.items()))


def test_task_definition_role_links(compute: Any) -> None:
    m = kit.Mount()
    links = m.path(f"{TASKDEF}/links")
    names = m.ls(links)
    if m.mounted(refs.IAM_ROLES):
        assert m.target(f"{links}/role") == m.gpath(
            f"iam/roles/{seed.ECS_TASK_ROLE_NAME}")
        assert m.target(f"{links}/execution-role") == m.gpath(
            f"iam/roles/{seed.ECS_EXECUTION_ROLE_NAME}")
    else:
        assert "role" not in names
        assert "execution-role" not in names


def test_access_denied_listing_degrades_to_empty_dir(
        compute: Any) -> None:
    m = kit.Mount()
    m.deny("ecs", "ListClusters")
    assert m.ls(m.path(CLUSTERS)) == []
    lines = m.denied("ecs")
    assert len(lines) == 1
    assert lines[0][4] == "list_clusters"
    assert m.ls(m.path(TASKDEFS)) == [TASKDEF_NAME]


def test_access_denied_on_lazy_describe_is_eacces(compute: Any) -> None:
    m = kit.Mount()
    m.deny("ecs", "DescribeTaskDefinition")
    with pytest.raises(PermissionDenied) as info:
        m.read(m.path(f"{TASKDEF}/describe.json"))
    assert info.value.errno == errno.EACCES
    assert m.denied("ecs", "describe_task_definition")
