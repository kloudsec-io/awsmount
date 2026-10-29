"""EKS provider against moto (docs/coverage.md)."""

from __future__ import annotations

import errno
import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from botocore.exceptions import ClientError

from awsmount.errors import PermissionDenied
from awsmount.providers import refs


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

CLUSTERS = "eks/clusters"
CLUSTER = f"{CLUSTERS}/{seed.EKS_CLUSTER}"
NODEGROUPS = f"{CLUSTER}/nodegroups"
NODEGROUP = f"{NODEGROUPS}/{seed.EKS_NODEGROUP}"
ADDONS = f"{CLUSTER}/addons"

ADDON_ROLE = "arn:aws:iam::123456789012:role/awsmount-eks-role"
ADDON_CONFIG = '{"env": {"AWS_SECRET_ACCESS_KEY": "fake-addon-config-secret"}}'


def test_listing_one_call_and_lazy_describe(compute: Any) -> None:
    m = kit.Mount()
    before = m.calls()
    assert m.ls(m.path(CLUSTERS)) == [seed.EKS_CLUSTER]
    assert m.calls() - before == 1
    m.ls(m.path(CLUSTER))
    loaded = m.calls()
    assert loaded - before == 1
    doc = m.json(m.path(f"{CLUSTER}/describe.json"))
    assert m.calls() - loaded == 1
    cluster = doc["cluster"]
    assert cluster["name"] == seed.EKS_CLUSTER
    assert cluster["roleArn"] == compute.eks_role_arn
    assert cluster["version"] == seed.EKS_VERSION
    assert "ResponseMetadata" not in doc
    cached = m.calls()
    m.read(m.path(f"{CLUSTER}/describe.json"))
    assert m.calls() == cached


def test_tags_reuse_the_describe_call(compute: Any) -> None:
    m = kit.Mount()
    m.read(m.path(f"{CLUSTER}/describe.json"))
    described = m.calls()
    assert m.json(m.path(f"{CLUSTER}/tags.json")) == dict(
        sorted(seed.EKS_TAGS.items()))
    assert m.text(m.path(f"{CLUSTER}/tags/team")) == "platform\n"
    assert m.calls() == described


def test_nodegroups(compute: Any) -> None:
    m = kit.Mount()
    text = m.text(m.path(f"{CLUSTER}/nodegroups.json"))
    assert seed.EKS_NODEGROUP in text


@pytest.mark.xfail(strict=True,
                   reason="moto does not implement eks ListAddons")
def test_addons(compute: Any) -> None:
    m = kit.Mount(max_attempts=1, connect_timeout=2.0, read_timeout=5.0)
    assert m.json(m.path(f"{CLUSTER}/addons.json")) == []


def test_links_from_describe(compute: Any) -> None:
    m = kit.Mount()
    net = compute.network
    links = m.path(f"{CLUSTER}/links")
    assert m.targets(f"{links}/subnets") == {
        m.path(f"vpc/subnets/{net.subnet_public}"),
        m.path(f"vpc/subnets/{net.subnet_private}")}
    assert m.path(f"vpc/security-groups/{net.sg_app}") in m.targets(
        f"{links}/security-groups")
    assert m.relative_links(f"{links}/subnets")
    if m.mounted(refs.IAM_ROLES):
        assert m.target(f"{links}/role") == m.gpath(
            f"iam/roles/{seed.EKS_ROLE_NAME}")
    else:
        assert "role" not in m.ls(links)


def test_access_denied_listing_degrades_to_empty_dir(
        compute: Any) -> None:
    m = kit.Mount()
    m.deny("eks", "ListClusters")
    assert m.ls(m.path(CLUSTERS)) == []
    lines = m.denied("eks")
    assert len(lines) == 1
    assert lines[0][4] == "list_clusters"
    assert m.ls(m.path("ecs/clusters")) == [seed.ECS_CLUSTER]


def test_access_denied_on_lazy_describe_is_eacces(compute: Any) -> None:
    m = kit.Mount()
    m.deny("eks", "DescribeCluster")
    with pytest.raises(PermissionDenied) as info:
        m.read(m.path(f"{CLUSTER}/describe.json"))
    assert info.value.errno == errno.EACCES
    assert m.denied("eks", "describe_cluster")


# -- nested node groups --


def test_nodegroups_listing_one_call_and_lazy_describe(
        compute: Any) -> None:
    m = kit.Mount()
    assert "nodegroups" in m.ls(m.path(CLUSTER))
    before = m.calls()
    assert m.ls(m.path(NODEGROUPS)) == [seed.EKS_NODEGROUP]
    assert m.calls() - before == 1
    m.ls(m.path(NODEGROUP))
    assert m.calls() - before == 1
    doc = m.json(m.path(f"{NODEGROUP}/describe.json"))
    assert m.calls() - before == 2
    group = doc["nodegroup"]
    assert group["nodegroupName"] == seed.EKS_NODEGROUP
    assert group["clusterName"] == seed.EKS_CLUSTER
    assert group["nodeRole"] == compute.eks_node_role_arn
    assert group["instanceTypes"] == ["t3.medium"]
    assert group["scalingConfig"]["desiredSize"] == 1
    assert group["nodegroupArn"].startswith("arn:aws:eks:")
    assert "ResponseMetadata" not in doc
    cached = m.calls()
    m.read(m.path(f"{NODEGROUP}/describe.json"))
    assert m.calls() == cached
    assert "arn" not in m.ls(m.path(NODEGROUP))


def test_nodegroup_tags_reuse_the_describe_call(compute: Any) -> None:
    m = kit.Mount()
    m.read(m.path(f"{NODEGROUP}/describe.json"))
    described = m.calls()
    assert m.json(m.path(f"{NODEGROUP}/tags.json")) == dict(
        sorted(seed.EKS_TAGS.items()))
    assert m.text(m.path(f"{NODEGROUP}/tags/team")) == "platform\n"
    assert m.calls() == described


def test_nodegroup_links(compute: Any) -> None:
    m = kit.Mount()
    links = m.path(f"{NODEGROUP}/links")
    assert m.target(f"{links}/cluster") == m.path(CLUSTER)
    assert m.targets(f"{links}/subnets") == {
        m.path(f"vpc/subnets/{compute.network.subnet_private}")}
    assert m.relative_links(f"{links}/subnets")
    if m.mounted(refs.IAM_ROLES):
        assert m.target(f"{links}/role") == m.gpath(
            f"iam/roles/{seed.EKS_NODE_ROLE_NAME}")
    else:
        assert "role" not in m.ls(links)


def test_nodegroup_access_denied_degrades(compute: Any) -> None:
    m = kit.Mount()
    m.deny("eks", "DescribeNodegroup")
    assert m.ls(m.path(NODEGROUPS)) == [seed.EKS_NODEGROUP]
    with pytest.raises(PermissionDenied) as info:
        m.read(m.path(f"{NODEGROUP}/describe.json"))
    assert info.value.errno == errno.EACCES
    assert m.denied("eks", "describe_nodegroup")
    other = kit.Mount()
    other.deny("eks", "ListNodegroups")
    assert other.ls(other.path(NODEGROUPS)) == []
    assert other.denied("eks", "list_nodegroups")


# -- nested add-ons (moto cannot list them: responses are injected) --


class _Ok:
    """Minimal 200 response for a before-call short-circuit."""

    status_code = 200
    headers: dict[str, str] = {}
    content = b""
    text = ""


def _inject_addons(m: Any) -> None:
    """Answer ListAddons and DescribeAddon without any HTTP request."""
    client = m.ctx.clients.get(m.account.profile, kit.REGION, "eks")
    described = {
        "vpc-cni": {"addonName": "vpc-cni", "status": "ACTIVE",
                    "addonVersion": "v1.18.0-eksbuild.1",
                    "clusterName": seed.EKS_CLUSTER,
                    "addonArn": "arn:aws:eks:us-east-1:123456789012:addon/"
                                f"{seed.EKS_CLUSTER}/vpc-cni/abc",
                    "serviceAccountRoleArn": ADDON_ROLE,
                    "configurationValues": ADDON_CONFIG,
                    "tags": {"team": "platform"}},
        "coredns": {"addonName": "coredns", "status": "DEGRADED",
                    "addonVersion": "v1.11.1-eksbuild.4",
                    "clusterName": seed.EKS_CLUSTER,
                    "health": {"issues": [{"code": "InsufficientNumberOf"
                                                   "Replicas"}]}},
    }

    def list_addons(**_kwargs: Any) -> tuple[Any, dict[str, Any]]:
        return _Ok(), {"addons": ["vpc-cni", "coredns"]}

    def describe_addon(params: dict[str, Any], **_kwargs: Any
                       ) -> tuple[Any, dict[str, Any]]:
        name = params["uri_path"].rsplit("/", 1)[-1] if "uri_path" in \
            params else params["url_path"].rsplit("/", 1)[-1]
        if name not in described:
            raise ClientError({"Error": {"Code": "ResourceNotFoundException",
                                         "Message": name}},
                              "DescribeAddon")
        return _Ok(), {"addon": described[name]}

    client.meta.events.register("before-call.eks.ListAddons", list_addons)
    client.meta.events.register("before-call.eks.DescribeAddon",
                                describe_addon)


def test_addons_listing_and_lazy_describe(compute: Any) -> None:
    m = kit.Mount()
    _inject_addons(m)
    assert "addons" in m.ls(m.path(CLUSTER))
    before = m.calls()
    assert m.ls(m.path(ADDONS)) == ["coredns", "vpc-cni"]
    assert m.calls() - before == 1
    doc = m.json(m.path(f"{ADDONS}/coredns/describe.json"))
    assert m.calls() - before == 2
    assert doc["addon"]["status"] == "DEGRADED"
    assert doc["addon"]["health"]["issues"]
    assert "ResponseMetadata" not in doc
    assert "arn" not in m.ls(m.path(f"{ADDONS}/coredns"))


def test_addon_configuration_values_hidden_unless_revealed(
        compute: Any) -> None:
    m = kit.Mount()
    _inject_addons(m)
    doc = m.json(m.path(f"{ADDONS}/vpc-cni/describe.json"))
    assert doc["addon"]["configurationValues"] == "<hidden>"
    assert doc["addon"]["addonVersion"] == "v1.18.0-eksbuild.1"
    assert m.grep(m.region_root, "fake-addon-config-secret") == []
    revealed = kit.Mount(reveal=True)
    _inject_addons(revealed)
    doc = revealed.json(revealed.path(f"{ADDONS}/vpc-cni/describe.json"))
    assert doc["addon"]["configurationValues"] == ADDON_CONFIG


def test_addon_tags_and_links(compute: Any) -> None:
    m = kit.Mount()
    _inject_addons(m)
    m.read(m.path(f"{ADDONS}/vpc-cni/describe.json"))
    described = m.calls()
    assert m.json(m.path(f"{ADDONS}/vpc-cni/tags.json")) == {
        "team": "platform"}
    assert m.calls() == described
    links = m.path(f"{ADDONS}/vpc-cni/links")
    assert m.target(f"{links}/cluster") == m.path(CLUSTER)
    assert "role" not in m.ls(m.path(f"{ADDONS}/coredns/links"))


def test_addons_access_denied_degrades(compute: Any) -> None:
    m = kit.Mount()
    m.deny("eks", "ListAddons")
    assert m.ls(m.path(ADDONS)) == []
    assert m.denied("eks", "list_addons")
