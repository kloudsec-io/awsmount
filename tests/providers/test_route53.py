"""Route 53 provider against moto: global hosted zones.

Covers zone display names (trailing dot removed, ``~<id>`` for the
split-horizon public/private pair), describe.json derived from the
listing, lazy records.json and tags, the region-scoped ``vpcs/`` links
of private zones (omitted for unmounted regions), no N+1, the strict
read-only allow-list and AccessDenied degradation.
"""

from __future__ import annotations

import errno
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from awsmount.errors import ForbiddenOperation, PermissionDenied
from awsmount.vfs.render import to_json_text


def _load_kit() -> ModuleType:
    """Load tests/providers/motokit.py by path (import-mode agnostic)."""
    name = "awsmount_tests_motokit"
    module = sys.modules.get(name)
    if module is not None:
        return module
    path = Path(__file__).resolve().with_name("motokit.py")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        del sys.modules[name]
        raise
    return module


kit = _load_kit()
seed = kit.seed
Mount = kit.Mount
REGION: str = kit.REGION
moto_session = kit.moto_session

ZONES = "route53/hosted-zones"
BARE = seed.ZONE_NAME[:-1]
SOLO = f"{ZONES}/{seed.ZONE_SOLO_NAME[:-1]}"


@pytest.fixture(scope="module")
def edge(moto_session: Any) -> Any:
    """The seeded ACM/Route 53 estate."""
    return seed.seed_edge(moto_session)


def _public(edge: Any) -> str:
    return f"{ZONES}/{BARE}~{edge.zone_public}"


def _private(edge: Any) -> str:
    return f"{ZONES}/{BARE}~{edge.zone_private}"


def _listed(session: Any, zone: str) -> dict[str, Any]:
    client = session.client("route53", region_name=REGION)
    for page in client.get_paginator("list_hosted_zones").paginate():
        for item in page["HostedZones"]:
            if item["Id"].rsplit("/", 1)[-1] == zone:
                return dict(item)
    raise AssertionError(f"{zone} not listed by moto")


def _spy(m: Any, service: str) -> list[str]:
    """Record every operation the mount sends to ``service``."""
    client = m.ctx.clients.get(m.account.profile, REGION, service)
    ops: list[str] = []

    def record(model: Any, **_kwargs: Any) -> None:
        ops.append(str(model.name))

    client.meta.events.register("before-call.*.*", record)
    return ops


def test_zone_names_and_collision_suffix(edge: Any) -> None:
    m = Mount()
    names = set(m.ls(m.gpath(ZONES)))
    expected = {p.rsplit("/", 1)[-1]
                for p in (_public(edge), _private(edge), SOLO)}
    assert expected <= names
    assert BARE not in names
    assert seed.ZONE_NAME not in names


def test_resource_dir_entries(edge: Any) -> None:
    m = Mount()
    assert set(m.ls(m.gpath(_public(edge)))) == {
        "arn", "describe.json", "links", "name", "private",
        "record-count", "records.json", "tags", "tags.json"}
    assert "referenced-by" not in m.ls(m.gpath(_public(edge)))


def test_describe_is_the_listing_item(edge: Any,
                                      moto_session: Any) -> None:
    expected = json.loads(to_json_text(_listed(moto_session,
                                               edge.zone_private)))
    revealed = Mount(reveal=True)
    path = revealed.gpath(f"{_private(edge)}/describe.json")
    assert revealed.json(path) == expected
    m = Mount()
    assert m.json(m.gpath(f"{_private(edge)}/describe.json")) == expected


def test_derived_files(edge: Any) -> None:
    m = Mount()
    public, private = m.gpath(_public(edge)), m.gpath(_private(edge))
    assert m.text(f"{public}/private") == "false\n"
    assert m.text(f"{private}/private") == "true\n"
    assert m.text(f"{public}/name") == BARE + "\n"
    assert m.text(f"{public}/arn") == \
        f"arn:aws:route53:::hostedzone/{edge.zone_public}\n"
    doc = m.json(f"{public}/describe.json")
    assert doc["Name"] == seed.ZONE_NAME
    assert doc["Config"]["Comment"] == seed.ZONE_PUBLIC_COMMENT


def test_records_json_and_count(edge: Any) -> None:
    m = Mount()
    public = m.gpath(_public(edge))
    records = m.json(f"{public}/records.json")
    www = [r for r in records
           if r["Name"] == seed.WWW_RECORD and r["Type"] == "A"]
    assert len(www) == 1
    assert www[0]["ResourceRecords"] == [{"Value": seed.WWW_IP}]
    cname = [r for r in records if r["Type"] == "CNAME"]
    assert cname[0]["ResourceRecords"] == [{"Value": seed.API_TARGET}]
    txt = [r for r in records if r["Type"] == "TXT"]
    assert txt[0]["ResourceRecords"] == [{"Value": seed.TXT_VALUE}]
    assert m.text(f"{public}/record-count") == f"{len(records)}\n"


def test_tags_are_lazy_and_not_redacted(edge: Any) -> None:
    m = Mount()
    public = m.gpath(_public(edge))
    assert m.json(f"{public}/tags.json") == dict(
        sorted(seed.ZONE_TAGS.items()))
    assert m.text(f"{public}/tags/ApiToken") == \
        seed.TAG_SECRET_VALUE + "\n"
    assert m.json(m.gpath(f"{SOLO}/tags.json")) == {}


def test_private_zone_links_only_mounted_vpcs(edge: Any) -> None:
    m = Mount()
    vpcs = m.gpath(f"{_private(edge)}/links/vpcs")
    main = edge.network.vpc_main
    assert m.ls(vpcs) == [main]
    assert m.vfs.readlink(f"{vpcs}/{main}") == \
        "../" * 6 + f"{REGION}/vpc/vpcs/{main}"
    assert m.target(f"{vpcs}/{main}") == m.path(f"vpc/vpcs/{main}")


def test_private_zone_links_every_region_when_mounted(edge: Any) -> None:
    m = Mount(regions=(REGION, seed.EU_VPC_REGION))
    vpcs = m.gpath(f"{_private(edge)}/links/vpcs")
    main, eu = edge.network.vpc_main, edge.vpc_eu
    assert m.ls(vpcs) == sorted([main, eu])
    assert m.relative_links(vpcs)
    assert m.target(f"{vpcs}/{eu}") == \
        f"{m.root}/{seed.EU_VPC_REGION}/vpc/vpcs/{eu}"
    assert m.target(f"{vpcs}/{main}") == m.path(f"vpc/vpcs/{main}")


def test_public_zone_makes_no_get_hosted_zone_call(edge: Any) -> None:
    m = Mount()
    ops = _spy(m, "route53")
    assert m.ls(m.gpath(f"{_public(edge)}/links/vpcs")) == []
    assert m.ls(m.gpath(f"{SOLO}/links/vpcs")) == []
    assert "GetHostedZone" not in ops


def test_listing_is_one_call_and_derived_files_are_free(
        edge: Any) -> None:
    m = Mount()
    before = m.calls()
    names = m.ls(m.gpath(ZONES))
    assert m.calls() == before + 1
    for name in names:
        base = m.gpath(f"{ZONES}/{name}")
        for leaf in ("describe.json", "arn", "name", "private",
                     "record-count"):
            m.read(f"{base}/{leaf}")
    assert m.calls() == before + 1
    m.read(m.gpath(f"{_public(edge)}/records.json"))
    assert m.calls() == before + 2


def test_writes_and_unlisted_reads_are_refused(edge: Any) -> None:
    m = Mount(reveal=True)
    client = m.ctx.clients.get(m.account.profile, REGION, "route53")
    record = {"Name": seed.WWW_RECORD, "Type": "A", "TTL": 300,
              "ResourceRecords": [{"Value": seed.WWW_IP}]}
    before = m.calls()
    with pytest.raises(ForbiddenOperation):
        client.change_resource_record_sets(
            HostedZoneId=edge.zone_public,
            ChangeBatch={"Changes": [{"Action": "DELETE",
                                      "ResourceRecordSet": record}]})
    with pytest.raises(ForbiddenOperation):
        client.delete_hosted_zone(Id=edge.zone_solo)
    with pytest.raises(ForbiddenOperation):
        client.get_hosted_zone_count()
    with pytest.raises(ForbiddenOperation):
        client.list_hosted_zones_by_name()
    assert m.calls() == before


def test_access_denied_on_listing_degrades_to_empty_dir(
        edge: Any) -> None:
    m = Mount()
    m.deny("route53", "ListHostedZones")
    assert m.ls(m.gpath(ZONES)) == []
    rows = m.denied("route53", "list_hosted_zones")
    assert len(rows) == 1
    assert rows[0][1] == edge.account_id
    assert rows[0][2] == REGION
    assert m.ls(m.path("acm/certificates"))


def test_access_denied_on_records_is_eacces(edge: Any) -> None:
    m = Mount()
    m.deny("route53", "ListResourceRecordSets")
    with pytest.raises(PermissionDenied) as info:
        m.read(m.gpath(f"{_public(edge)}/records.json"))
    assert info.value.errno == errno.EACCES
    assert m.text(m.gpath(f"{_public(edge)}/private")) == "false\n"
    assert len(m.denied("route53", "list_resource_record_sets")) == 1


def test_access_denied_on_get_hosted_zone_omits_vpc_links(
        edge: Any) -> None:
    m = Mount()
    m.deny("route53", "GetHostedZone")
    assert m.ls(m.gpath(f"{_private(edge)}/links/vpcs")) == []
    assert len(m.denied("route53", "get_hosted_zone")) == 1


def test_seed_is_idempotent(moto_session: Any, edge: Any) -> None:
    again = seed.seed_edge(moto_session)
    assert again == edge
    m = Mount()
    names = m.ls(m.gpath(ZONES))
    assert sum(1 for n in names if n.startswith(f"{BARE}~")) == 2
