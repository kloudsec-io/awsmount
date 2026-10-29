"""ACM provider against moto: certificates listed once, details lazy.

Covers the domain-name display with the ``~<id>`` collision rule,
describe.json derived from the listing, lazy details.json and tags,
no N+1, the strict read-only allow-list (ExportCertificate denied,
GetCertificate not allow-listed) and AccessDenied degradation.
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
from awsmount.providers.acm import KEY_TYPES
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

CERTS = "acm/certificates"
API = f"{CERTS}/{seed.CERT_DOMAIN}"


@pytest.fixture(scope="module")
def edge(moto_session: Any) -> Any:
    """The seeded ACM/Route 53 estate."""
    return seed.seed_edge(moto_session)


def _cid(arn: str) -> str:
    return arn.rsplit("/", 1)[-1]


def _dup_dirs(edge: Any) -> list[str]:
    return [f"{CERTS}/{seed.CERT_DUP_DOMAIN}~{_cid(a)}"
            for a in edge.dup_certificate_arns]


def _listed(session: Any, arn: str) -> dict[str, Any]:
    client = session.client("acm", region_name=REGION)
    pages = client.get_paginator("list_certificates").paginate(
        Includes={"keyTypes": list(KEY_TYPES)})
    for page in pages:
        for item in page["CertificateSummaryList"]:
            if item["CertificateArn"] == arn:
                return dict(item)
    raise AssertionError(f"{arn} not listed by moto")


def test_domain_names_with_collision_suffix(edge: Any) -> None:
    m = Mount()
    names = m.ls(m.path(CERTS))
    dups = [d.rsplit("/", 1)[-1] for d in _dup_dirs(edge)]
    assert names == sorted([seed.CERT_DOMAIN] + dups)
    assert seed.CERT_DUP_DOMAIN not in names
    assert len(set(dups)) == seed.CERT_DUP_COUNT


def test_resource_dir_entries(edge: Any) -> None:
    m = Mount()
    assert set(m.ls(m.path(API))) == {
        "arn", "describe.json", "details.json", "name", "status",
        "tags", "tags.json"}


def test_describe_is_the_listing_item(edge: Any,
                                      moto_session: Any) -> None:
    item = _listed(moto_session, edge.certificate_arn)
    m = Mount(reveal=True)
    doc = m.json(m.path(f"{API}/describe.json"))
    assert doc == json.loads(to_json_text(item))
    assert doc["DomainName"] == seed.CERT_DOMAIN


def test_derived_files(edge: Any) -> None:
    m = Mount()
    doc = m.json(m.path(f"{API}/describe.json"))
    assert m.text(m.path(f"{API}/arn")) == edge.certificate_arn + "\n"
    assert m.text(m.path(f"{API}/name")) == seed.CERT_DOMAIN + "\n"
    assert m.text(m.path(f"{API}/status")) == \
        str(doc.get("Status") or "") + "\n"
    for arn, path in zip(edge.dup_certificate_arns, _dup_dirs(edge)):
        assert m.text(m.path(f"{path}/arn")) == arn + "\n"
        assert m.text(m.path(f"{path}/name")) == \
            seed.CERT_DUP_DOMAIN + "\n"


def test_details_json_is_describe_certificate(edge: Any) -> None:
    m = Mount()
    details = m.json(m.path(f"{API}/details.json"))
    assert details["CertificateArn"] == edge.certificate_arn
    assert details["DomainName"] == seed.CERT_DOMAIN
    assert set(seed.CERT_SANS) <= set(details["SubjectAlternativeNames"])


def test_tags_are_lazy_and_not_redacted(edge: Any) -> None:
    m = Mount()
    assert m.json(m.path(f"{API}/tags.json")) == dict(
        sorted(seed.CERT_TAGS.items()))
    assert m.text(m.path(f"{API}/tags/ApiToken")) == \
        seed.TAG_SECRET_VALUE + "\n"


def test_listing_is_one_call_and_lazy_files_cost_one_each(
        edge: Any) -> None:
    m = Mount()
    before = m.calls()
    names = m.ls(m.path(CERTS))
    assert m.calls() == before + 1
    for name in names:
        base = m.path(f"{CERTS}/{name}")
        for leaf in ("describe.json", "arn", "name", "status"):
            m.read(f"{base}/{leaf}")
    assert m.calls() == before + 1
    m.read(m.path(f"{API}/details.json"))
    assert m.calls() == before + 2
    m.read(m.path(f"{API}/tags.json"))
    m.ls(m.path(f"{API}/tags"))
    assert m.calls() == before + 3


def test_no_links_and_no_referenced_by(edge: Any) -> None:
    m = Mount()
    entries = m.ls(m.path(API))
    assert "links" not in entries
    assert "referenced-by" not in entries


def test_private_key_and_writes_are_refused(edge: Any) -> None:
    m = Mount(reveal=True)
    client = m.ctx.clients.get(m.account.profile, REGION, "acm")
    arn = edge.certificate_arn
    before = m.calls()
    with pytest.raises(ForbiddenOperation):
        client.export_certificate(CertificateArn=arn,
                                  Passphrase=b"passphrase")
    with pytest.raises(ForbiddenOperation):
        client.get_certificate(CertificateArn=arn)
    with pytest.raises(ForbiddenOperation):
        client.delete_certificate(CertificateArn=arn)
    with pytest.raises(ForbiddenOperation):
        client.request_certificate(DomainName="x.awsmount.example")
    assert m.calls() == before


def test_access_denied_on_listing_degrades_to_empty_dir(
        edge: Any) -> None:
    m = Mount()
    m.deny("acm", "ListCertificates")
    assert m.ls(m.path(CERTS)) == []
    rows = m.denied("acm", "list_certificates")
    assert len(rows) == 1
    assert rows[0][1] == edge.account_id
    assert rows[0][2] == REGION
    assert m.ls(m.gpath("route53/hosted-zones"))


def test_access_denied_on_details_is_eacces(edge: Any) -> None:
    m = Mount()
    m.deny("acm", "DescribeCertificate")
    with pytest.raises(PermissionDenied) as info:
        m.read(m.path(f"{API}/details.json"))
    assert info.value.errno == errno.EACCES
    assert m.text(m.path(f"{API}/arn")) == edge.certificate_arn + "\n"
    assert len(m.denied("acm", "describe_certificate")) == 1


def test_access_denied_on_tags(edge: Any) -> None:
    m = Mount()
    m.deny("acm", "ListTagsForCertificate")
    with pytest.raises(PermissionDenied):
        m.read(m.path(f"{API}/tags.json"))
    assert m.ls(m.path(f"{API}/tags")) == []
    assert len(m.denied("acm", "list_tags_for_certificate")) == 1


def test_seed_is_idempotent(moto_session: Any, edge: Any) -> None:
    again = seed.seed_edge(moto_session)
    assert again == edge
    m = Mount()
    assert len(m.ls(m.path(CERTS))) == 1 + seed.CERT_DUP_COUNT
