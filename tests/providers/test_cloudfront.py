"""CloudFront provider (global) against a seeded moto backend.

Covers the derived listing (no N+1), lazy config and tags, origin and
certificate links across scopes, custom-header redaction (rule
``cloudfront``) and ``--reveal``, the read-only guard and AccessDenied
degradation.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import boto3
import pytest

from awsmount.errors import ForbiddenOperation, PermissionDenied
from awsmount.session.redact import REDACTED
from awsmount.vfs.render import to_json_text


def _load_kit() -> ModuleType:
    """Load tests/providers/motokit.py by path (any import mode)."""
    name = "awsmount_tests_motokit"
    module = sys.modules.get(name)
    if module is not None:
        return module
    path = Path(__file__).resolve().parent / "motokit.py"
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
moto_session = kit.moto_session


@pytest.fixture(scope="module")
def cf(moto_session: boto3.Session) -> Any:
    """The seeded CloudFront estate (buckets and certificate included)."""
    return seed.seed_cloudfront(moto_session)


def _client(session: boto3.Session) -> Any:
    return session.client("cloudfront", region_name=seed.CF_REGION)


def _summaries(session: boto3.Session) -> list[dict[str, Any]]:
    resp = _client(session).list_distributions()
    return list((resp.get("DistributionList") or {}).get("Items") or [])


def _summary(session: boto3.Session, dist_id: str) -> dict[str, Any]:
    for item in _summaries(session):
        if item["Id"] == dist_id:
            return item
    raise AssertionError(f"distribution {dist_id} not listed")


def _canon(obj: Any) -> Any:
    """Canonical JSON round-trip (datetimes become ISO strings)."""
    return json.loads(to_json_text(obj))


def _dir(m: Any, cf: Any) -> str:
    return m.gpath(f"cloudfront/distributions/{cf.distribution_id}")


def test_listing_is_derived_from_one_call(
        cf: Any, moto_session: boto3.Session) -> None:
    """describe.json and text files come from ListDistributions."""
    m = kit.Mount(reveal=True)
    dists = m.gpath("cloudfront/distributions")
    assert m.ls(dists) == [cf.distribution_id]
    raw = _summary(moto_session, cf.distribution_id)
    before = m.calls()
    base = _dir(m, cf)
    assert m.json(f"{base}/describe.json") == _canon(raw)
    assert m.text(f"{base}/arn") == raw["ARN"] + "\n"
    assert raw["ARN"] == cf.distribution_arn
    assert m.text(f"{base}/domain-name") == raw["DomainName"] + "\n"
    assert raw["DomainName"].endswith(".cloudfront.net")
    assert m.text(f"{base}/status") == raw["Status"] + "\n"
    aliases = m.text(f"{base}/aliases").splitlines()
    assert sorted(aliases) == sorted(seed.CF_ALIASES)
    assert m.calls() == before


def test_tags_are_lazy_and_not_redacted(cf: Any) -> None:
    """One ListTagsForResource call feeds tags.json and tags/."""
    m = kit.Mount()
    base = _dir(m, cf)
    m.ls(base)
    before = m.calls()
    assert m.json(f"{base}/tags.json") == seed.CF_TAGS
    assert m.text(f"{base}/tags/ApiToken") == seed.TAG_SECRET_VALUE + "\n"
    assert m.calls() == before + 1


def test_config_json_is_lazy(cf: Any) -> None:
    """config.json makes exactly one GetDistributionConfig call."""
    m = kit.Mount()
    base = _dir(m, cf)
    m.ls(base)
    before = m.calls()
    config = m.json(f"{base}/config.json")
    assert m.calls() == before + 1
    assert config["CallerReference"] == seed.CF_CALLER_REFERENCE
    assert config["Comment"] == seed.CF_COMMENT
    ids = {o["Id"] for o in config["Origins"]["Items"]}
    assert ids == {seed.CF_ORIGIN_S3, seed.CF_ORIGIN_EU,
                   seed.CF_ORIGIN_API}
    m.json(f"{base}/config.json")
    assert m.calls() == before + 1


def test_origin_links_only_for_mounted_regions(cf: Any) -> None:
    """origins-s3/ links the us-east-1 bucket; the eu-west-1 one is
    omitted because that region is not mounted."""
    m = kit.Mount()
    links = f"{_dir(m, cf)}/links"
    origins = f"{links}/origins-s3"
    assert m.ls(origins) == [seed.BUCKET_NAME]
    assert m.targets(origins) == {
        m.path(f"s3/buckets/{seed.BUCKET_NAME}")}
    assert m.relative_links(origins)
    readlink = m.vfs.readlink(f"{origins}/{seed.BUCKET_NAME}")
    assert "/global/" not in readlink
    assert readlink.startswith("../")


def test_origin_links_follow_extra_region(cf: Any) -> None:
    """Mounting eu-west-1 as well makes the EU bucket link appear."""
    m = kit.Mount(regions=(kit.REGION, seed.BUCKET_EU_REGION))
    origins = f"{_dir(m, cf)}/links/origins-s3"
    assert m.targets(origins) == {
        m.path(f"s3/buckets/{seed.BUCKET_NAME}"),
        f"{m.root}/{seed.BUCKET_EU_REGION}/s3/buckets/{seed.BUCKET_EU}"}


def test_certificate_link_matches_backend(
        cf: Any, moto_session: boto3.Session) -> None:
    """The certificate link exists iff the backend kept the ACM ARN."""
    m = kit.Mount()
    links = f"{_dir(m, cf)}/links"
    viewer = _summary(moto_session, cf.distribution_id).get(
        "ViewerCertificate") or {}
    if viewer.get("ACMCertificateArn") == cf.certificate_arn:
        assert m.target(f"{links}/certificate") == m.path(
            f"acm/certificates/{seed.CERT_DOMAIN}")
        assert not m.vfs.readlink(f"{links}/certificate").startswith("/")
    else:
        assert "certificate" not in m.ls(links)


def test_custom_header_secret_redacted_by_default(
        cf: Any, moto_session: boto3.Session) -> None:
    """Origin header values never leak; --reveal mirrors the backend."""
    raw = _client(moto_session).get_distribution_config(
        Id=cf.distribution_id)["DistributionConfig"]
    raw_has = seed.FAKE_SECRET in json.dumps(raw, default=str)
    m = kit.Mount()
    base = _dir(m, cf)
    for name in ("describe.json", "config.json"):
        assert seed.FAKE_SECRET not in m.text(f"{base}/{name}")
    config = m.json(f"{base}/config.json")
    for origin in config["Origins"]["Items"]:
        headers = (origin.get("CustomHeaders") or {}).get("Items") or []
        for header in headers:
            assert header["HeaderValue"] == REDACTED
            assert header["HeaderName"]
    assert m.grep(m.gpath("cloudfront"), seed.FAKE_SECRET) == []
    revealed = kit.Mount(reveal=True)
    text = revealed.text(f"{_dir(revealed, cf)}/config.json")
    assert (seed.FAKE_SECRET in text) == raw_has


def test_mount_clients_cannot_mutate_cloudfront(
        cf: Any, moto_session: boto3.Session) -> None:
    """Write operations are refused before any HTTP request."""
    m = kit.Mount(reveal=True)
    client = m.ctx.clients.get(m.account.profile, kit.REGION,
                               "cloudfront")
    with pytest.raises(ForbiddenOperation):
        client.delete_distribution(Id=cf.distribution_id, IfMatch="x")
    with pytest.raises(ForbiddenOperation):
        client.create_invalidation(
            DistributionId=cf.distribution_id,
            InvalidationBatch={"Paths": {"Quantity": 1, "Items": ["/*"]},
                               "CallerReference": "awsmount-test"})
    assert [d["Id"] for d in _summaries(moto_session)] == [
        cf.distribution_id]


def test_access_denied_listing_degrades(cf: Any) -> None:
    """Denied ListDistributions: empty dir plus one errors.log line."""
    m = kit.Mount()
    m.deny("cloudfront", "ListDistributions")
    assert m.ls(m.gpath("cloudfront/distributions")) == []
    rows = m.denied("cloudfront", "list_distributions")
    assert len(rows) == 1
    assert rows[0][1] == m.account.account_id
    assert seed.BUCKET_NAME in m.ls(m.path("s3/buckets"))


def test_access_denied_lazy_config_is_eacces(cf: Any) -> None:
    """Denied GetDistributionConfig: config.json EACCES, rest served."""
    m = kit.Mount()
    m.deny("cloudfront", "GetDistributionConfig")
    base = _dir(m, cf)
    with pytest.raises(PermissionDenied):
        m.read(f"{base}/config.json")
    assert m.json(f"{base}/describe.json")["Id"] == cf.distribution_id
    assert m.denied("cloudfront", "get_distribution_config")


def test_seed_cloudfront_is_idempotent(
        cf: Any, moto_session: boto3.Session) -> None:
    """Running the seed again reuses the distribution."""
    assert seed.seed_cloudfront(moto_session) == cf
    assert len(_summaries(moto_session)) == 1
