"""CLI tests: click ``CliRunner`` against an in-process moto estate.

``services`` counts are derived from the registry. One-shot ``ls``,
``cat``, ``grep -r``, ``find``, ``tree``, ``get``, ``export`` and
``shell -c`` run over the estate seeded by ``tests/fixtures/seed.py``
and must find the open ``0.0.0.0/0`` ingress rule of the web security
group, while never leaking the seeded user-data secret.
"""

from __future__ import annotations

import importlib.util
import inspect
import json
import os
import re
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

import boto3
import pytest
from click.testing import CliRunner, Result
from moto import mock_aws

from awsmount import __version__
from awsmount.cli import REVEAL_WARNING, cli
from awsmount.config import Config
from awsmount.providers import ALL, ProviderRegistry
from awsmount.providers.base import CollectionSpec
from awsmount.session.context import Context
from awsmount.session.redact import REDACTED

REGION = "us-east-1"
AWS = ("--region", REGION)
REPO = Path(__file__).resolve().parents[2]
SEED_PATH = REPO / "tests" / "fixtures" / "seed.py"


def _load_seed() -> ModuleType:
    """Import tests/fixtures/seed.py by path (registered first)."""
    name = "awsmount_tests_fixtures_seed"
    loaded = sys.modules.get(name)
    if loaded is not None:
        return loaded
    spec = importlib.util.spec_from_file_location(name, SEED_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


seed = _load_seed()


def _runner() -> CliRunner:
    """CliRunner with separate stderr on every click version."""
    params = inspect.signature(CliRunner.__init__).parameters
    if "mix_stderr" in params:
        return CliRunner(mix_stderr=False)  # type: ignore[call-arg]
    return CliRunner()


def invoke(args: Sequence[str]) -> Result:
    """Run ``awsmount ARGS``."""
    return _runner().invoke(cli, list(args), catch_exceptions=True)


def expect(result: Result, code: int) -> None:
    """Assert the exit code, showing output on failure."""
    assert result.exit_code == code, (
        f"exit {result.exit_code} (wanted {code})\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}\n"
        f"exception: {result.exception!r}")


def _count(specs: Sequence[CollectionSpec]) -> int:
    return sum(1 + _count(s.children) for s in specs)


def _aws_env(mp: pytest.MonkeyPatch, home: Path) -> None:
    for var in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ENDPOINT_URL",
                "AWS_ENDPOINT_URL_STS", "AWS_ENDPOINT_URL_EC2",
                "AWS_ENDPOINT_URL_IAM", "AWS_ROLE_ARN",
                "AWS_WEB_IDENTITY_TOKEN_FILE", "NO_COLOR"):
        mp.delenv(var, raising=False)
    mp.setenv("AWS_ACCESS_KEY_ID", "testing")
    mp.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    mp.setenv("AWS_SESSION_TOKEN", "testing")
    mp.setenv("AWS_DEFAULT_REGION", REGION)
    mp.setenv("AWS_CONFIG_FILE", str(home / "config"))
    mp.setenv("AWS_SHARED_CREDENTIALS_FILE", str(home / "credentials"))
    mp.setenv("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "true")


@pytest.fixture(scope="module")
def estate(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Any]:
    """The seeded EC2/VPC estate inside an active moto mock."""
    with pytest.MonkeyPatch.context() as mp:
        _aws_env(mp, tmp_path_factory.mktemp("aws-home"))
        with mock_aws():
            session = boto3.Session(region_name=REGION)
            yield seed.seed_all(session).ec2_vpc


def _region_path(estate: Any) -> str:
    return f"/{estate.account_id}/{REGION}"


def _sg_dir(estate: Any, group_id: str) -> str:
    return f"{_region_path(estate)}/vpc/security-groups/{group_id}"


# -- no AWS ----------------------------------------------------------------


def test_version() -> None:
    """``--version`` prints the package version."""
    result = invoke(["--version"])
    expect(result, 0)
    assert __version__ in result.stdout
    result = invoke(["version"])
    expect(result, 0)
    assert result.stdout == f"awsmount {__version__}\n"


def test_services_counts_derive_from_registry() -> None:
    """Header counts equal the registry (and an independent count)."""
    registry = ProviderRegistry()
    rows = registry.summary()
    assert len(rows) == sum(_count(s.collections) for s in ALL)
    assert len(registry.services()) == len(ALL) > 0
    result = invoke(["services"])
    expect(result, 0)
    lines = result.stdout.splitlines()
    assert lines[0] == (f"{len(ALL)} services, {len(rows)} resource "
                        "types")
    body = "\n".join(lines[1:])
    for service, collection, _scope in rows:
        assert service in body
        assert collection in body


def test_services_json() -> None:
    """JSON output lists every registry row."""
    registry = ProviderRegistry()
    result = invoke(["services", "--json"])
    expect(result, 0)
    data = json.loads(result.stdout)
    assert data["services"] == len(registry.services())
    assert data["resource_types"] == len(registry.summary())
    items = [(i["service"], i["collection"], i["scope"])
             for i in data["items"]]
    assert items == registry.summary()


def test_services_markdown() -> None:
    """Markdown output has the header and one row per service."""
    registry = ProviderRegistry()
    result = invoke(["services", "--markdown"])
    expect(result, 0)
    rows = registry.summary()
    header = f"{len(registry.services())} services, {len(rows)} " \
        "resource types"
    assert header in result.stdout.splitlines()
    coverage = result.stdout.split("## Files and links")[0]
    table = [line for line in coverage.splitlines()
             if line.startswith("| ") and not line.startswith("| Service")]
    assert len(table) == len({(s, sc) for s, _c, sc in rows})


def test_services_markdown_lists_files_and_links() -> None:
    """A second table has one row per resource type with its files."""
    result = invoke(["services", "--markdown"])
    expect(result, 0)
    section = result.stdout.split("## Files and links")[1]
    table = [line for line in section.splitlines()
             if line.startswith("| ")
             and not line.startswith(("| Resource type", "|---"))]
    assert len(table) == len(ProviderRegistry().summary())
    row = next(line for line in table if line.startswith("| ec2/instances "))
    assert "describe.json" in row and "user-data" in row
    assert "security-groups/" in row


def test_services_default_lists_files_and_links() -> None:
    """The default output shows each type's files and links."""
    result = invoke(["services"])
    expect(result, 0)
    out = result.stdout
    assert "files: describe.json" in out
    assert "links: " in out
    assert "user-data*" in out
    assert "fetched on first read" in out
    lines = out.splitlines()
    at = lines.index("  instances")
    assert lines[at + 1].startswith("    files: describe.json, arn")


def test_services_short_is_one_line_per_service() -> None:
    """``--short`` keeps the compact view, without files."""
    registry = ProviderRegistry()
    result = invoke(["services", "--short"])
    expect(result, 0)
    lines = result.stdout.splitlines()
    assert "files:" not in result.stdout
    assert len(lines) == 1 + len({(s, sc) for s, _c, sc
                                  in registry.summary()})


def test_services_json_has_files_and_links() -> None:
    result = invoke(["services", "--json"])
    expect(result, 0)
    items = json.loads(result.stdout)["items"]
    inst = next(i for i in items
                if (i["service"], i["collection"]) == ("ec2", "instances"))
    assert "describe.json" in inst["files"]
    assert "user-data*" in inst["files"]
    assert "vpc" in inst["links"]


def test_readme_coverage_count_matches_registry() -> None:
    """A coverage count stated in README.md must be the real one."""
    readme = REPO / "README.md"
    if not readme.is_file():
        pytest.skip("README.md not present")
    text = readme.read_text(encoding="utf-8")
    assert not re.search(r"(?i)100\s*%\s*(coverage|of aws)", text)
    found = re.findall(r"(\d+)\s+services?\W+(\d+)\s+resource types",
                       text)
    if not found:
        pytest.skip("README.md states no coverage count")
    registry = ProviderRegistry()
    expected = (str(len(registry.services())),
                str(len(registry.summary())))
    for pair in found:
        assert pair == expected


def test_unknown_service_is_usage_error() -> None:
    """Unknown ``--services`` names exit 2 before any AWS call."""
    result = invoke(["ls", "--services", "nope", "/"])
    expect(result, 2)
    assert "unknown service" in result.stderr


def test_doctor_json() -> None:
    """``doctor --json`` reports checks and a per-method summary."""
    result = invoke(["doctor", "--json"])
    expect(result, 0)
    data = json.loads(result.stdout)
    assert {"shell", "webdav-serve", "webdav-mount", "fuse"} <= set(
        data["summary"])
    assert any(c["method"] == "python" for c in data["checks"])


def test_doctor_uses_a_profile_given_before_or_after_the_command(
        tmp_path: Path) -> None:
    """``-p`` means the same on either side of ``doctor``."""
    with pytest.MonkeyPatch.context() as mp:
        _aws_env(mp, tmp_path)
        before = invoke(["-p", "typo", "doctor", "--check-credentials",
                         "--json"])
        after = invoke(["doctor", "--check-credentials", "-p", "typo",
                        "--json"])
    for result in (before, after):
        expect(result, 1)
        rows = {c["method"]: c for c in json.loads(result.stdout)["checks"]}
        assert rows["credentials:typo"]["status"] == "FAIL"
        assert "ProfileNotFound" in rows["credentials:typo"]["detail"]
        assert "credentials:default" not in rows


def test_doctor_exit_code_follows_the_fail_rows(
        estate: Any, tmp_path: Path) -> None:
    """0 when every row is fine, 1 when a credential check says FAIL."""
    expect(invoke(["doctor", "--json"]), 0)
    good = invoke(["doctor", "--check-credentials", "--json"])
    expect(good, 0)
    rows = {c["method"]: c for c in json.loads(good.stdout)["checks"]}
    assert rows["credentials:default"]["status"] == "OK"
    with pytest.MonkeyPatch.context() as mp:
        _aws_env(mp, tmp_path)
        bad = invoke(["doctor", "--check-credentials", "-p", "typo"])
    expect(bad, 1)
    assert "FAIL" in bad.stdout
    assert "credentials:typo" in bad.stdout


# -- one-shots over the estate --------------------------------------------


def test_ls_root_and_account(estate: Any) -> None:
    """Root lists the account; the account lists _meta/global/region."""
    result = invoke(["ls", *AWS, "/"])
    expect(result, 0)
    assert result.stdout == f"{estate.account_id}\n"
    result = invoke(["ls", *AWS, f"/{estate.account_id}"])
    expect(result, 0)
    assert result.stdout == f"_meta\nglobal\n{REGION}\n"


def test_group_level_options(estate: Any) -> None:
    """Options before the subcommand are honoured."""
    result = invoke(["--region", REGION, "ls", f"/{estate.account_id}"])
    expect(result, 0)
    assert result.stdout == f"_meta\nglobal\n{REGION}\n"


def test_ls_region_and_services_filter(estate: Any) -> None:
    """Region dirs list registered services; --services narrows."""
    registry = ProviderRegistry()
    names = sorted(s.dirname for s in registry.services("region"))
    result = invoke(["ls", *AWS, _region_path(estate)])
    expect(result, 0)
    assert result.stdout == "".join(f"{n}\n" for n in names)
    result = invoke(["ls", *AWS, "--services", "vpc",
                     _region_path(estate)])
    expect(result, 0)
    assert result.stdout == "vpc\n"


def test_ls_security_groups(estate: Any) -> None:
    """Every seeded security group has a directory."""
    result = invoke(["ls", *AWS,
                     f"{_region_path(estate)}/vpc/security-groups"])
    expect(result, 0)
    listed = result.stdout.splitlines()
    for group in (estate.sg_web, estate.sg_app, estate.sg_db,
                  estate.sg_lonely):
        assert group in listed


def test_cat_rules_json_shows_open_ingress(estate: Any) -> None:
    """rules.json of the web SG has 0.0.0.0/0 on 443 ingress."""
    result = invoke(["cat", *AWS,
                     f"{_sg_dir(estate, estate.sg_web)}/rules.json"])
    expect(result, 0)
    rows = json.loads(result.stdout)
    open_rows = [r for r in rows if r.get("cidr") == "0.0.0.0/0"
                 and r["direction"] == "ingress"]
    assert open_rows == [{
        "cidr": "0.0.0.0/0", "description": "public https",
        "direction": "ingress", "from_port": 443, "protocol": "tcp",
        "to_port": 443}]


def test_grep_recursive_finds_open_rule(estate: Any) -> None:
    """``grep -r`` over the mounted estate finds the open rule."""
    result = invoke(["grep", "-r", "-l", "--region", REGION,
                     "--services", "vpc", "0.0.0.0/0", "/"])
    expect(result, 0)
    lines = result.stdout.splitlines()
    assert f"{_sg_dir(estate, estate.sg_web)}/rules.json" in lines
    assert f"{_sg_dir(estate, estate.sg_web)}/describe.json" in lines
    assert not any("/links/" in line or "/referenced-by/" in line
                   for line in lines)


def test_grep_line_numbers_on_rule_file(estate: Any) -> None:
    """``grep -n`` reports the cidr line of the open rule."""
    path = f"{_sg_dir(estate, estate.sg_web)}/rules.json"
    result = invoke(["grep", "-n", "--region", REGION,
                     '"cidr": "0\\.0\\.0\\.0/0"', path])
    expect(result, 0)
    assert re.match(r"^\d+:\s+\"cidr\": \"0\.0\.0\.0/0\",$",
                    result.stdout.splitlines()[0])


def test_grep_whole_estate_never_leaks_user_data(estate: Any) -> None:
    """The user-data secret is invisible to grep without --reveal."""
    result = invoke(["grep", "-r", "--region", REGION, "--services",
                     "ec2,vpc", seed.FAKE_SECRET, "/"])
    expect(result, 1)
    assert seed.FAKE_SECRET not in result.stdout


def test_cat_user_data_is_redacted(estate: Any) -> None:
    """user-data is whole-file redacted by default."""
    path = f"{_region_path(estate)}/ec2/instances/" \
        f"{estate.instance_web}/user-data"
    result = invoke(["cat", *AWS, path])
    expect(result, 0)
    assert result.stdout == REDACTED + "\n"
    assert REVEAL_WARNING not in result.stderr


def test_reveal_prints_warning(estate: Any) -> None:
    """--reveal warns on stderr, never on stdout."""
    result = invoke(["ls", "--reveal", *AWS, "/"])
    expect(result, 0)
    assert REVEAL_WARNING in result.stderr
    assert REVEAL_WARNING not in result.stdout
    assert result.stdout == f"{estate.account_id}\n"
    quiet = invoke(["ls", *AWS, "/"])
    expect(quiet, 0)
    assert "WARNING" not in quiet.stderr


def test_reveal_disables_user_data_redaction(estate: Any) -> None:
    """With --reveal user-data is fetched instead of redacted."""
    path = f"{_region_path(estate)}/ec2/instances/" \
        f"{estate.instance_web}/user-data"
    result = invoke(["cat", "--reveal", *AWS, path])
    assert result.exit_code in (0, 1), result.stderr
    assert REDACTED not in result.stdout
    assert REVEAL_WARNING in result.stderr


def test_get_one_shot(estate: Any) -> None:
    """``get`` extracts raw strings."""
    path = f"{_sg_dir(estate, estate.sg_web)}/describe.json"
    result = invoke(["get", *AWS, path, "GroupName"])
    expect(result, 0)
    assert result.stdout == f"{seed.SG_WEB}\n"


def test_find_one_shot(estate: Any) -> None:
    """``find -name`` lists the rules files."""
    result = invoke(["find", *AWS,
                     f"{_region_path(estate)}/vpc/security-groups",
                     "-name", "rules.json"])
    expect(result, 0)
    lines = result.stdout.splitlines()
    assert f"{_sg_dir(estate, estate.sg_web)}/rules.json" in lines
    assert all(line.endswith("/rules.json") for line in lines)


def test_tree_one_shot(estate: Any) -> None:
    """``tree -L 1`` of vpc lists one dir per collection."""
    registry = ProviderRegistry()
    vpc = registry.service("region", "vpc")
    assert vpc is not None
    result = invoke(["tree", "-L", "1", *AWS,
                     f"{_region_path(estate)}/vpc"])
    expect(result, 0)
    assert "security-groups" in result.stdout
    assert result.stdout.endswith(
        f"\n{len(vpc.collections)} directories, 0 files\n")


def test_cat_missing_exits_one(estate: Any) -> None:
    """A missing file exits 1 with a cat-style message."""
    path = f"/{estate.account_id}/nope"
    result = invoke(["cat", *AWS, path])
    expect(result, 1)
    assert f"cat: {path}: {os.strerror(2)}" in result.stderr


def test_budget_exhaustion_exits_four(estate: Any) -> None:
    """Exceeding --max-api-calls exits 4 with a clear message."""
    result = invoke(["ls", "--max-api-calls", "2", *AWS,
                     f"{_region_path(estate)}/vpc/security-groups"])
    expect(result, 4)
    assert "API call budget exhausted" in result.stderr


def test_shell_c(estate: Any) -> None:
    """``shell -c`` runs one line and exits with its status."""
    result = invoke(["shell", *AWS, "-c", "ls /"])
    expect(result, 0)
    assert result.stdout == f"{estate.account_id}\n"
    expect(invoke(["shell", *AWS, "-c", "exit 5"]), 5)
    expect(invoke(["shell", *AWS, "-c", "nosuchcommand"]), 127)


@pytest.mark.skipif(not os.access("/bin/sh", os.X_OK),
                    reason="/bin/sh is required")
def test_shell_c_pipe(estate: Any) -> None:
    """Builtin output can be piped to a host command."""
    path = f"{_sg_dir(estate, estate.sg_web)}/group-name"
    result = invoke(["shell", *AWS, "-c", f"cat {path} | !tr a-z A-Z"])
    expect(result, 0)
    assert result.stdout == seed.SG_WEB.upper() + "\n"


def test_export_one_shot(estate: Any, tmp_path: Path) -> None:
    """``export`` writes the subtree and refuses a non-empty dest."""
    dest = tmp_path / "snap"
    src = _sg_dir(estate, estate.sg_web)
    result = invoke(["export", *AWS, src, str(dest)])
    expect(result, 0)
    assert "exported " in result.stderr
    assert "0.0.0.0/0" in (dest / "rules.json").read_text()
    assert (dest / ".awsmount-export").is_file()
    expect(invoke(["export", *AWS, src, str(dest)]), 1)
    expect(invoke(["export", *AWS, "--clean", src, str(dest)]), 0)


def test_export_links_skip_leaves_no_empty_link_directories(
        estate: Any, tmp_path: Path) -> None:
    """``--links skip`` omits ``links/`` and ``referenced-by/`` entirely."""
    src = _sg_dir(estate, estate.sg_web)
    full, skipped = tmp_path / "file", tmp_path / "skip"
    expect(invoke(["export", *AWS, src, str(full)]), 0)
    expect(invoke(["export", *AWS, "--links", "skip", src, str(skipped)]), 0)
    assert any((full / "links").iterdir()), "the default keeps the links"
    assert (full / "referenced-by").is_dir()
    assert not (skipped / "links").exists()
    assert not (skipped / "referenced-by").exists()

    def rest(root: Path) -> list[str]:
        """Every path except the link containers and what is in them."""
        return sorted(
            p.relative_to(root).as_posix() for p in root.rglob("*")
            if not {"links", "referenced-by"} & set(
                p.relative_to(root).parts))

    assert rest(full) == rest(skipped)
    assert (skipped / "rules.json").read_text() == \
        (full / "rules.json").read_text()


# -- a profile that cannot be resolved ---------------------------------------


def test_working_profile_prints_no_profile_warning(estate: Any) -> None:
    """A normal run says nothing about profiles and exits 0."""
    result = invoke(["ls", *AWS, "/"])
    expect(result, 0)
    assert "profile" not in result.stderr


def test_mistyped_profile_is_announced_and_exits_three(
        tmp_path: Path) -> None:
    """A profile that does not exist is not a silent empty account."""
    with pytest.MonkeyPatch.context() as mp:
        _aws_env(mp, tmp_path)
        result = invoke(["-p", "typo", "ls", "/"])
    expect(result, 3)
    assert result.stdout == "profile-typo\n"
    assert "awsmount: profile typo: " in result.stderr
    assert "nothing is shown for it" in result.stderr
    assert "typo" in result.stderr.split("profile typo: ", 1)[1]


def test_a_search_over_a_failed_profile_is_not_no_match(
        tmp_path: Path) -> None:
    """``grep -r`` that could not look exits 3, never 1 (no match)."""
    with pytest.MonkeyPatch.context() as mp:
        _aws_env(mp, tmp_path)
        result = invoke(["-p", "typo", "grep", "-r", "-l", "0.0.0.0/0",
                         "/"])
    expect(result, 3)
    assert result.stdout == ""
    assert "nothing is shown for it" in result.stderr


def test_one_bad_profile_among_good_ones_exits_three(
        tmp_path: Path) -> None:
    """The good account is listed, the bad one is announced, exit is 3."""
    with pytest.MonkeyPatch.context() as mp:
        _aws_env(mp, tmp_path)
        (tmp_path / "credentials").write_text(
            "[good]\naws_access_key_id = testing\n"
            "aws_secret_access_key = testing\n")
        (tmp_path / "config").write_text(
            f"[profile good]\nregion = {REGION}\n")
        with mock_aws():
            result = invoke(["-p", "good", "-p", "typo", "ls", "/"])
    expect(result, 3)
    names = result.stdout.split()
    assert "profile-typo" in names
    assert len(names) == 2
    assert result.stderr.count("awsmount: profile ") == 1
    assert "awsmount: profile typo: " in result.stderr


def test_export_of_a_failed_profile_exits_three(tmp_path: Path) -> None:
    """``export`` that wrote nothing but ``_meta`` is partial, not OK."""
    with pytest.MonkeyPatch.context() as mp:
        _aws_env(mp, tmp_path / "home")
        result = invoke(["-p", "typo", "export", "/", str(tmp_path / "x")])
    expect(result, 3)
    assert "nothing is shown for it" in result.stderr


def test_a_failed_profile_is_announced_once(
        tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Retrying a failed profile does not repeat the same line."""
    with pytest.MonkeyPatch.context() as mp:
        _aws_env(mp, tmp_path)
        ctx = Context.from_config(Config(profiles=("typo",),
                                         regions=(REGION,),
                                         negative_ttl=0.0))
        ctx.accounts.accounts()
        ctx.accounts.accounts()
    assert capsys.readouterr().err.count("awsmount: profile typo: ") == 1
    assert set(ctx.accounts.failures()) == {"typo"}
    ctx.accounts.reset()
    assert ctx.accounts.failures() == {}


# -- awsmount secrets --------------------------------------------------------

SECRET_VALUE = "CANARY-cli-secret"
PARAM_VALUE = "CANARY-cli-param"


@pytest.fixture
def secrets_estate(tmp_path: Path,
                   monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """One secret and one parameter with known values, inside moto.

    The module-scoped ``estate`` may keep a mock alive around this one,
    and both share one backend, so the pair is removed again afterwards.
    """
    _aws_env(monkeypatch, tmp_path)
    with mock_aws():
        sm = boto3.client("secretsmanager", region_name=REGION)
        ssm = boto3.client("ssm", region_name=REGION)
        sm.create_secret(Name="team/api", SecretString=SECRET_VALUE)
        ssm.put_parameter(Name="/team/db/host", Type="String",
                          Value=PARAM_VALUE)
        try:
            yield
        finally:
            sm.delete_secret(SecretId="team/api",
                             ForceDeleteWithoutRecovery=True)
            ssm.delete_parameter(Name="/team/db/host")


def test_secrets_command_is_listed_with_its_subcommands() -> None:
    result = invoke(["--help"])
    expect(result, 0)
    assert "secrets" in result.stdout
    result = invoke(["secrets", "--help"])
    expect(result, 0)
    for word in ("mount", "shell", "umount"):
        assert word in result.stdout
    assert "export" not in result.stdout


def test_secrets_shell_prints_the_values_and_warns(
        secrets_estate: None) -> None:
    result = invoke(["secrets", "shell", *AWS, "-c",
                     "cat secretsmanager/team%2Fapi/value"])
    expect(result, 0)
    assert result.stdout == SECRET_VALUE
    assert "secret VALUES" in result.stderr
    assert "kept in memory for 300 s" in result.stderr
    result = invoke(["secrets", "shell", *AWS, "-c",
                     "cat ssm/team/db/host"])
    expect(result, 0)
    assert result.stdout == PARAM_VALUE


def test_secrets_ttl_zero_says_not_cached(secrets_estate: None) -> None:
    result = invoke(["secrets", "shell", *AWS, "--ttl", "0", "-c", "ls /"])
    expect(result, 0)
    assert "not cached" in result.stderr


def test_secrets_options_given_before_the_command_are_used(
        secrets_estate: None) -> None:
    result = invoke(["--region", REGION, "--ttl", "42", "secrets", "shell",
                     "-c", "ls /"])
    expect(result, 0)
    assert result.stdout == "secretsmanager\nssm\n"
    assert "kept in memory for 42 s" in result.stderr


@pytest.mark.parametrize("args", [
    ["--reveal", "secrets", "shell", "-c", "ls /"],
    ["--services", "ssm", "secrets", "shell", "-c", "ls /"],
    ["--s3-objects", "3", "secrets", "shell", "-c", "ls /"],
    ["secrets", "shell", "-p", "a", "-p", "b", "-c", "ls /"],
    ["-p", "a", "-p", "b", "secrets", "shell", "-c", "ls /"],
    ["secrets", "shell", "-r", "all", "-c", "ls /"],
    ["secrets", "shell", "-r", "us-east-1,eu-west-1", "-c", "ls /"],
])
def test_secrets_refuses_options_that_do_not_apply(
        secrets_estate: None, args: list[str]) -> None:
    result = invoke(args)
    expect(result, 2)
    assert "secret VALUES" not in result.stderr


def test_secrets_without_any_region_is_an_error(
        secrets_estate: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AWS_DEFAULT_REGION")
    result = invoke(["secrets", "shell", "-c", "ls /"])
    expect(result, 2)
    assert "no region" in result.stderr


def test_secrets_with_unusable_credentials_does_not_start(
        secrets_estate: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AWS_ACCESS_KEY_ID")
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY")
    result = invoke(["secrets", "shell", *AWS, "-c", "ls /"])
    expect(result, 1)
    assert "cannot use these credentials" in result.stderr
    assert "secret VALUES" not in result.stderr


def test_the_normal_tree_still_never_serves_a_value(
        secrets_estate: None) -> None:
    """Same account, normal commands: names only, no value, no flag."""
    result = invoke(["grep", "-r", "CANARY", *AWS, "/"])
    assert SECRET_VALUE not in result.stdout + result.stderr
    assert PARAM_VALUE not in result.stdout + result.stderr
    result = invoke(["--reveal", "grep", "-r", "CANARY", *AWS, "/"])
    assert SECRET_VALUE not in result.stdout + result.stderr
    assert PARAM_VALUE not in result.stdout + result.stderr


def test_secrets_umount_of_a_plain_directory_exits_one(
        tmp_path: Path) -> None:
    result = invoke(["secrets", "umount", str(tmp_path)])
    expect(result, 1)
    assert "not a mount point" in result.stderr


def test_secrets_mount_hands_the_secrets_tree_to_the_adapter(
        secrets_estate: None, tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch) -> None:
    """``mount`` builds the secrets session, warns, and cleans up."""
    import awsmount.cli as cli_module
    from awsmount.secrets.cli import WEBDAV_CACHE_WARNING
    seen: dict[str, Any] = {}

    def fake_mount(vfs: Any, ctx: Any, mountpoint: str,
                   **kwargs: Any) -> int:
        seen.update(vfs=vfs, ctx=ctx, mountpoint=mountpoint, **kwargs)
        seen["listing"] = vfs.listdir("/")
        seen["value"] = vfs.read("/ssm/team/db/host")
        seen["store"] = vfs.root._src.store
        assert len(seen["store"]) == 1
        return 0

    monkeypatch.setattr(cli_module, "_adapter",
                        lambda module, attr: fake_mount)
    for method, warns in (("webdav", True), ("fuse", False)):
        monkeypatch.setattr("awsmount.platform.is_macos", lambda: True)
        result = invoke(["secrets", "mount", *AWS, "--method", method,
                         str(tmp_path / "mnt")])
        expect(result, 0)
        assert seen["listing"] == ["secretsmanager", "ssm"]
        assert seen["value"] == PARAM_VALUE.encode()
        assert seen["mountpoint"] == str(tmp_path / "mnt")
        assert len(seen["store"]) == 0, "values must be wiped at exit"
        assert ("temporary copy" in result.stderr) is warns
        assert WEBDAV_CACHE_WARNING.startswith("awsmount: WARNING")
    assert seen["ctx"].registry.services() == []
