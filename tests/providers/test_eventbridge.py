"""EventBridge provider (event buses and their rules).

The seeded rule has a target whose static ``Input`` holds the fake secret.
It must stay hidden in ``targets.json``, and ``--reveal`` shows it.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from awsmount.vfs import walk

BUSES = "eventbridge/event-buses"


def rule_path(m: Any, seed: Any) -> str:
    svc = seed.services
    return m.path(f"{BUSES}/{svc.bus_name}/rules/{svc.rule_name}")


def test_buses_and_their_files(mount: Any, seed: Any) -> None:
    svc = seed.services
    before = mount.calls()
    assert mount.ls(mount.path(BUSES)) == [svc.bus_name, "default"]
    assert mount.calls() - before == 1
    bus = mount.path(f"{BUSES}/{svc.bus_name}")
    assert mount.text(f"{bus}/arn").endswith(f"event-bus/{svc.bus_name}\n")
    assert mount.json(f"{bus}/tags.json")["team"] == "platform"


def test_rule_files_tags_and_links(mount: Any, seed: Any) -> None:
    svc = seed.services
    bus = mount.path(f"{BUSES}/{svc.bus_name}")
    assert mount.ls(f"{bus}/rules") == [svc.rule_name]
    rule = rule_path(mount, seed)
    assert mount.json(f"{rule}/describe.json")["EventBusName"] == svc.bus_name
    assert mount.text(f"{rule}/state") == "ENABLED\n"
    assert mount.json(f"{rule}/tags.json")["team"] == "platform"
    assert mount.realpath(f"{rule}/links/role") == mount.gpath(
        "iam/roles/awsmount-sfn-role")


def test_scheduled_rule_on_the_default_bus(mount: Any, seed: Any) -> None:
    rules = mount.path(f"{BUSES}/default/rules")
    name = seed.services.schedule_rule_name
    assert name in mount.ls(rules)
    assert mount.text(f"{rules}/{name}/schedule") == "rate(1 hour)\n"
    assert mount.text(f"{rules}/{name}/state") == "DISABLED\n"


def test_targets_are_lazy_and_hide_static_input(mount: Any,
                                                seed: Any) -> None:
    rule = rule_path(mount, seed)
    mount.ls(rule)
    before = mount.calls()
    targets = {t["Id"]: t for t in mount.json(f"{rule}/targets.json")}
    assert mount.calls() - before == 1
    assert targets["notify"]["Input"] == "<hidden>"
    assert targets["notify"]["Arn"].startswith("arn:aws:sns:")
    assert "Input" not in targets["workflow"]


def test_reveal_shows_the_static_input(reveal: Any, seed: Any,
                                       seedlib: Any) -> None:
    rule = rule_path(reveal, seed)
    notify = [t for t in reveal.json(f"{rule}/targets.json")
              if t["Id"] == "notify"][0]
    assert seedlib.FAKE_SECRET in notify["Input"]


def test_secret_is_nowhere_in_the_masked_tree(mount: Any,
                                              seedlib: Any) -> None:
    hits = walk.grep(mount.vfs, seedlib.FAKE_SECRET,
                     [mount.path("eventbridge")], recursive=True,
                     files_only=True, on_error=lambda *_: None)
    assert list(hits) == []


def test_access_denied_on_rules_degrades(make_mount: Callable[..., Any],
                                         seed: Any,
                                         deny: Callable[..., Any]) -> None:
    m = make_mount()
    deny(m.ctx, "events", "ListRules", "AccessDeniedException")
    bus = m.path(f"{BUSES}/{seed.services.bus_name}")
    assert m.ls(f"{bus}/rules") == []
    assert "list_rules" in m.errors()
