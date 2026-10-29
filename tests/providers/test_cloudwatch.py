"""CloudWatch provider (alarms) over the seeded estate."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

ALARMS = "cloudwatch/alarms"


class OkResponse:
    """Minimal 200 response for a ``before-call`` short-circuit."""

    status_code = 200
    headers: dict[str, str] = {}
    content = b""
    text = ""


def test_listing_is_one_call(mount: Any) -> None:
    before = mount.calls()
    mount.ls(mount.path(ALARMS))
    assert mount.calls() - before == 1


def test_alarm_files_and_tags(mount: Any, seed: Any) -> None:
    name = seed.services.alarm_name
    assert mount.ls(mount.path(ALARMS)) == [name]
    d = mount.path(f"{ALARMS}/{name}")
    doc = mount.json(f"{d}/describe.json")
    assert doc["Namespace"] == "AWS/EC2"
    assert mount.text(f"{d}/arn") == doc["AlarmArn"] + "\n"
    assert mount.text(f"{d}/metric") == "CPUUtilization\n"
    assert mount.text(f"{d}/state") == doc["StateValue"] + "\n"
    before = mount.calls()
    assert mount.json(f"{d}/tags.json")["team"] == "platform"
    assert mount.calls() - before == 1


def test_alarm_links(mount: Any, seed: Any) -> None:
    d = mount.path(f"{ALARMS}/{seed.services.alarm_name}/links")
    topics = mount.ls(f"{d}/sns-topics")
    assert len(topics) == 1
    assert mount.realpath(f"{d}/sns-topics/{topics[0]}") == mount.path(
        f"sns/topics/{topics[0]}")
    web = seed.ec2_vpc.instance_web
    assert mount.realpath(f"{d}/instances/{web}") == mount.path(
        f"ec2/instances/{web}")


def test_composite_alarms_are_requested_and_listed(
        make_mount: Callable[..., Any], seed: Any) -> None:
    """moto has no composite alarms, so the response is injected."""
    m = make_mount()
    client = m.ctx.clients.get(None, m.region, "cloudwatch")
    requests: list[str] = []

    def describe_alarms(params: dict[str, Any], **_kwargs: Any
                        ) -> tuple[Any, dict[str, Any]]:
        requests.append(str(params.get("body")))
        arn = "arn:aws:cloudwatch:us-east-1:123456789012:alarm:combo"
        return OkResponse(), {"MetricAlarms": [], "CompositeAlarms": [{
            "AlarmName": "combo", "AlarmArn": arn,
            "AlarmRule": "ALARM(a)", "StateValue": "OK"}]}

    client.meta.events.register("before-call.cloudwatch.DescribeAlarms",
                                describe_alarms)
    assert m.ls(m.path(ALARMS)) == ["combo"]
    assert "CompositeAlarm" in requests[0] and "MetricAlarm" in requests[0]
    d = m.path(f"{ALARMS}/combo")
    assert m.json(f"{d}/describe.json")["AlarmRule"] == "ALARM(a)"


def test_access_denied_listing_degrades_to_empty_dir(
        make_mount: Callable[..., Any], seed: Any,
        deny: Callable[..., Any]) -> None:
    m = make_mount()
    deny(m.ctx, "cloudwatch", "DescribeAlarms", "AccessDenied")
    assert m.ls(m.path(ALARMS)) == []
    assert "describe_alarms" in m.errors()
