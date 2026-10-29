"""ApiBudget: limits, rolling window, message.

See ARCHITECTURE: Budget and limits.
"""

from __future__ import annotations

import errno
import threading
from collections.abc import Callable
from typing import Any

import pytest

from awsmount.errors import BudgetExceeded
from awsmount.session.budget import ApiBudget
from awsmount.session.context import Context
from awsmount.tree.root import build_vfs

EXPECTED_MESSAGE = (
    "API call budget exhausted (5000 calls / 600s). Cached data is still "
    "served. Raise --max-api-calls, narrow --services/--region, or run "
    "'refresh'.")


def test_limit_enforced(clock: Any) -> None:
    """charge returns used; the call past the limit raises."""
    budget = ApiBudget(3, 600, clock=clock)
    assert [budget.charge("x") for _ in range(3)] == [1, 2, 3]
    with pytest.raises(BudgetExceeded) as info:
        budget.charge("ec2:DescribeInstances")
    assert info.value.errno == errno.EIO
    assert budget.used() == 3
    assert budget.limit == 3


def test_design_message_text(clock: Any) -> None:
    """The exhaustion message is the documented one."""
    budget = ApiBudget(5000, 600, clock=clock)
    for _ in range(5000):
        budget.charge("x")
    with pytest.raises(BudgetExceeded) as info:
        budget.charge("x")
    assert EXPECTED_MESSAGE in str(info.value)


def test_zero_is_unlimited(clock: Any) -> None:
    """limit=0 never raises."""
    budget = ApiBudget(0, 600, clock=clock)
    for _ in range(10_000):
        budget.charge("x")
    assert budget.used() == 10_000


def test_rolling_window(clock: Any) -> None:
    """Old charges leave the window and free capacity."""
    clock.now = 0.0
    budget = ApiBudget(2, 10, clock=clock)
    budget.charge("a")
    clock.now = 1.0
    budget.charge("b")
    clock.now = 5.0
    with pytest.raises(BudgetExceeded):
        budget.charge("c")
    assert budget.used() == 2
    clock.now = 10.5
    assert budget.used() == 1
    assert budget.charge("d") == 2
    clock.now = 10.6
    with pytest.raises(BudgetExceeded):
        budget.charge("e")
    clock.now = 11.5
    assert budget.charge("f") == 2


def test_failed_charges_not_counted(clock: Any) -> None:
    """Refused calls do not consume the budget."""
    clock.now = 0.0
    budget = ApiBudget(1, 10, clock=clock)
    budget.charge("a")
    for _ in range(5):
        with pytest.raises(BudgetExceeded):
            budget.charge("b")
    assert budget.used() == 1
    clock.now = 10.5
    assert budget.charge("c") == 1


def test_window_zero_is_session_lifetime(clock: Any) -> None:
    """window=0: charges never expire."""
    budget = ApiBudget(2, 0, clock=clock)
    budget.charge("a")
    budget.charge("b")
    clock.advance(10 ** 9)
    with pytest.raises(BudgetExceeded):
        budget.charge("c")
    assert budget.used() == 2


def test_reset(clock: Any) -> None:
    """reset() forgets every recorded call."""
    budget = ApiBudget(1, 0, clock=clock)
    budget.charge("a")
    budget.reset()
    assert budget.used() == 0
    assert budget.charge("b") == 1


def test_thread_safe_exact_count() -> None:
    """Concurrent charges never exceed the limit."""
    budget = ApiBudget(500, 0)
    ok: list[int] = []
    refused: list[int] = []
    lock = threading.Lock()

    def worker() -> None:
        for _ in range(100):
            try:
                budget.charge("x")
            except BudgetExceeded:
                with lock:
                    refused.append(1)
            else:
                with lock:
                    ok.append(1)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert len(ok) == 500
    assert len(refused) == 300
    assert budget.used() == 500


def test_exhaustion_notified_once_per_window(clock: Any) -> None:
    """The first exhaustion of a window is reported once."""
    clock.now = 0.0
    notes: list[str] = []
    budget = ApiBudget(1, 10, clock=clock, on_exhausted=notes.append)
    budget.charge("a")
    for _ in range(3):
        with pytest.raises(BudgetExceeded):
            budget.charge("b")
    assert len(notes) == 1
    assert "API call budget exhausted" in notes[0]
    clock.now = 11.0
    budget.charge("c")
    with pytest.raises(BudgetExceeded):
        budget.charge("d")
    assert len(notes) == 2


def test_invalid_arguments() -> None:
    """Negative limit/window are rejected."""
    with pytest.raises(ValueError):
        ApiBudget(-1, 10)
    with pytest.raises(ValueError):
        ApiBudget(1, -10)


def test_exhaustion_through_vfs(make_ctx: Callable[..., Context],
                                fake: Any) -> None:
    """EIO on exhaustion, one errors.log line, cached data served."""
    ctx = make_ctx(max_api_calls=3)
    vfs = build_vfs(ctx)
    assert vfs.listdir(f"{fake.base}/widgets") == ["w-1", "w-2", "w-3"]
    assert ctx.budget.used() == 3
    for _ in range(2):
        with pytest.raises(BudgetExceeded) as info:
            vfs.listdir(f"{fake.base}/gadgets")
        assert info.value.errno == errno.EIO
        assert "Cached data is still served" in str(info.value)
    with pytest.raises(BudgetExceeded):
        vfs.read(f"{fake.base}/widgets/w-1/details.json")
    lines = [line for line in ctx.errors.render().decode().splitlines()
             if "\tbudget\t" in line]
    assert len(lines) == 1
    assert "(x" not in lines[0]
    assert vfs.listdir(f"{fake.base}/widgets") == ["w-1", "w-2", "w-3"]
    assert b"blue" in vfs.read(f"{fake.base}/widgets/w-2/describe.json")
