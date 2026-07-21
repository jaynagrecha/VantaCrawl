"""Concurrent scan slot policy for multi-user queue consumer."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "web" / "api"))

from vantacrawl_api.services.worker_slots import can_start_job  # noqa: E402


def test_different_users_can_run_in_parallel():
    ok, reason = can_start_job(
        "user-b",
        active_job_count=1,
        active_by_user={"user-a": 1},
        max_concurrent=3,
        max_per_user=1,
    )
    assert ok and reason == "ok"


def test_same_user_second_scan_waits():
    ok, reason = can_start_job(
        "user-a",
        active_job_count=1,
        active_by_user={"user-a": 1},
        max_concurrent=3,
        max_per_user=1,
    )
    assert not ok and reason == "user_full"


def test_global_pool_cap():
    ok, reason = can_start_job(
        "user-c",
        active_job_count=3,
        active_by_user={"user-a": 1, "user-b": 1, "user-d": 1},
        max_concurrent=3,
        max_per_user=1,
    )
    assert not ok and reason == "global_full"


def test_unknown_user_still_respects_global_cap():
    ok, reason = can_start_job(
        "",
        active_job_count=2,
        active_by_user={},
        max_concurrent=3,
        max_per_user=1,
    )
    assert ok and reason == "ok"
    ok2, reason2 = can_start_job(
        "",
        active_job_count=3,
        active_by_user={},
        max_concurrent=3,
        max_per_user=1,
    )
    assert not ok2 and reason2 == "global_full"
