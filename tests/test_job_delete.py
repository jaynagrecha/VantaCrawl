"""Delete finished jobs; block active/running statuses."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "web" / "api"
if str(API) not in sys.path:
    sys.path.insert(0, str(API))

from vantacrawl_api.job_access import job_is_deletable  # noqa: E402


def test_finished_statuses_are_deletable():
    for status in ("completed", "failed", "cancelled", "canceled", "stopped"):
        assert job_is_deletable(status), status


def test_active_statuses_are_not_deletable():
    for status in ("queued", "running", "paused", "stopping", "scheduled", "RUNNING", " Queued "):
        assert not job_is_deletable(status), status


def test_delete_route_exists_in_source():
    src = (API / "vantacrawl_api" / "routes" / "jobs.py").read_text(encoding="utf-8")
    assert '@router.delete("/{job_id}"' in src
    assert "job_is_deletable" in src
    assert "Cannot delete a job while status" in src
