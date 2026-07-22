"""Redis progress publish must not abort long-running scans."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "web" / "api"
if str(API) not in sys.path:
    sys.path.insert(0, str(API))

import redis  # noqa: E402

from vantacrawl_api.services import queue as queue_mod  # noqa: E402


def test_publish_progress_swallows_connection_refused():
    """Render Key Value Error 111 must not fail the worker mid-scan."""
    client = MagicMock()
    client.publish.side_effect = redis.ConnectionError(
        "Error 111 connecting to red-xxxxx:6379. Connection refused."
    )
    with patch.object(queue_mod, "redis_client", return_value=client):
        with patch.object(queue_mod.time, "sleep", return_value=None):
            # Must not raise
            queue_mod.publish_progress("job-1", {"status": "running", "log": "hi"})
    assert client.publish.call_count >= 1


def test_get_job_command_returns_none_on_redis_down():
    client = MagicMock()
    client.get.side_effect = redis.ConnectionError("Connection refused")
    with patch.object(queue_mod, "redis_client", return_value=client):
        with patch.object(queue_mod.time, "sleep", return_value=None):
            assert queue_mod.get_job_command("job-1") is None


def test_enqueue_job_still_raises_after_retries():
    client = MagicMock()
    client.lpush.side_effect = redis.ConnectionError("Connection refused")
    with patch.object(queue_mod, "redis_client", return_value=client):
        with patch.object(queue_mod.time, "sleep", return_value=None):
            with pytest.raises(redis.ConnectionError):
                queue_mod.enqueue_job("job-1")
