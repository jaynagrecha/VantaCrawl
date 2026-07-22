from __future__ import annotations

import json
import logging
import time
from typing import Any, Callable, Dict, List, Optional, TypeVar

import redis

from ..config import get_settings

DELAYED_QUEUE_KEY = "vantacrawl:delayed"
log = logging.getLogger("vantacrawl.queue")

T = TypeVar("T")

# Transient Redis failures must not abort a long-running scan (Render Key Value
# can briefly refuse connections / restart while a crawl is mid-flight).
_REDIS_TRANSIENT = (
    redis.RedisError,
    OSError,
    ConnectionError,
    TimeoutError,
)


def redis_client() -> redis.Redis:
    """Return a Redis client with short timeouts so a dead KV does not hang the worker."""
    return redis.Redis.from_url(
        get_settings().redis_url,
        decode_responses=True,
        socket_connect_timeout=5,
        socket_timeout=5,
        retry_on_timeout=True,
        health_check_interval=30,
    )


def _retry(
    op: str,
    fn: Callable[[], T],
    *,
    attempts: int = 3,
    critical: bool = False,
    default: T = None,
) -> T:
    last: Optional[BaseException] = None
    for i in range(max(1, attempts)):
        try:
            return fn()
        except _REDIS_TRANSIENT as exc:
            last = exc
            log.warning("Redis %s failed (%s/%s): %s", op, i + 1, attempts, exc)
            if i + 1 < attempts:
                time.sleep(min(2.0, 0.35 * (2**i)))
    if critical and last is not None:
        raise last
    if last is not None:
        log.error("Redis %s giving up (non-fatal): %s", op, last)
    return default


def enqueue_job(job_id: str) -> None:
    settings = get_settings()

    def _do() -> None:
        redis_client().lpush(settings.job_queue_key, job_id)

    _retry("enqueue_job", _do, attempts=4, critical=True)


def schedule_job(job_id: str, run_at_unix: float) -> None:
    def _do() -> None:
        redis_client().zadd(DELAYED_QUEUE_KEY, {job_id: float(run_at_unix)})

    _retry("schedule_job", _do, attempts=3, critical=True)


def claim_due_scheduled_jobs(limit: int = 20) -> List[str]:
    """Move due delayed jobs onto the main queue. Returns claimed job ids."""

    def _do() -> List[str]:
        client = redis_client()
        now = time.time()
        due = client.zrangebyscore(DELAYED_QUEUE_KEY, min="-inf", max=now, start=0, num=limit)
        claimed: List[str] = []
        for job_id in due or []:
            removed = client.zrem(DELAYED_QUEUE_KEY, job_id)
            if removed:
                client.lpush(get_settings().job_queue_key, job_id)
                claimed.append(job_id)
        return claimed

    return _retry("claim_due_scheduled_jobs", _do, attempts=2, critical=False, default=[]) or []


def publish_progress(job_id: str, payload: Dict[str, Any]) -> None:
    """Best-effort live UI pub/sub — never fail the scan if Redis is briefly down."""
    settings = get_settings()
    channel = settings.progress_channel_prefix + job_id
    body = json.dumps(payload)

    def _do() -> None:
        redis_client().publish(channel, body)

    _retry("publish_progress", _do, attempts=2, critical=False)


def set_job_command(job_id: str, command: str) -> None:
    """command: pause | resume | stop — best-effort (API already updates DB status)."""

    def _do() -> None:
        redis_client().set(f"vantacrawl:cmd:{job_id}", command, ex=86400)

    _retry("set_job_command", _do, attempts=3, critical=False)


def get_job_command(job_id: str) -> Optional[str]:
    def _do() -> Optional[str]:
        return redis_client().get(f"vantacrawl:cmd:{job_id}")

    return _retry("get_job_command", _do, attempts=2, critical=False, default=None)


def clear_job_command(job_id: str) -> None:
    def _do() -> None:
        redis_client().delete(f"vantacrawl:cmd:{job_id}")

    _retry("clear_job_command", _do, attempts=2, critical=False)


def purge_job_queue_state(job_id: str) -> None:
    """Remove a job id from Redis queues/commands (best-effort)."""
    settings = get_settings()

    def _do() -> None:
        client = redis_client()
        try:
            client.lrem(settings.job_queue_key, 0, job_id)
        except Exception:
            pass
        try:
            client.zrem(DELAYED_QUEUE_KEY, job_id)
        except Exception:
            pass
        try:
            client.delete(f"vantacrawl:cmd:{job_id}")
        except Exception:
            pass

    _retry("purge_job_queue_state", _do, attempts=2, critical=False)
