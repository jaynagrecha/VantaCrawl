from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

import redis

from ..config import get_settings

DELAYED_QUEUE_KEY = "vantacrawl:delayed"


def redis_client() -> redis.Redis:
    return redis.Redis.from_url(get_settings().redis_url, decode_responses=True)


def enqueue_job(job_id: str) -> None:
    settings = get_settings()
    client = redis_client()
    client.lpush(settings.job_queue_key, job_id)


def schedule_job(job_id: str, run_at_unix: float) -> None:
    client = redis_client()
    client.zadd(DELAYED_QUEUE_KEY, {job_id: float(run_at_unix)})


def claim_due_scheduled_jobs(limit: int = 20) -> List[str]:
    """Move due delayed jobs onto the main queue. Returns claimed job ids."""
    client = redis_client()
    now = time.time()
    due = client.zrangebyscore(DELAYED_QUEUE_KEY, min="-inf", max=now, start=0, num=limit)
    claimed: List[str] = []
    for job_id in due or []:
        removed = client.zrem(DELAYED_QUEUE_KEY, job_id)
        if removed:
            enqueue_job(job_id)
            claimed.append(job_id)
    return claimed


def publish_progress(job_id: str, payload: Dict[str, Any]) -> None:
    settings = get_settings()
    client = redis_client()
    client.publish(settings.progress_channel_prefix + job_id, json.dumps(payload))


def set_job_command(job_id: str, command: str) -> None:
    """command: pause | resume | stop"""
    client = redis_client()
    client.set(f"vantacrawl:cmd:{job_id}", command, ex=86400)


def get_job_command(job_id: str) -> Optional[str]:
    client = redis_client()
    return client.get(f"vantacrawl:cmd:{job_id}")


def clear_job_command(job_id: str) -> None:
    client = redis_client()
    client.delete(f"vantacrawl:cmd:{job_id}")


def purge_job_queue_state(job_id: str) -> None:
    """Remove a job id from Redis queues/commands (best-effort)."""
    settings = get_settings()
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
