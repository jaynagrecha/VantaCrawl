from __future__ import annotations

import json
from typing import Any, Dict, Optional

import redis

from ..config import get_settings


def redis_client() -> redis.Redis:
    return redis.Redis.from_url(get_settings().redis_url, decode_responses=True)


def enqueue_job(job_id: str) -> None:
    settings = get_settings()
    client = redis_client()
    client.lpush(settings.job_queue_key, job_id)


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
