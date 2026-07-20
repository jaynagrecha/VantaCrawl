"""Optional Redis-backed URL queue for distributed crawling."""

from __future__ import annotations

from typing import List, Optional


def get_redis_client(redis_url: str):
    try:
        import redis
    except ImportError:
        return None
    try:
        return redis.from_url(redis_url)
    except Exception:
        return None


def push_urls(redis_url: str, queue_name: str, urls: List[str]) -> int:
    client = get_redis_client(redis_url)
    if not client:
        return 0
    if not urls:
        return 0
    return client.rpush(queue_name, *urls)


def pop_url(redis_url: str, queue_name: str) -> Optional[str]:
    client = get_redis_client(redis_url)
    if not client:
        return None
    value = client.lpop(queue_name)
    if value is None:
        return None
    return value.decode("utf-8") if isinstance(value, bytes) else str(value)


def queue_length(redis_url: str, queue_name: str) -> int:
    client = get_redis_client(redis_url)
    if not client:
        return 0
    return int(client.llen(queue_name))
