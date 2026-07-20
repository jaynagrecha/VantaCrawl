"""Concurrent BFS crawl loop extracted for clarity."""

from __future__ import annotations

import asyncio
import heapq
from typing import Any, Callable


async def run_concurrent_bfs(
    *,
    queue,
    use_priority: bool,
    running: Callable[[], bool],
    crawl_concurrency: int,
    process_url: Callable[[str], Any],
):
    queue_lock = asyncio.Lock()
    sem = asyncio.Semaphore(max(1, crawl_concurrency))

    async def _pop_next():
        async with queue_lock:
            if not queue:
                return None
            if use_priority:
                _, _, url = heapq.heappop(queue)
                return url
            return queue.popleft()

    async def _wrapped(url: str):
        async with sem:
            await process_url(url)

    while running():
        batch = []
        for _ in range(max(1, crawl_concurrency)):
            url = await _pop_next()
            if url:
                batch.append(url)
        if not batch:
            break
        results = await asyncio.gather(*[_wrapped(u) for u in batch], return_exceptions=True)
        for url, result in zip(batch, results):
            if isinstance(result, Exception):
                raise result
