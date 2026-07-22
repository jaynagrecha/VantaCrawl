"""Concurrent BFS crawl loop — continuous worker pool with per-page timeout."""

from __future__ import annotations

import asyncio
import heapq
from typing import Any, Callable, Optional, Union, Awaitable

from async_runtime import is_running

RunningFn = Callable[[], Union[bool, Awaitable[bool]]]


async def run_concurrent_bfs(
    *,
    queue,
    use_priority: bool,
    running: RunningFn,
    crawl_concurrency: int,
    process_url: Callable[[str], Any],
    page_timeout: float = 90.0,
    on_page_timeout: Optional[Callable[[str], Any]] = None,
    queue_lock: Optional[asyncio.Lock] = None,
):
    """Process the queue with N workers; do not batch-barrier on the slowest URL.

    Each page is bounded by ``page_timeout`` so one hung fetch cannot freeze the crawl.
    Workers exit only after the queue stays empty while no work is in flight.

    When ``queue_lock`` is provided, share it with producers that enqueue into the
    same queue (e.g. crawl discover) so pop/push stay consistent.
    """
    queue_lock = queue_lock or asyncio.Lock()
    state = {"active": 0, "empty_streak": 0}
    n = max(1, int(crawl_concurrency) or 1)
    timeout = max(1.0, float(page_timeout) if page_timeout else 90.0)

    async def _pop_next():
        async with queue_lock:
            if not queue:
                return None
            if use_priority:
                _, _, url = heapq.heappop(queue)
                return url
            return queue.popleft()

    async def _worker():
        while await is_running(running):
            url = await _pop_next()
            if url is None:
                await asyncio.sleep(0.15)
                async with queue_lock:
                    if not queue and state["active"] == 0:
                        state["empty_streak"] += 1
                        if state["empty_streak"] >= 3:
                            return
                    else:
                        state["empty_streak"] = 0
                continue

            async with queue_lock:
                state["active"] += 1
                state["empty_streak"] = 0
            try:
                try:
                    await asyncio.wait_for(process_url(url), timeout=timeout)
                except asyncio.TimeoutError:
                    if on_page_timeout is not None:
                        try:
                            on_page_timeout(url)
                        except Exception:
                            pass
                except Exception:
                    # process_url is expected to catch its own errors; re-raise only
                    # unexpected escapes so the worker dies visibly.
                    raise
            finally:
                async with queue_lock:
                    state["active"] = max(0, state["active"] - 1)

    await asyncio.gather(*[_worker() for _ in range(n)])
