"""Wave1: async pause + defense scoring regressions."""

from __future__ import annotations

import asyncio
import time

from async_runtime import is_running
from crawl_orchestrator import PauseController


def test_pause_does_not_block_event_loop():
    base = {"ok": True}
    pause = PauseController(lambda: base["ok"])
    pause.pause()

    progress = []

    async def ticker():
        for i in range(4):
            progress.append(i)
            await asyncio.sleep(0.05)

    async def waiter():
        async def running():
            await pause.wait_if_paused()
            return base["ok"]

        # Resume after ticker has made progress
        await asyncio.sleep(0.12)
        pause.resume()
        assert await is_running(running)

    async def main():
        await asyncio.gather(ticker(), waiter())

    t0 = time.perf_counter()
    asyncio.run(main())
    elapsed = time.perf_counter() - t0
    assert progress == [0, 1, 2, 3]
    # Sync sleep would have blocked ticker until resume; async must finish quickly
    assert elapsed < 1.0


def test_pause_controller_sync_call_from_async_does_not_sleep():
    pause = PauseController(lambda: True)
    pause.pause()

    async def main():
        t0 = time.perf_counter()
        # Must return immediately (no busy-wait) when a loop is running
        assert pause() is True
        assert time.perf_counter() - t0 < 0.05

    asyncio.run(main())
