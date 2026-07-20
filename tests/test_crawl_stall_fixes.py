"""Regression tests for crawl stall + ChromeDriver stack-dump log leak."""

from __future__ import annotations

import asyncio
from collections import deque

from bfs_loop import run_concurrent_bfs
from evasion_layer import EvasionConfig, EvasionSession, detect_challenge
from user_output import sanitize_error_message, simplify_log_line


def test_detect_challenge_ignores_cdn_headers_on_200():
    # Former false positive: header bits "cf-challenge" on a normal page
    assert detect_challenge(200, "cf-challenge cloudflare") == ""
    assert detect_challenge(200, "sucuri cloudproxy") == ""
    assert detect_challenge(403, "blocked by sucuri cloudproxy") == "sucuri"
    assert detect_challenge(429, "") == "rate_limit"


def test_backoff_not_triggered_by_200_with_cf_markers():
    session = EvasionSession(EvasionConfig(enabled=True, level="stealth", adaptive_backoff=True))
    session.after_request("https://lab.local/", 200, "cf-challenge cf-ray")
    assert session.backoff_remaining() == 0
    assert session._challenge_hits == 0


def test_sanitize_strips_chromedriver_stack():
    blob = (
        "Message: unknown error: net::ERR_CONNECTION_CLOSED\n"
        "Stacktrace:\n"
        "#0 0x60ed3afa6218 <unknown>\n"
        "#6 0x60ed3b5d4c94 <unknown>\n"
        "#23 0x7090c7c551f5 <unknown>\n"
    )
    clean = sanitize_error_message(blob)
    assert "0x60ed" not in clean
    assert "<unknown>" not in clean
    assert "ERR_CONNECTION_CLOSED" in clean
    friendly = simplify_log_line(f"Error accessing https://lab.local/: {blob}")
    assert "0x60ed" not in friendly
    assert "Could not open https://lab.local/" in friendly


def test_concurrent_bfs_does_not_batch_barrier():
    """Slow pages must not block other workers from draining the queue."""
    queue = deque([f"https://lab.local/{i}" for i in range(6)])
    started = []
    finished = []
    lock = asyncio.Lock()

    async def process(url: str):
        async with lock:
            started.append(url)
        # First URL is slow; others should still finish while it runs
        if url.endswith("/0"):
            await asyncio.sleep(0.35)
        else:
            await asyncio.sleep(0.02)
        async with lock:
            finished.append(url)

    async def run():
        await run_concurrent_bfs(
            queue=queue,
            use_priority=False,
            running=lambda: True,
            crawl_concurrency=3,
            process_url=process,
            page_timeout=5.0,
        )

    asyncio.run(run())
    assert len(finished) == 6
    # With a true worker pool, some fast URLs finish before the slow first URL
    assert finished[0].endswith("/0") is False or len(finished) == 6
    # Stronger: at least one non-/0 finished before /0 completed
    # (started order may vary; check finished order)
    if "https://lab.local/0" in finished:
        idx = finished.index("https://lab.local/0")
        assert idx > 0 or len(finished) == 1


def test_page_timeout_invokes_callback():
    queue = deque(["https://lab.local/hang"])
    timed = []

    async def hang(_url: str):
        await asyncio.sleep(10)

    async def run():
        await run_concurrent_bfs(
            queue=queue,
            use_priority=False,
            running=lambda: True,
            crawl_concurrency=1,
            process_url=hang,
            page_timeout=0.2,
            on_page_timeout=lambda u: timed.append(u),
        )

    asyncio.run(run())
    assert timed == ["https://lab.local/hang"]
