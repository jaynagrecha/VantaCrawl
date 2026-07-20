"""Virtual-host discovery (Gobuster vhost mode)."""

from __future__ import annotations

import asyncio
from typing import Callable, List, Optional
from urllib.parse import urlparse

import httpx

from crawler_common import load_wordlist, response_length


async def enumerate_vhosts(
    base_url: str,
    wordlist_path: str,
    client: httpx.AsyncClient,
    *,
    baseline_length: int,
    baseline_status: int,
    running: Callable[[], bool],
    output_callback,
    status_filter,
    exclude_lengths: set,
    max_hosts: int = 500,
    concurrency: int = 40,
) -> List[str]:
    parsed = urlparse(base_url)
    base_host = parsed.netloc
    if ":" in base_host:
        base_host = base_host.split(":")[0]
    words = load_wordlist(wordlist_path)[:max_hosts]
    found: List[str] = []
    found_set = set()
    sem = asyncio.Semaphore(max(1, concurrency))

    async def check_word(word: str):
        if not running():
            return
        host = f"{word.strip()}.{base_host}"
        async with sem:
            try:
                response = await client.get(
                    base_url,
                    headers={"Host": host},
                    timeout=8,
                    follow_redirects=False,
                )
            except httpx.HTTPError:
                return
        if not status_filter.allows(response.status_code):
            return
        length = response_length(response)
        if length in exclude_lengths:
            return
        if response.status_code == baseline_status and abs(length - baseline_length) < 5:
            return
        key = (host, response.status_code, length)
        if key in found_set:
            return
        found_set.add(key)
        found.append(host)
        output_callback(f"VHOST hit: {host} [{response.status_code}] size={length}")

    output_callback(f"Vhost scan: {len(words)} hostnames against {base_url}")
    batch_size = concurrency
    for index in range(0, len(words), batch_size):
        if not running():
            break
        batch = words[index : index + batch_size]
        await asyncio.gather(*[check_word(word) for word in batch], return_exceptions=True)
    return found
