"""S3 and GCS bucket discovery (Gobuster cloud modes)."""

from __future__ import annotations

import asyncio
from typing import Callable, List
from urllib.parse import urlparse

import httpx

from content_validate import classify_bucket_response
from crawler_common import load_wordlist


async def _probe_bucket(
    client: httpx.AsyncClient,
    url: str,
    *,
    provider: str,
) -> tuple[bool, str, int]:
    """HEAD then GET on 403/ambiguous to classify real buckets vs NoSuchBucket."""
    try:
        response = await client.head(url, timeout=8, follow_redirects=True)
    except httpx.HTTPError:
        return False, "request failed", 0
    status = response.status_code
    body = b""
    if status in (200, 204, 301, 302, 307, 308):
        ok, note = classify_bucket_response(status, body, provider=provider)
        return ok, note, status
    if status == 403:
        try:
            get_resp = await client.get(url, timeout=8, follow_redirects=True)
            status = get_resp.status_code
            body = get_resp.content or b""
        except httpx.HTTPError:
            body = b""
        ok, note = classify_bucket_response(status, body, provider=provider)
        return ok, note, status
    return False, f"ignored HTTP {status}", status


async def enumerate_s3_buckets(
    domain: str,
    wordlist_path: str,
    client: httpx.AsyncClient,
    *,
    running: Callable[[], bool],
    output_callback,
    max_names: int = 500,
    concurrency: int = 40,
) -> List[str]:
    root = urlparse(f"https://{domain}").netloc.split(":")[0]
    root = root.replace("www.", "")
    words = load_wordlist(wordlist_path)[:max_names]
    found: List[str] = []
    sem = asyncio.Semaphore(max(1, concurrency))

    async def check_name(name: str):
        if not running():
            return
        bucket = name.strip().lower()
        if not bucket:
            return
        for url in (
            f"https://{bucket}.s3.amazonaws.com/",
            f"https://s3.amazonaws.com/{bucket}/",
        ):
            async with sem:
                ok, note, status = await _probe_bucket(client, url, provider="s3")
            if ok:
                found.append(url)
                output_callback(f"S3 bucket: {url} [{status}] {note}")
                return

    output_callback(f"S3 scan: {len(words)} names for {root}")
    for index in range(0, len(words), concurrency):
        if not running():
            break
        await asyncio.gather(*[check_name(w) for w in words[index : index + concurrency]], return_exceptions=True)
    return found


async def enumerate_gcs_buckets(
    domain: str,
    wordlist_path: str,
    client: httpx.AsyncClient,
    *,
    running: Callable[[], bool],
    output_callback,
    max_names: int = 500,
    concurrency: int = 40,
) -> List[str]:
    words = load_wordlist(wordlist_path)[:max_names]
    found: List[str] = []
    sem = asyncio.Semaphore(max(1, concurrency))

    async def check_name(name: str):
        if not running():
            return
        bucket = name.strip().lower()
        if not bucket:
            return
        url = f"https://storage.googleapis.com/{bucket}/"
        async with sem:
            ok, note, status = await _probe_bucket(client, url, provider="gcs")
        if ok:
            found.append(url)
            output_callback(f"GCS bucket: {url} [{status}] {note}")

    output_callback(f"GCS scan: {len(words)} bucket names")
    for index in range(0, len(words), concurrency):
        if not running():
            break
        await asyncio.gather(*[check_name(w) for w in words[index : index + concurrency]], return_exceptions=True)
    return found
