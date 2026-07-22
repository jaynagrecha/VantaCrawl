"""Conservative active API path enumeration (GET/HEAD)."""

from __future__ import annotations

import asyncio
from typing import Callable, List, Optional, Set
from urllib.parse import urljoin, urlparse

import httpx

from async_runtime import is_running
from crawler_common import load_wordlist
from enum_engine import REDIRECT_STATUSES, follow_same_host_redirects
from .models import ApiEndpoint

DEFAULT_BASES = ("/api/", "/api/v1/", "/api/v2/", "/v1/", "/v2/", "/rest/", "/graphql")
# Final statuses that count as API hits after redirect resolution
_HIT_STATUSES = {200, 201, 204, 401, 403}


def _probe_path(url: str) -> str:
    path = urlparse(url).path or "/"
    return path if path.startswith("/") else f"/{path}"


async def run_active_api_enum(
    client: httpx.AsyncClient,
    start_url: str,
    *,
    wordlist_file: str,
    word_limit: int = 3000,
    headers: dict,
    concurrency: int = 20,
    method: str = "GET",
    running: Optional[Callable[[], bool]] = None,
    output_callback: Optional[Callable[[str], None]] = None,
    update_progress=None,
    follow_redirects: bool = True,
    max_redirect_hops: int = 5,
    stats=None,
) -> List[ApiEndpoint]:
    origin = f"{urlparse(start_url).scheme}://{urlparse(start_url).netloc}"
    words = load_wordlist(wordlist_file, max_words=max(1, int(word_limit) or 3000))
    if not words:
        words = [
            "health",
            "status",
            "users",
            "user",
            "login",
            "auth",
            "token",
            "me",
            "config",
            "swagger",
            "openapi",
            "docs",
            "graphql",
            "admin",
            "search",
            "products",
            "orders",
            "v1",
            "v2",
        ]

    targets: List[str] = []
    seen: Set[str] = set()
    for base in DEFAULT_BASES:
        for word in words:
            w = word.strip().lstrip("/")
            if not w:
                continue
            url = urljoin(origin + base, w)
            if url in seen:
                continue
            seen.add(url)
            targets.append(url)
            if word_limit and len(targets) >= word_limit:
                break
        if word_limit and len(targets) >= word_limit:
            break

    total = len(targets)
    if output_callback:
        output_callback(f"API active enum: {total:,} probes · {method} · {concurrency} threads")
    if stats is not None and hasattr(stats, "note_api_recon_progress"):
        stats.note_api_recon_progress(0, total=total, path="", hits=0)
    if update_progress and total:
        update_progress(total, 0, f"API recon 0/{total}")

    sem = asyncio.Semaphore(max(1, int(concurrency) or 1))
    hits: List[ApiEndpoint] = []
    done = 0
    lock = asyncio.Lock()
    verb = (method or "HEAD").upper()
    if verb not in ("GET", "HEAD"):
        verb = "HEAD"

    def _publish(done_n: int, path: str = "") -> None:
        hit_n = len(hits)
        if stats is not None and hasattr(stats, "note_api_recon_progress"):
            stats.note_api_recon_progress(done_n, total=total, path=path, hits=hit_n)
        # Every probe into stats; UI publish every 5 so progress % moves without spam
        if update_progress and total and (done_n == 0 or done_n == total or done_n % 5 == 0):
            label = f"API recon {done_n}/{total}"
            if path:
                label = f"{label} · {path}"
            if hit_n:
                label = f"{label} · {hit_n} hit(s)"
            update_progress(total, done_n, label)

    async def probe(url: str) -> None:
        nonlocal done
        if running and not await is_running(running):
            return
        status = 0
        final_url = url
        hops = 0
        ctype = ""
        path = _probe_path(url)
        async with sem:
            if running and not running():
                return
            # Show the path while this worker is in-flight (including WAF backoff sleep)
            async with lock:
                if stats is not None and hasattr(stats, "note_api_recon_progress"):
                    stats.note_api_recon_progress(done, total=total, path=path, hits=len(hits))
            try:
                if verb == "GET":
                    resp = await client.get(url, headers=headers, timeout=10, follow_redirects=False)
                else:
                    resp = await client.head(url, headers=headers, timeout=10, follow_redirects=False)
                    if resp.status_code in (405, 501) or (
                        follow_redirects and resp.status_code in REDIRECT_STATUSES
                    ):
                        resp = await client.get(url, headers=headers, timeout=10, follow_redirects=False)
                status = resp.status_code
                ctype = (resp.headers.get("content-type") or "")[:80]
                if follow_redirects and status in REDIRECT_STATUSES:
                    status, _length, _hash, _body, final_url, hops = await follow_same_host_redirects(
                        client,
                        url,
                        max_hops=max_redirect_hops,
                        timeout=10,
                    )
                    ctype = ctype  # best-effort; final GET body not re-typed here
            except httpx.HTTPError:
                async with lock:
                    done += 1
                    _publish(done, path)
                return
        async with lock:
            done += 1
            if status in _HIT_STATUSES:
                note = "Protected API path" if status in (401, 403) else ""
                if hops:
                    note = (note + "; " if note else "") + f"via {hops} redirect hop(s) → {final_url}"
                hits.append(
                    ApiEndpoint(
                        method=verb,
                        url=url,
                        path=urlparse(url).path or "/",
                        source="active",
                        status=status,
                        content_type=ctype,
                        note=note,
                    )
                )
            _publish(done, path)

    await asyncio.gather(*(probe(u) for u in targets))
    if stats is not None and hasattr(stats, "note_api_recon_progress"):
        stats.note_api_recon_progress(total, total=total, path="", hits=len(hits))
    if update_progress and total:
        update_progress(total, total, f"API recon {total}/{total}")
    return hits
