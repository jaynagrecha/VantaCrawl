"""Extra discovery: Wayback, Common Crawl, subdomains, OpenAPI, RSS, JS routes."""

from __future__ import annotations

import asyncio
import json
import re
from typing import Callable, List, Optional, Set
from urllib.parse import urljoin, urlparse

import httpx

JS_ROUTE_RE = re.compile(
    r"""['"](/[a-zA-Z0-9_\-./?=&\[\]{}:<>]{2,160})['"]""",
)
OPENAPI_PATH_RE = re.compile(r"(?i)(swagger\.json|openapi\.json|api-docs|/v[0-9]+/api-docs)")
RSS_LINK_RE = re.compile(r"(?i)<link[^>]+type=[\"']application/(rss|atom)\+xml[\"'][^>]+href=[\"']([^\"']+)")


async def fetch_wayback_urls(domain: str, limit: int = 200) -> List[str]:
    urls = []
    api = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey&limit={limit}"
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(api)
            if response.status_code != 200:
                return urls
            data = response.json()
            for row in data[1:]:
                if row:
                    urls.append(row[0])
    except Exception:
        pass
    return urls


async def fetch_common_crawl_urls(domain: str, limit: int = 200) -> List[str]:
    urls = []
    index = "https://index.commoncrawl.org/collinfo.json"
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            colls = await client.get(index)
            if colls.status_code != 200:
                return urls
            latest = colls.json()[0]["id"]
            query = f"https://index.commoncrawl.org/{latest}-index?url={domain}/*&output=json&limit={limit}"
            response = await client.get(query)
            if response.status_code != 200:
                return urls
            for line in response.text.splitlines():
                try:
                    row = json.loads(line)
                    urls.append(row.get("url", ""))
                except json.JSONDecodeError:
                    continue
    except Exception:
        pass
    return [u for u in urls if u]


async def enumerate_subdomains(
    domain: str,
    wordlist_path: str,
    client,
    exists_checker,
    output_callback,
    limit: int = 500,
    *,
    concurrency: int = 20,
    running: Optional[Callable[[], bool]] = None,
    update_progress=None,
    stats=None,
    probe_timeout: float = 8.0,
) -> List[str]:
    """Probe common subdomains concurrently with live progress (no silent stalls)."""
    found: List[str] = []
    try:
        with open(wordlist_path, encoding="utf-8", errors="ignore") as handle:
            words = [line.strip() for line in handle if line.strip() and not line.startswith("#")]
    except OSError:
        output_callback(f"Subdomain wordlist not found: {wordlist_path}")
        return found

    targets = words[: max(0, int(limit) or 0)]
    total = len(targets)
    if total <= 0:
        return found

    workers = max(1, min(int(concurrency) or 1, 40))
    output_callback(f"Subdomain enum: {total:,} host(s) · {workers} threads")
    if stats is not None and hasattr(stats, "note_subdomain_progress"):
        stats.note_subdomain_progress(0, total=total, host="")
    if update_progress:
        update_progress(total, 0, f"Subdomain enum 0/{total}")

    sem = asyncio.Semaphore(workers)
    done = 0
    lock = asyncio.Lock()

    def _publish(done_n: int, host: str = "") -> None:
        hit_n = len(found)
        if stats is not None and hasattr(stats, "note_subdomain_progress"):
            stats.note_subdomain_progress(done_n, total=total, host=host, hits=hit_n)
        if update_progress and (done_n == 0 or done_n == total or done_n % 10 == 0):
            label = f"Subdomain enum {done_n}/{total}"
            if host:
                label = f"{label} · {host}"
            if hit_n:
                label = f"{label} · {hit_n} hit(s)"
            update_progress(total, done_n, label)

    async def probe(word: str) -> None:
        nonlocal done
        if running and not running():
            return
        host = f"{word}.{domain}"
        test_url = f"https://{host}/"
        async with sem:
            if running and not running():
                return
            async with lock:
                if stats is not None and hasattr(stats, "note_subdomain_progress"):
                    stats.note_subdomain_progress(done, total=total, host=host, hits=len(found))
            exists = False
            try:
                exists = bool(
                    await asyncio.wait_for(exists_checker(test_url), timeout=max(1.0, float(probe_timeout)))
                )
            except (asyncio.TimeoutError, httpx.HTTPError, OSError):
                exists = False
            except Exception:
                exists = False
        async with lock:
            done += 1
            if exists:
                found.append(test_url)
                if output_callback:
                    output_callback(f"Subdomain found: {test_url}")
            _publish(done, host)

    await asyncio.gather(*(probe(w) for w in targets))
    if stats is not None and hasattr(stats, "note_subdomain_progress"):
        stats.note_subdomain_progress(total, total=total, host="", hits=len(found))
    if update_progress:
        update_progress(total, total, f"Subdomain enum {total}/{total}")
    output_callback(f"Subdomain enum done: {len(found)} live host(s) of {total:,} probed")
    return found


def extract_js_routes(js_text: str, base_url: str) -> Set[str]:
    """Extract crawlable routes from JS without resolving relatives against chunk dirs.

    Literal placeholders become inventory-only templates (not returned for enqueue).
    Absolute and root-relative paths are resolved against the page/script origin.
    """
    urls: Set[str] = set()
    if not js_text:
        return urls
    from crawl_url_policy import (
        classify_js_candidate,
        js_candidate_enqueue_url,
        origin_of,
        path_has_route_placeholder,
    )

    origin = origin_of(base_url)
    for match in JS_ROUTE_RE.findall(js_text):
        if path_has_route_placeholder(match):
            # Inventory as template via side channel when stats available — skip enqueue set
            continue
        enq = js_candidate_enqueue_url(match, base_url, origin)
        if enq and is_plausible_route(enq):
            urls.add(enq)
            continue
        kind, payload = classify_js_candidate(match, base_url, origin)
        if kind == "root_relative_url" and payload and is_plausible_route(payload):
            urls.add(payload)
    return urls


def extract_js_route_templates(js_text: str) -> Set[str]:
    """Return normalized route templates (``{param}``) found as literal placeholders."""
    from crawl_url_policy import normalize_route_template, path_has_route_placeholder

    out: Set[str] = set()
    if not js_text:
        return out
    for match in JS_ROUTE_RE.findall(js_text):
        if path_has_route_placeholder(match):
            out.add(normalize_route_template(match if match.startswith("/") else f"/{match}"))
    return out


def is_plausible_route(url: str) -> bool:
    if "${" in url or " " in url:
        return False
    from crawl_url_policy import path_has_route_placeholder

    path = urlparse(url).path
    if path_has_route_placeholder(path):
        return False
    return 1 < len(path) < 200


def extract_rss_feeds(html: str, base_url: str) -> Set[str]:
    feeds = set()
    if not html:
        return feeds
    for _, href in RSS_LINK_RE.findall(html):
        feeds.add(urljoin(base_url, href))
    return feeds


def extract_openapi_urls(html: str, base_url: str, content_type: str = "") -> Set[str]:
    urls = set()
    if "openapi" in content_type.lower() or "json" in content_type.lower():
        if '"openapi"' in html or '"swagger"' in html:
            urls.add(base_url)
    for match in OPENAPI_PATH_RE.findall(html or ""):
        urls.add(urljoin(base_url, match))
    return urls


def parse_openapi_endpoints(spec_text: str, base_url: str) -> Set[str]:
    endpoints = set()
    try:
        spec = json.loads(spec_text)
    except json.JSONDecodeError:
        return endpoints
    base = spec.get("servers", [{}])[0].get("url", "") if spec.get("servers") else ""
    paths = spec.get("paths", {})
    for path in paths:
        full = urljoin(base or base_url, path.lstrip("/"))
        if not full.startswith("http"):
            full = urljoin(base_url, path)
        endpoints.add(full)
    return endpoints
