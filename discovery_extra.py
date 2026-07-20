"""Extra discovery: Wayback, Common Crawl, subdomains, OpenAPI, RSS, JS routes."""

from __future__ import annotations

import json
import re
from typing import List, Set
from urllib.parse import urljoin, urlparse

import httpx

JS_ROUTE_RE = re.compile(
    r"""['"](/[a-zA-Z0-9_\-./?=&]{2,120})['"]""",
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


async def enumerate_subdomains(domain: str, wordlist_path: str, client, exists_checker, output_callback, limit: int = 500) -> List[str]:
    found = []
    try:
        with open(wordlist_path, encoding="utf-8", errors="ignore") as handle:
            words = [line.strip() for line in handle if line.strip() and not line.startswith("#")]
    except OSError:
        output_callback(f"Subdomain wordlist not found: {wordlist_path}")
        return found

    checked = 0
    for word in words:
        if checked >= limit:
            break
        host = f"{word}.{domain}"
        test_url = f"https://{host}/"
        checked += 1
        if await exists_checker(test_url):
            found.append(test_url)
            output_callback(f"Subdomain found: {test_url}")
    return found


def extract_js_routes(js_text: str, base_url: str) -> Set[str]:
    urls = set()
    if not js_text:
        return urls
    for match in JS_ROUTE_RE.findall(js_text):
        if match.startswith("/") and not match.startswith("//"):
            full = urljoin(base_url, match)
            if is_plausible_route(full):
                urls.add(full)
    return urls


def is_plausible_route(url: str) -> bool:
    if "${" in url or " " in url:
        return False
    path = urlparse(url).path
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
