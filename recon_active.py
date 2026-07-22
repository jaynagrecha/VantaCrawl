"""Capped active recon: sitemap, TLS SAN, well-known (excludes security.txt / robots)."""

from __future__ import annotations

import asyncio
import re
import socket
import ssl
from typing import Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from async_runtime import is_running
from recon_extract import parse_sitemap_locs

# Fixed ≤6 probes; security.txt intentionally omitted (user policy)
WELL_KNOWN_PATHS = (
    "/.well-known/change-password",
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
    "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
    "/.well-known/webfinger",
)

HTMLISH_RE = re.compile(r"(?i)<!doctype\s+html|<html[\s>]|<head[\s>]")
JSONISH_RE = re.compile(r"(?i)^\s*[\{\[]")


def extract_tls_sans(host: str, port: int = 443, timeout: float = 5.0) -> List[str]:
    """One TLS handshake per host; return DNS SANs + CN."""
    host = (host or "").split(":")[0].strip()
    if not host or host.replace(".", "").isdigit():
        # Skip raw IPs for SNI simplicity unless needed
        pass
    if not host:
        return []
    names: List[str] = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except Exception:
        return []
    if not cert:
        return []
    for typ, value in cert.get("subjectAltName") or []:
        if typ.lower() == "dns" and value:
            names.append(value.lower().lstrip("*.").lstrip("*"))
            # Keep wildcard form too for inventory
            if value.startswith("*."):
                names.append(value.lower())
    for part in cert.get("subject") or ():
        for key, value in part:
            if key == "commonName" and value:
                names.append(str(value).lower())
    # Dedupe preserve order
    seen: Set[str] = set()
    out: List[str] = []
    for name in names:
        if name and name not in seen:
            seen.add(name)
            out.append(name)
    return out[:40]


def well_known_is_real(status: int, body: bytes | str, content_type: str = "") -> Optional[str]:
    """Evidence gate for well-known responses."""
    if status in (404, 410) or status >= 500:
        return None
    text = body.decode("utf-8", errors="replace") if isinstance(body, (bytes, bytearray)) else (body or "")
    ct = (content_type or "").lower()
    if HTMLISH_RE.search(text[:1500]) and "json" not in ct and "jose" not in ct:
        # Soft HTML error page
        if status == 200 and len(text) > 200:
            return None
        if status in (401, 403) and HTMLISH_RE.search(text[:800]):
            return None
    if status in (401, 403) and not HTMLISH_RE.search(text[:800]):
        return f"HTTP {status} non-HTML (endpoint likely real)"
    if "json" in ct or JSONISH_RE.search(text[:200]):
        if re.search(
            r'(?i)("issuer"|"authorization_endpoint"|"token_endpoint"|"jwks_uri"|'
            r'"appLinks"|"relation"|"webcredentials"|"subject"|"links")',
            text[:8000],
        ):
            return "Confirmed well-known JSON structure"
        if status == 200 and len(text.strip()) > 20 and not HTMLISH_RE.search(text[:800]):
            return "Non-HTML JSON-like well-known body"
    if status == 200 and "text/html" not in ct and text.strip() and not HTMLISH_RE.search(text[:800]):
        return f"Non-HTML HTTP 200 ({len(text)} bytes)"
    # change-password often redirects to login
    if status in (301, 302, 303, 307, 308):
        return f"HTTP {status} redirect (endpoint present)"
    return None


async def probe_well_known(
    client,
    origin: str,
    *,
    running: Optional[Callable[[], bool]] = None,
) -> List[Dict[str, str]]:
    """≤6 GETs; only keep evidence-gated hits."""
    origin = origin.rstrip("/") + "/"
    hits: List[Dict[str, str]] = []
    for path in WELL_KNOWN_PATHS:
        if running and not await is_running(running):
            break
        url = urljoin(origin, path.lstrip("/"))
        # urljoin with origin ending / and path starting / needs care
        url = origin.rstrip("/") + path
        try:
            response = await client.get(url, timeout=8, follow_redirects=False)
        except Exception:
            continue
        body = response.content or b""
        proof = well_known_is_real(
            response.status_code, body, response.headers.get("content-type", "")
        )
        if not proof:
            continue
        location = response.headers.get("location", "")
        hits.append(
            {
                "url": url,
                "status": str(response.status_code),
                "evidence": proof,
                "location": location[:200],
            }
        )
    return hits


async def fetch_sitemaps(
    client,
    origin: str,
    *,
    running: Optional[Callable[[], bool]] = None,
    max_child_sitemaps: int = 3,
    max_urls: int = 500,
) -> Tuple[List[str], List[str]]:
    """
    1–2 root GETs + up to max_child_sitemaps child GETs.
    Returns (sitemap_doc_urls_fetched, discovered_page_urls).
    """
    origin = origin.rstrip("/")
    roots = [f"{origin}/sitemap.xml", f"{origin}/sitemap_index.xml"]
    fetched_docs: List[str] = []
    pages: List[str] = []
    children_to_fetch: List[str] = []
    seen_pages: Set[str] = set()

    async def _get(url: str) -> Optional[str]:
        try:
            response = await client.get(url, timeout=12, follow_redirects=True)
        except Exception:
            return None
        if response.status_code >= 400:
            return None
        text = response.text or ""
        if not re.search(r"(?i)<(urlset|sitemapindex)\b", text[:3000]):
            return None
        return text

    for root in roots:
        if running and not await is_running(running):
            break
        text = await _get(root)
        if not text:
            continue
        fetched_docs.append(root)
        page_urls, child_urls = parse_sitemap_locs(text)
        for u in page_urls:
            if u not in seen_pages and len(pages) < max_urls:
                seen_pages.add(u)
                pages.append(u)
        for u in child_urls:
            if u not in children_to_fetch and u not in fetched_docs:
                children_to_fetch.append(u)
        # Prefer sitemap_index when both exist — still OK to stop after first solid hit
        if page_urls or child_urls:
            break

    for child in children_to_fetch[:max_child_sitemaps]:
        if running and not await is_running(running):
            break
        text = await _get(child)
        if not text:
            continue
        fetched_docs.append(child)
        page_urls, _more = parse_sitemap_locs(text)
        for u in page_urls:
            if u not in seen_pages and len(pages) < max_urls:
                seen_pages.add(u)
                pages.append(u)

    return fetched_docs, pages


async def run_host_recon_once(
    client,
    start_url: str,
    *,
    running: Optional[Callable[[], bool]] = None,
    do_tls: bool = True,
    do_sitemap: bool = True,
    do_well_known: bool = True,
) -> Dict[str, object]:
    """Bundle once-per-host active recon. Safe to call under a host-seen lock."""
    parsed = urlparse(start_url)
    host = parsed.netloc.split(":")[0]
    scheme = parsed.scheme or "https"
    origin = f"{scheme}://{parsed.netloc}"
    result: Dict[str, object] = {
        "tls_sans": [],
        "sitemap_docs": [],
        "sitemap_urls": [],
        "well_known": [],
    }
    tasks = []

    if do_tls and scheme == "https":
        port = int(parsed.port or 443)

        def _tls():
            return extract_tls_sans(host, port=port)

        tasks.append(("tls", asyncio.to_thread(_tls)))

    async def _empty():
        return []

    if do_sitemap:
        tasks.append(("sitemap", fetch_sitemaps(client, origin, running=running)))
    if do_well_known:
        tasks.append(("well_known", probe_well_known(client, origin, running=running)))

    for name, coro in tasks:
        if running and not await is_running(running):
            break
        try:
            value = await coro
        except Exception:
            continue
        if name == "tls":
            result["tls_sans"] = value or []
        elif name == "sitemap":
            docs, urls = value
            result["sitemap_docs"] = docs
            result["sitemap_urls"] = urls
        elif name == "well_known":
            result["well_known"] = value or []
    return result
