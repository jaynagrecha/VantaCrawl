"""Orchestrate full API recon: passive → docs → import → active → GraphQL."""

from __future__ import annotations

import os
from typing import Callable, Iterable, List, Optional, Set
from urllib.parse import urlparse

import httpx

from .active import run_active_api_enum
from .auth import build_api_headers
from .docs import discover_doc_urls
from .graphql import try_introspection
from .imports import load_har_file, load_postman_collection
from .models import ApiEndpoint, ApiReconResult
from .passive import classify_discovered_urls, extract_from_text

_DEFAULT_WORDLIST = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "Wordlist",
    "api-common.txt",
)


async def run_api_recon(
    config,
    client: httpx.AsyncClient,
    *,
    stats,
    seed_urls: Iterable[str],
    output_callback: Callable[[str], None],
    running: Callable[[], bool],
    update_progress=None,
) -> ApiReconResult:
    result = ApiReconResult()
    if not getattr(config, "api_recon", False):
        return result

    output_callback("\n=== API recon ===")
    if update_progress:
        update_progress(1, 0, "API recon: collecting surface…")

    headers = build_api_headers(
        header_name=getattr(config, "api_auth_header_name", "Authorization") or "Authorization",
        header_value=getattr(config, "api_auth_header_value", "") or "",
        base_headers=dict(getattr(config, "custom_headers", None) or {}),
    )

    seeds: List[str] = list(seed_urls or [])
    for attr in (
        "discovered_urls",
        "js_route_urls",
        "openapi_endpoints",
        "openapi_doc_urls",
        "enum_hit_urls",
    ):
        val = getattr(stats, attr, None)
        if isinstance(val, (list, set)):
            seeds.extend(list(val))

    # Passive from URL inventory
    for ep in classify_discovered_urls(seeds, source="crawl"):
        result.endpoints.append(ep)
    output_callback(f"API passive: {len(result.endpoints)} candidate(s) from crawl inventory")

    # Sample JS/HTML bodies for path mining (capped)
    js_like = [
        u
        for u in seeds
        if any(x in (urlparse(u).path or "").lower() for x in (".js", "/api", "graphql", "swagger", "openapi"))
    ][:40]
    mined = 0
    for url in js_like:
        if not running():
            break
        try:
            resp = await client.get(url, headers=headers, timeout=12, follow_redirects=True)
            body = (resp.content or b"").decode("utf-8", errors="replace")
        except httpx.HTTPError:
            continue
        for ep in extract_from_text(body, str(resp.url), source="js"):
            result.endpoints.append(ep)
            mined += 1
    if mined:
        output_callback(f"API passive: mined {mined} path hint(s) from JS/HTML samples")

    # Docs / well-known
    if running():
        if update_progress:
            update_progress(1, 0, "API recon: OpenAPI / well-known docs…")
        docs, doc_eps = await discover_doc_urls(
            client,
            config.start_url,
            headers=headers,
            extra_candidates=list(getattr(stats, "openapi_doc_urls", []) or []),
            running=running,
        )
        result.docs.extend(docs)
        result.endpoints.extend(doc_eps)
        for d in docs:
            stats.record_url("openapi_doc", d)
        output_callback(f"API docs: {len(docs)} document(s), {len(doc_eps)} operation(s)")

    # Imports
    postman = (getattr(config, "api_postman_file", "") or "").strip()
    har = (getattr(config, "api_har_file", "") or "").strip()
    if postman:
        imported = load_postman_collection(postman)
        result.endpoints.extend(imported)
        output_callback(f"API import (Postman): {len(imported)} request(s)")
    if har:
        imported = load_har_file(har)
        result.endpoints.extend(imported)
        output_callback(f"API import (HAR): {len(imported)} request(s)")

    # Active enum (optional)
    if getattr(config, "api_recon_active", False) and running():
        wl = (getattr(config, "api_recon_wordlist", "") or "").strip() or _DEFAULT_WORDLIST
        limit = int(getattr(config, "api_recon_word_limit", 3000) or 3000)
        active_hits = await run_active_api_enum(
            client,
            config.start_url,
            wordlist_file=wl,
            word_limit=limit,
            headers=headers,
            concurrency=min(int(getattr(config, "enum_concurrency", 20) or 20), 40),
            method=str(getattr(config, "api_recon_method", "HEAD") or "HEAD"),
            running=running,
            output_callback=output_callback,
            update_progress=update_progress,
            follow_redirects=bool(getattr(config, "enum_follow_redirects", True)),
            max_redirect_hops=int(getattr(config, "enum_redirect_max_hops", 5) or 5),
            stats=stats,
        )
        result.probed = limit
        result.hits = len(active_hits)
        result.endpoints.extend(active_hits)
        output_callback(f"API active: {len(active_hits)} live/protected path(s)")

    # GraphQL introspection (optional)
    if getattr(config, "api_recon_graphql", False) and running():
        gql_urls: Set[str] = set()
        for ep in result.endpoints:
            if "graphql" in (ep.path or "").lower() or "graphql" in (ep.url or "").lower():
                gql_urls.add(ep.url)
        origin = f"{urlparse(config.start_url).scheme}://{urlparse(config.start_url).netloc}"
        for path in ("/graphql", "/api/graphql", "/v1/graphql"):
            gql_urls.add(origin + path)
        for url in list(gql_urls)[:8]:
            if not running():
                break
            ops, eps = await try_introspection(client, url, headers=headers)
            result.endpoints.extend(eps)
            result.graphql_operations.extend(ops)
            if ops:
                output_callback(f"GraphQL introspection OK at {url} · {len(ops)} field(s)")
                break

    result.dedupe_endpoints()

    # Persist onto stats
    stats.api_endpoints = [ep.as_dict() for ep in result.endpoints[:2000]]
    stats.api_docs = list(result.docs)[:200]
    stats.api_graphql_operations = list(result.graphql_operations)[:500]
    for ep in result.endpoints:
        if ep.source in ("openapi", "docs"):
            stats.record_url("openapi_endpoint", ep.url)
        stats.record_url("api_endpoint", ep.url)

    output_callback(
        f"API recon done: {len(result.endpoints)} unique endpoint(s) · "
        f"{len(result.docs)} doc(s) · {len(result.graphql_operations)} GraphQL field(s)"
    )
    if update_progress:
        update_progress(max(len(result.endpoints), 1), max(len(result.endpoints), 1), "API recon complete")
    return result
