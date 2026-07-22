"""Discover and parse OpenAPI / Swagger / well-known API docs."""

from __future__ import annotations

import json
from typing import Iterable, List, Set, Tuple
from urllib.parse import urljoin, urlparse

import httpx

from discovery_extra import parse_openapi_endpoints
from async_runtime import is_running
from .models import ApiEndpoint

WELL_KNOWN_DOC_PATHS = (
    "/openapi.json",
    "/openapi.yaml",
    "/swagger",
    "/swagger/",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/swagger-ui",
    "/swagger-ui/",
    "/swagger-ui/index.html",
    "/swagger-ui/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/api/swagger.json",
    "/api/openapi.json",
    "/docs/openapi.json",
    "/swagger-resources",
    "/graphql",
    "/api/graphql",
    "/graphiql",
    "/.well-known/openid-configuration",
)


def _origin(start_url: str) -> str:
    p = urlparse(start_url)
    return f"{p.scheme}://{p.netloc}"


async def discover_doc_urls(
    client: httpx.AsyncClient,
    start_url: str,
    *,
    headers: dict,
    extra_candidates: Iterable[str] | None = None,
    running=None,
) -> Tuple[List[str], List[ApiEndpoint]]:
    origin = _origin(start_url)
    candidates: List[str] = [urljoin(origin + "/", path.lstrip("/")) for path in WELL_KNOWN_DOC_PATHS]
    for url in extra_candidates or []:
        if url:
            candidates.append(url)

    docs: List[str] = []
    endpoints: List[ApiEndpoint] = []
    seen: Set[str] = set()
    for url in candidates:
        if running and not await is_running(running):
            break
        if url in seen:
            continue
        seen.add(url)
        try:
            resp = await client.get(url, headers=headers, timeout=12, follow_redirects=True)
        except httpx.HTTPError:
            continue
        ctype = (resp.headers.get("content-type") or "").lower()
        body = (resp.content or b"").decode("utf-8", errors="replace")
        if resp.status_code >= 400:
            continue
        low = body[:4000].lower()
        is_doc = (
            "openapi" in low
            or "swagger" in low
            or (
                "paths" in low
                and ("openapi" in ctype or "json" in ctype or url.endswith((".json", ".yaml", ".yml")))
            )
            or ("graphql" in url.lower() and resp.status_code < 500)
        )
        if not is_doc and "json" not in ctype and "yaml" not in ctype:
            # Still keep GraphQL-looking 200s
            if "graphql" not in url.lower():
                continue
        docs.append(str(resp.url))
        if "graphql" in url.lower():
            endpoints.append(
                ApiEndpoint(
                    method="POST",
                    url=str(resp.url),
                    path=urlparse(str(resp.url)).path or "/graphql",
                    source="docs",
                    status=resp.status_code,
                    content_type=ctype,
                    note="GraphQL endpoint candidate",
                )
            )
            continue
        for ep_url in parse_openapi_endpoints(body, str(resp.url)):
            parsed = urlparse(ep_url)
            endpoints.append(
                ApiEndpoint(
                    method="GET",
                    url=ep_url,
                    path=parsed.path or "/",
                    source="openapi",
                    status=0,
                    note="From OpenAPI/Swagger doc",
                )
            )
        # Also parse methods when available
        try:
            spec = json.loads(body)
            paths = spec.get("paths") or {}
            for path, ops in paths.items():
                if not isinstance(ops, dict):
                    continue
                for method in ops:
                    if method.lower() in ("get", "post", "put", "patch", "delete", "options", "head"):
                        full = urljoin(str(resp.url), path.lstrip("/"))
                        if not full.startswith("http"):
                            full = urljoin(origin + "/", path.lstrip("/"))
                        endpoints.append(
                            ApiEndpoint(
                                method=method.upper(),
                                url=full,
                                path=path if path.startswith("/") else "/" + path,
                                source="openapi",
                                note="OpenAPI operation",
                            )
                        )
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
    return docs, endpoints
