"""Mine API-looking routes from HTML/JS and discovered URL sets."""

from __future__ import annotations

import re
from typing import Iterable, List, Set
from urllib.parse import urljoin, urlparse

from .models import ApiEndpoint

_FETCH_RE = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|patch|delete)|\$\.(?:get|post|ajax))\s*\(\s*['"`]([^'"`]+)['"`]""",
    re.IGNORECASE,
)
_PATH_RE = re.compile(
    r"""['"`]((?:/?api|/v\d+|/rest|/graphql|/swagger|/openapi)[^'"`\s]{0,160})['"`]""",
    re.IGNORECASE,
)
_ABS_API_RE = re.compile(
    r"""https?://[^\s"'<>]{0,120}(?:/api(?:/|$)|/v\d+/|/graphql|/rest/)[^\s"'<>]{0,160}""",
    re.IGNORECASE,
)


def _looks_like_api_path(path: str) -> bool:
    p = (path or "").lower()
    if not p.startswith("/"):
        p = "/" + p
    markers = ("/api", "/v1", "/v2", "/v3", "/graphql", "/rest/", "/swagger", "/openapi", "/actuator")
    return any(m in p for m in markers)


def classify_discovered_urls(urls: Iterable[str], *, source: str = "crawl") -> List[ApiEndpoint]:
    out: List[ApiEndpoint] = []
    for url in urls or []:
        try:
            parsed = urlparse(url)
        except Exception:
            continue
        if not parsed.scheme.startswith("http"):
            continue
        if not _looks_like_api_path(parsed.path or "/"):
            continue
        out.append(
            ApiEndpoint(
                method="GET",
                url=url.split("#", 1)[0],
                path=parsed.path or "/",
                source=source,
            )
        )
    return out


def extract_from_text(text: str, base_url: str, *, source: str = "js") -> List[ApiEndpoint]:
    if not text:
        return []
    found: Set[str] = set()
    for match in _FETCH_RE.findall(text):
        found.add(match)
    for match in _PATH_RE.findall(text):
        found.add(match)
    for match in _ABS_API_RE.findall(text):
        found.add(match.rstrip(").,;'\""))

    endpoints: List[ApiEndpoint] = []
    for raw in found:
        raw = raw.strip()
        if not raw or raw.startswith("data:") or len(raw) > 300:
            continue
        if raw.startswith("http://") or raw.startswith("https://"):
            full = raw
        else:
            if not raw.startswith("/"):
                raw = "/" + raw
            if not _looks_like_api_path(raw):
                continue
            full = urljoin(base_url, raw)
        parsed = urlparse(full)
        if not parsed.scheme.startswith("http"):
            continue
        endpoints.append(
            ApiEndpoint(
                method="GET",
                url=full.split("#", 1)[0],
                path=parsed.path or "/",
                source=source,
            )
        )
    return endpoints
