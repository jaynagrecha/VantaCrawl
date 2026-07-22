"""Crawl URL policy: scheme gates, query-variant caps, static assets, form keys.

Addresses mapper quality issues (query explosion, non-HTTP curl targets,
malformed % encoding, static-as-page, form dedupe) without inventing findings.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, Iterable, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlsplit, urlunsplit

INVALID_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")

NON_HTTP_SCHEMES = frozenset(
    {
        "javascript",
        "mailto",
        "tel",
        "data",
        "blob",
        "about",
        "file",
        "ws",
        "wss",
        "ftp",
        "intent",
        "chrome",
        "chrome-extension",
    }
)

# Drop from crawl identity (tracking noise)
TRACKING_PARAM_PREFIXES = ("utm_", "af_", "fbclid", "gclid", "msclkid", "mc_")
TRACKING_PARAM_NAMES = frozenset(
    {
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_term",
        "utm_content",
        "fbclid",
        "gclid",
        "msclkid",
        "mc_cid",
        "mc_eid",
        "source_caller",
        "_ga",
        "_gl",
        "ref",
        "ref_src",
        "ref_url",
    }
)

# Functional amount/id params — keep at most N representative values
FUNCTIONAL_PARAM_NAMES = frozenset(
    {
        "sendamount",
        "amount",
        "qty",
        "quantity",
        "price",
        "id",
        "uid",
        "userid",
        "page",
        "p",
        "offset",
        "limit",
        "pid",
        "sku",
    }
)

STATIC_EXT_RE = re.compile(
    r"\.(?:css|js|mjs|map|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|eot|otf|"
    r"mp4|webm|mp3|wav|pdf|zip|gz|tgz|rar|7z|dmg|exe|apk|"
    r"json|xml|txt|csv|htc)(?:$|\?)",
    re.I,
)

STATIC_PATH_MARKERS = (
    "/staticassets/",
    "/static/",
    "/assets/",
    "/_next/static/",
    "/page-data/",
    "/blogs-staticassets/",
    "/fonts/",
    "/media/",
    "/dist/",
    "/build/",
    "/css/",
    "/js/",
    "/images/",
    "/img/",
)


def has_invalid_percent_encoding(url: str) -> bool:
    return bool(INVALID_PERCENT_RE.search(url or ""))


def resolve_http_target(raw_url: str, base_url: str = "") -> Optional[str]:
    """Return an absolute http(s) URL or None (never pass non-HTTP to curl)."""
    raw = (raw_url or "").strip().strip("'\"")
    if not raw or raw.startswith("#"):
        return None
    low = raw.lower()
    for scheme in NON_HTTP_SCHEMES:
        if low.startswith(scheme + ":"):
            return None
    if low in ("javascript:void(0)", "javascript:void(0);", "javascript:;", "javascript:"):
        return None
    try:
        if raw.startswith("//") and base_url:
            parsed_base = urlparse(base_url)
            raw = f"{parsed_base.scheme or 'https'}:{raw}"
        resolved = raw if raw.startswith(("http://", "https://")) else urljoin(base_url or "", raw)
        parsed = urlsplit(resolved)
    except Exception:
        return None
    if parsed.scheme.lower() not in ("http", "https"):
        return None
    if not parsed.hostname:
        return None
    if has_invalid_percent_encoding(resolved):
        return None
    return resolved


def strip_tracking_params(url: str) -> str:
    try:
        parts = urlsplit(url)
        kept = []
        for name, value in parse_qsl(parts.query, keep_blank_values=True):
            low = (name or "").lower()
            if low in TRACKING_PARAM_NAMES:
                continue
            if any(low.startswith(p) for p in TRACKING_PARAM_PREFIXES):
                continue
            kept.append((name, value))
        query = urlencode(kept, doseq=True)
        return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", query, ""))
    except Exception:
        return url


def endpoint_identity(url: str) -> str:
    """GET + origin + path + sorted parameter *names* (not values)."""
    try:
        parts = urlsplit(url)
        names = sorted({(n or "").lower() for n, _v in parse_qsl(parts.query, keep_blank_values=True)})
        path = parts.path or "/"
        host = (parts.netloc or "").lower()
        return f"GET|{host}|{path}|{'&'.join(names)}"
    except Exception:
        return f"GET|{url}"


def resource_identity(url: str) -> str:
    """Full canonical URL without fragment (resource identity)."""
    try:
        parts = urlsplit(url)
        return urlunsplit((parts.scheme, parts.netloc.lower(), parts.path or "/", parts.query, ""))
    except Exception:
        return url


def is_static_asset_url(url: str) -> bool:
    """True for CSS/JS/images/fonts/page-data — recordable but not HTML crawl targets."""
    if not url:
        return False
    try:
        path = (urlsplit(url).path or "").lower()
    except Exception:
        return False
    if STATIC_EXT_RE.search(path):
        return True
    if any(m in path for m in STATIC_PATH_MARKERS):
        return True
    if path.endswith("/page-data.json") or "/page-data/" in path:
        return True
    return False


def is_html_crawl_candidate(url: str) -> bool:
    """False for static assets that should not expand the BFS frontier as pages."""
    if is_static_asset_url(url):
        # Allow HTML-ish endpoints under /js/ that are really pages? Prefer extension gate.
        path = (urlsplit(url).path or "").lower()
        if path.endswith((".html", ".htm", ".php", ".asp", ".aspx", ".jsp")):
            return True
        return False
    return True


class QueryVariantTracker:
    """Cap query-value explosion per endpoint identity."""

    def __init__(
        self,
        *,
        max_values_per_parameter: int = 2,
        max_query_variants_per_endpoint: int = 3,
    ):
        self.max_values_per_parameter = max(1, int(max_values_per_parameter or 2))
        self.max_query_variants_per_endpoint = max(1, int(max_query_variants_per_endpoint or 3))
        self._endpoint_variants: Dict[str, Set[str]] = {}
        self._param_values: Dict[str, Dict[str, Set[str]]] = {}
        self.skipped_variants = 0

    def allow(self, url: str) -> bool:
        """Return True if this URL's query variant should be enqueued."""
        cleaned = strip_tracking_params(url)
        eid = endpoint_identity(cleaned)
        rid = resource_identity(cleaned)
        variants = self._endpoint_variants.setdefault(eid, set())
        if rid in variants:
            return True  # already counted; caller still dedupes on full URL
        if len(variants) >= self.max_query_variants_per_endpoint:
            # Allow only if no query
            try:
                if not urlsplit(cleaned).query:
                    variants.add(rid)
                    return True
            except Exception:
                pass
            self.skipped_variants += 1
            return False
        # Cap functional param value cardinality
        try:
            parts = urlsplit(cleaned)
            by_param = self._param_values.setdefault(eid, {})
            for name, value in parse_qsl(parts.query, keep_blank_values=True):
                low = (name or "").lower()
                if low not in FUNCTIONAL_PARAM_NAMES and not low.endswith("amount"):
                    continue
                seen_vals = by_param.setdefault(low, set())
                if value in seen_vals:
                    continue
                if len(seen_vals) >= self.max_values_per_parameter:
                    self.skipped_variants += 1
                    return False
                seen_vals.add(value)
        except Exception:
            pass
        variants.add(rid)
        return True


def form_fingerprint(
    *,
    method: str,
    action: str,
    fields: Iterable[Tuple[str, str]] | Iterable[str],
    enctype: str = "",
) -> str:
    """Stable form key — field names/types only (never CSRF token values)."""
    method_u = (method or "GET").upper()
    action_c = resolve_http_target(action, "") or (action or "").split("#", 1)[0]
    pairs: list[str] = []
    for item in fields or []:
        if isinstance(item, (tuple, list)) and len(item) >= 2:
            name, typ = str(item[0]), str(item[1] or "text")
        else:
            name, typ = str(item), "text"
        name = name.strip()
        if not name:
            continue
        # Mark classic CSRF field names as dynamic type slot
        low = name.lower()
        if low in ("csrf", "csrf_token", "csrftoken", "_token", "authenticity_token", "__requestverificationtoken"):
            typ = "csrf"
        pairs.append(f"{name}:{typ.lower()}")
    pairs.sort()
    enc = (enctype or "").strip().lower()
    if enc in ("", "application/x-www-form-urlencoded"):
        enc = ""
    raw = method_u + "|" + action_c + "|" + "|".join(pairs) + "|" + enc
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:32]


def host_in_exact_origin_scope(url: str, start_url: str) -> bool:
    """scheme + hostname + effective port must match start origin."""
    try:
        a = urlsplit(url)
        b = urlsplit(start_url)
        if a.scheme.lower() != b.scheme.lower():
            return False
        return (a.netloc or "").lower() == (b.netloc or "").lower()
    except Exception:
        return False
