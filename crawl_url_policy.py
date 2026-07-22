"""Crawl URL policy: scheme gates, query-variant caps, static assets, form keys.

Design rule (non-negotiable):
  Efficiency fine-tunes *how much we enqueue*, never *what we can find*.
  Caps must not erase attack surface — inventory skipped query values, still
  fetch JS/JSON for extractors, and keep security modules wired to the same
  endpoints. Capabilities must not be lost; only redundant crawl work is cut.

Addresses mapper quality issues (query explosion, non-HTTP curl targets,
malformed % encoding, static-as-page, form dedupe) without inventing findings.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
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

# Functional amount/id params — keep at most N representative values *in the queue*
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

# Still fetched for extractors / secret scan (not treated as dead weight)
ANALYSIS_EXT_RE = re.compile(r"\.(?:js|mjs|cjs|json|map|xml)(?:$|\?)", re.I)

STATIC_EXT_RE = re.compile(
    r"\.(?:css|js|mjs|map|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|eot|otf|"
    r"mp4|webm|mp3|wav|pdf|zip|gz|tgz|rar|7z|dmg|exe|apk|"
    r"json|xml|txt|csv|htc)(?:$|\?)",
    re.I,
)

# Binary / style / media — inventory + mirror only; do not BFS as pages
NON_ANALYSIS_STATIC_EXT_RE = re.compile(
    r"\.(?:css|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|eot|otf|"
    r"mp4|webm|mp3|wav|pdf|zip|gz|tgz|rar|7z|dmg|exe|apk|txt|csv|htc)(?:$|\?)",
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


def is_page_data_json_url(url: str) -> bool:
    """Gatsby/Next page-data JSON — inventory / extract later; never browser HTML queue."""
    try:
        path = (urlsplit(url).path or "").lower()
    except Exception:
        return False
    return "/page-data/" in path and path.endswith(".json")


def is_analysis_asset_url(url: str) -> bool:
    """JS/JSON/XML/sourcemap — still fetched for route/secret extractors.

    Exception: page-data.json is inventoried but not enqueued as a crawl page
    (floods the frontier on locale/destination sites without adding HTML surface).
    """
    if not url or is_page_data_json_url(url):
        return False
    try:
        path = (urlsplit(url).path or "").lower()
    except Exception:
        return False
    if ANALYSIS_EXT_RE.search(path):
        return True
    return False


def is_static_asset_url(url: str) -> bool:
    """True for CSS/JS/images/fonts/page-data — recordable static-like URLs."""
    if not url:
        return False
    try:
        path = (urlsplit(url).path or "").lower()
    except Exception:
        return False
    if is_page_data_json_url(url):
        return True
    if STATIC_EXT_RE.search(path):
        return True
    if any(m in path for m in STATIC_PATH_MARKERS):
        return True
    if path.endswith("/page-data.json") or "/page-data/" in path:
        return True
    return False


def is_non_analysis_static_url(url: str) -> bool:
    """Images/fonts/CSS/media/page-data — inventory/mirror only; do not enqueue as crawl pages."""
    if is_page_data_json_url(url):
        return True
    if not url or is_analysis_asset_url(url):
        return False
    try:
        path = (urlsplit(url).path or "").lower()
    except Exception:
        return False
    if NON_ANALYSIS_STATIC_EXT_RE.search(path):
        return True
    # Path markers that are clearly style/media trees (not /js/ — may hold app chunks)
    style_markers = (
        "/staticassets/css/",
        "/fonts/",
        "/images/",
        "/img/",
        "/media/",
        "/blogs-staticassets/",
    )
    if any(m in path for m in style_markers):
        return True
    if "/css/" in path and not path.endswith((".html", ".htm", ".php", ".asp", ".aspx", ".jsp")):
        return True
    return False


def is_html_crawl_candidate(url: str) -> bool:
    """False only for assets that should not enter the fetch queue at all.

    Analysis assets (JS/XML, non-page-data JSON) remain True so extractors keep full power.
    """
    if is_page_data_json_url(url):
        return False
    if is_analysis_asset_url(url):
        return True
    if is_non_analysis_static_url(url):
        path = (urlsplit(url).path or "").lower()
        if path.endswith((".html", ".htm", ".php", ".asp", ".aspx", ".jsp")):
            return True
        return False
    if is_static_asset_url(url):
        path = (urlsplit(url).path or "").lower()
        if path.endswith((".html", ".htm", ".php", ".asp", ".aspx", ".jsp")):
            return True
        if NON_ANALYSIS_STATIC_EXT_RE.search(path):
            return False
        # Keep /js/ chunks without extension enqueueable when analysis might apply
        if "/js/" in path or "/_next/static/" in path:
            return True
        return False
    return True


def discovery_kind(url: str) -> str:
    """Label for structured discovery logs (not a security finding)."""
    try:
        path = (urlsplit(url).path or "").lower()
    except Exception:
        path = ""
    if is_page_data_json_url(url) or path.endswith(".json"):
        return "JSON_RESOURCE"
    if path.endswith((".js", ".mjs", ".cjs", ".map")):
        return "SCRIPT_REFERENCE"
    if "sitemap" in path and path.endswith((".xml", ".gz")):
        return "SITEMAP"
    if path.endswith((".xml",)):
        return "XML_RESOURCE"
    if path.endswith((".html", ".htm", ".php", ".asp", ".aspx", ".jsp")) or path.endswith("/"):
        return "HTML_PAGE"
    return "ENDPOINT"


# Common BCP-47 language tags used as path segments (not country codes like "be")
KNOWN_LOCALES = frozenset(
    {
        "en",
        "fr",
        "nl",
        "de",
        "es",
        "it",
        "pt",
        "ja",
        "ko",
        "zh",
        "ar",
        "ru",
        "uk",
        "pl",
        "cs",
        "sk",
        "hu",
        "ro",
        "bg",
        "el",
        "tr",
        "sv",
        "da",
        "no",
        "fi",
        "he",
        "th",
        "vi",
        "id",
        "ms",
        "hi",
        "ka",
        "en-us",
        "en-gb",
        "pt-br",
        "zh-cn",
        "zh-tw",
    }
)

_SEND_MONEY_RE = re.compile(r"(?i)^send-money-to-(.+)$")
_CURRENCY_PAIR_RE = re.compile(r"(?i)^([a-z]{3})-to-([a-z]{3})-rate$")
_ID_SEG_RE = re.compile(r"(?i)^(?:[0-9a-f]{8,}|[0-9]{4,})$")


def extract_path_locale(url: str) -> str:
    """First known locale segment in the path, if any."""
    try:
        segments = [s for s in (urlsplit(url).path or "/").split("/") if s]
    except Exception:
        return ""
    for seg in segments:
        base = seg.split(".", 1)[0].lower()
        if base in KNOWN_LOCALES:
            return base
    return ""


def route_template_key(url: str) -> str:
    """Collapse locale/destination/currency/country-language families into one route key."""
    try:
        parts = urlsplit(url)
        segments = [s for s in (parts.path or "/").split("/") if s]
        # Pre-mark country+language pairs: /us/en/... → /{country}/{locale}/...
        marked: list[Optional[str]] = [None] * len(segments)
        for i in range(len(segments) - 1):
            a = segments[i]
            b = segments[i + 1]
            a_base = a.split(".", 1)[0].lower()
            b_base = b.split(".", 1)[0].lower()
            if (
                len(a_base) == 2
                and a_base.isalpha()
                and a_base not in KNOWN_LOCALES
                and b_base in KNOWN_LOCALES
            ):
                marked[i] = "{country}"
                # language handled in main loop via KNOWN_LOCALES
        out: list[str] = []
        for idx, seg in enumerate(segments):
            if "." in seg:
                base, ext = seg.rsplit(".", 1)
                ext = "." + ext
            else:
                base, ext = seg, ""
            low = base.lower()
            if marked[idx] == "{country}":
                out.append("{country}" + ext)
                continue
            if low in KNOWN_LOCALES:
                out.append("{locale}" + ext)
                continue
            m = _SEND_MONEY_RE.match(base)
            if m:
                out.append("send-money-to-{destination}" + ext)
                continue
            m = _CURRENCY_PAIR_RE.match(base)
            if m:
                out.append("{currency-pair}-rate" + ext)
                continue
            if _ID_SEG_RE.match(low):
                out.append("{id}" + ext)
                continue
            out.append(seg)
        path = "/" + "/".join(out)
        host = (parts.netloc or "").lower()
        return f"{(parts.scheme or 'https').lower()}://{host}{path}"
    except Exception:
        return url


class RouteTemplateTracker:
    """Cap fetch queue for equivalent route families; always keep URL inventory."""

    def __init__(
        self,
        *,
        max_instances_per_route_template: int = 3,
        max_locales_per_route_template: int = 2,
        same_locale_only: bool = True,
        start_url: str = "",
    ):
        self.max_instances = max(1, int(max_instances_per_route_template or 3))
        self.max_locales = max(1, int(max_locales_per_route_template or 2))
        self.same_locale_only = bool(same_locale_only)
        self.seed_locale = extract_path_locale(start_url) if start_url else ""
        self._queued_counts: Dict[str, int] = {}
        self._queued_locales: Dict[str, Set[str]] = {}
        self._inventory: Dict[str, Set[str]] = {}
        self.skipped_variants = 0
        self.observed = 0

    def observe(self, url: str) -> str:
        key = route_template_key(url)
        self._inventory.setdefault(key, set()).add(url)
        self.observed += 1
        return key

    def inventory_counts(self) -> Dict[str, int]:
        return {k: len(v) for k, v in self._inventory.items()}

    def allow(self, url: str) -> bool:
        """True if this URL should enter the fetch queue."""
        key = self.observe(url)
        loc = extract_path_locale(url)
        if self.same_locale_only and self.seed_locale and loc and loc != self.seed_locale:
            self.skipped_variants += 1
            return False
        locales = self._queued_locales.setdefault(key, set())
        if loc and loc not in locales and len(locales) >= self.max_locales:
            self.skipped_variants += 1
            return False
        if self._queued_counts.get(key, 0) >= self.max_instances:
            self.skipped_variants += 1
            return False
        self._queued_counts[key] = self._queued_counts.get(key, 0) + 1
        if loc:
            locales.add(loc)
        return True


class QueryVariantTracker:
    """Cap query-value *enqueue* explosion; always retain full param inventory."""

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
        # Unbounded attack-surface inventory (never drop observed values)
        self._observed_param_values: Dict[str, Dict[str, Set[str]]] = {}
        self._observed_endpoints: Set[str] = set()
        self.skipped_variants = 0
        self.observed_variants = 0

    def observe(self, url: str) -> str:
        """Record endpoint + every query value as attack surface. Returns endpoint id."""
        cleaned = strip_tracking_params(url)
        eid = endpoint_identity(cleaned)
        self._observed_endpoints.add(eid)
        self.observed_variants += 1
        try:
            parts = urlsplit(cleaned)
            by_param = self._observed_param_values.setdefault(eid, {})
            for name, value in parse_qsl(parts.query, keep_blank_values=True):
                low = (name or "").lower()
                if not low:
                    continue
                by_param.setdefault(low, set()).add(value)
        except Exception:
            pass
        return eid

    def inventory_rows(self, *, max_values: int = 20) -> List[Dict[str, Any]]:
        """Serialize observed params for reports (capped display, full names)."""
        rows: List[Dict[str, Any]] = []
        for eid in sorted(self._observed_endpoints):
            params = self._observed_param_values.get(eid) or {}
            for name in sorted(params.keys()):
                vals = sorted(params[name])
                rows.append(
                    {
                        "endpoint_identity": eid,
                        "name": name,
                        "values_sample": vals[:max_values],
                        "values_count": len(vals),
                        "source": "query_observe",
                    }
                )
        return rows

    def allow(self, url: str) -> bool:
        """Return True if this URL's query variant should be enqueued for fetch.

        Always calls ``observe`` first so skipped variants remain in inventory.
        """
        cleaned = strip_tracking_params(url)
        self.observe(cleaned)
        eid = endpoint_identity(cleaned)
        rid = resource_identity(cleaned)
        variants = self._endpoint_variants.setdefault(eid, set())
        if rid in variants:
            return True  # already counted; caller still dedupes on full URL
        if len(variants) >= self.max_query_variants_per_endpoint:
            try:
                if not urlsplit(cleaned).query:
                    variants.add(rid)
                    return True
            except Exception:
                pass
            self.skipped_variants += 1
            return False
        # Cap functional param value cardinality for the *queue* only
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
        if low in (
            "csrf",
            "csrf_token",
            "csrftoken",
            "_token",
            "authenticity_token",
            "__requestverificationtoken",
        ):
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


# --- JavaScript string → URL classification (safer than blind urljoin) --------

PLACEHOLDER_PATTERN = re.compile(
    r"(\[[^\]]+\]|\{[^}]+\}|<[^>]+>|:\w+|\[\[[^\]]+\]\])"
)

_STATIC_ASSET_HINT_RE = re.compile(
    r"(?i)(?:^|/)_next/static/|/static/chunks/|/chunks/|/\.map$|\.(?:js|mjs|css|woff2?|png|jpe?g|gif|svg|webp)(?:$|\?)"
)

_ANALYTICS_PATH_RE = re.compile(
    r"(?i)^/\d{8,}/(?:wu_web|gtm|analytics|pixel|events?)/|"
    r"^/(?:collect|g/collect|pagead|gtag|beacon|telemetry)/"
)

_AKAMAI_CHALLENGE_SEG_RE = re.compile(
    r"(?i)^/(?:[A-Za-z0-9_-]{16,}/){1,}[A-Za-z0-9_-]{8,}(?:/|$)"
)

_HIGH_ENTROPY_SEG_RE = re.compile(r"^[A-Za-z0-9_-]{20,}$")


def path_has_route_placeholder(path: str) -> bool:
    return bool(PLACEHOLDER_PATTERN.search(path or ""))


def normalize_route_template(path: str) -> str:
    """Convert Next.js ``[param]`` / ``[[...slug]]`` style into ``{param}`` templates."""
    p = path or "/"
    p = re.sub(r"\[\[\.\.\.([^\]]+)\]\]", r"{{\1}}", p)
    p = re.sub(r"\[([^\]]+)\]", r"{\1}", p)
    p = re.sub(r":([A-Za-z_][A-Za-z0-9_]*)", r"{\1}", p)
    return p


def is_protection_artifact_path(path: str) -> bool:
    """Akamai/challenge high-entropy paths — WAF telemetry only, not app inventory."""
    p = path or ""
    if not p.startswith("/"):
        return False
    if path_has_route_placeholder(p):
        return False
    segs = [s for s in p.split("/") if s]
    if not segs:
        return False
    # Single long opaque token or multi-segment challenge style
    if len(segs) >= 1 and _HIGH_ENTROPY_SEG_RE.match(segs[0]) and len(segs[0]) >= 20:
        # Avoid treating real app slugs; require challenge-like mix of case/digits
        s0 = segs[0]
        if any(c.isdigit() for c in s0) and any(c.isupper() for c in s0) and any(c.islower() for c in s0):
            return True
    if _AKAMAI_CHALLENGE_SEG_RE.match(p) and len(segs[0]) >= 16:
        s0 = segs[0]
        if any(c.isdigit() for c in s0) and any(c.isalpha() for c in s0):
            return True
    return False


def is_analytics_like_path(path: str) -> bool:
    return bool(_ANALYTICS_PATH_RE.search(path or ""))


def origin_of(url: str) -> str:
    try:
        parts = urlsplit(url)
        if not parts.scheme or not parts.netloc:
            return ""
        return f"{parts.scheme}://{parts.netloc}"
    except Exception:
        return ""


def script_dir_is_static_bundle(script_url: str) -> bool:
    path = (urlsplit(script_url).path or "").lower()
    return any(
        m in path
        for m in (
            "/_next/static/",
            "/static/chunks/",
            "/chunks/",
            "/webpack/",
            "/assets/js/",
        )
    )


def classify_js_candidate(value: str, script_url: str, origin: str) -> Tuple[str, str]:
    """Classify a JS string for crawl/inventory.

    Returns ``(kind, payload)`` where kind is one of:
      absolute_url | root_relative_url | route_template | static_asset |
      protection_artifact | analytics_path | unverified_string
    """
    raw = (value or "").strip().strip("'\"")
    if not raw or len(raw) < 2 or len(raw) > 300:
        return "unverified_string", raw
    if " " in raw or "${" in raw:
        return "unverified_string", raw
    low = raw.lower()
    if low.startswith(("http://", "https://")):
        return "absolute_url", raw
    if low.startswith("//") and origin:
        try:
            scheme = urlsplit(origin).scheme or "https"
            return "absolute_url", f"{scheme}:{raw}"
        except Exception:
            return "unverified_string", raw
    if path_has_route_placeholder(raw):
        return "route_template", normalize_route_template(raw if raw.startswith("/") else f"/{raw}")
    if is_protection_artifact_path(raw if raw.startswith("/") else f"/{raw}"):
        return "protection_artifact", raw if raw.startswith("/") else f"/{raw}"
    if is_analytics_like_path(raw if raw.startswith("/") else f"/{raw}"):
        return "analytics_path", raw if raw.startswith("/") else f"/{raw}"
    if raw.startswith("/"):
        if _STATIC_ASSET_HINT_RE.search(raw) and not raw.endswith((".html", ".htm", "/")):
            # Still allow root-relative app paths; only mark pure assets when extension-like
            if re.search(r"(?i)\.(?:js|mjs|css|map|woff2?|png|jpe?g|gif|svg|webp)(?:$|\?)", raw):
                return "static_asset", urljoin(origin or script_url, raw)
        return "root_relative_url", urljoin(origin or "", raw)
    # Bare relative — never resolve against deep /_next/static/chunks/… bases
    if script_dir_is_static_bundle(script_url):
        if _STATIC_ASSET_HINT_RE.search(raw):
            return "static_asset", raw
        return "unverified_string", raw
    if _STATIC_ASSET_HINT_RE.search(raw):
        return "static_asset", urljoin(script_url or origin or "", raw)
    return "unverified_string", raw


def js_candidate_enqueue_url(value: str, script_url: str, origin: str = "") -> Optional[str]:
    """Return an absolute http(s) URL safe to enqueue from a JS string, else None.

    Route templates, protection artifacts, analytics paths, and unverified relative
    strings are inventoried by the caller but never returned for enqueue.
    """
    origin = origin or origin_of(script_url)
    kind, payload = classify_js_candidate(value, script_url, origin)
    if kind in ("absolute_url", "root_relative_url"):
        resolved = resolve_http_target(payload, origin or script_url)
        if not resolved:
            return None
        path = urlsplit(resolved).path or ""
        if path_has_route_placeholder(path):
            return None
        if is_protection_artifact_path(path) or is_analytics_like_path(path):
            return None
        # Never fabricate HTML under static chunk directories
        if "/_next/static/" in path.lower() and path.lower().endswith((".html", ".htm")):
            return None
        return resolved
    return None
