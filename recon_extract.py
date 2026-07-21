"""Passive recon extractors — zero extra requests; accuracy-gated inventories."""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

SOURCEMAP_RE = re.compile(
    r"(?://[#@]|/\*)\s*sourceMappingURL\s*=\s*(\S+?)(?:\s*\*/)?\s*$",
    re.MULTILINE | re.IGNORECASE,
)
WS_LITERAL_RE = re.compile(r"(?i)[\"'](wss?://[^\"']+)[\"']")
JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
)
LOGIN_PATH_RE = re.compile(
    r"(?i)/(?:login|signin|sign-in|log-in|auth(?:/|$)|account/login|session/new|oauth/authorize)(?:$|[/?#])"
)
PASSWORD_FIELD_RE = re.compile(
    r"(?i)(<input[^>]+type\s*=\s*[\"']password[\"']|name\s*=\s*[\"']password[\"'])"
)
MIXED_CONTENT_RE = re.compile(
    r"(?i)(?:src|href|action|data|poster)\s*=\s*[\"'](http://[^\"']+)[\"']"
)
EMAIL_RE = re.compile(r"(?i)\b([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})\b")
MAILTO_RE = re.compile(r"(?i)mailto:([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})")
PHONE_RE = re.compile(r"(?<!\w)(\+?\d[\d\-\s().]{7,}\d)")
LINK_REL_RE = re.compile(
    r"(?i)<link[^>]+rel\s*=\s*[\"']([^\"']+)[\"'][^>]*>|<link[^>]+href\s*=\s*[\"']([^\"']+)[\"'][^>]*rel\s*=\s*[\"']([^\"']+)[\"']"
)
LINK_HREF_IN_TAG = re.compile(r"(?i)href\s*=\s*[\"']([^\"']+)[\"']")
HTML_COMMENT_RE = re.compile(r"<!--([\s\S]{3,400}?)-->")
JS_COMMENT_RE = re.compile(r"(?://([^\n]{8,200})|/\*([\s\S]{8,400}?)\*/)")
URLISH_IN_COMMENT = re.compile(
    r"(?i)(https?://[^\s<>\"']+|/(?:admin|api|internal|debug|staging|backup)[^\s<>\"']{0,80}|TODO|FIXME|XXX|password|secret)"
)
ABS_URL_RE = re.compile(r"(?i)https?://([a-z0-9._\-]+(?::\d+)?)(/[^\s\"'<>]*)?")
DOM_SINK_RE = re.compile(
    r"(?i)\b(innerHTML|outerHTML|document\.write|document\.writeln|eval\s*\(|setTimeout\s*\(\s*[\"']|"
    r"setInterval\s*\(\s*[\"']|new\s+Function\s*\()"
)
USER_INPUT_NEAR_RE = re.compile(
    r"(?i)(location\.(?:hash|search|href)|document\.URL|window\.name|localStorage|sessionStorage|"
    r"\.value\b|querySelector|getParameter|URLSearchParams)"
)
CLOUD_URL_RE = re.compile(
    r"(?i)("
    r"https?://[a-z0-9.\-]+\.firebaseio\.com[^\s\"'<>]*|"
    r"https?://[a-z0-9.\-]+\.firebaseapp\.com[^\s\"'<>]*|"
    r"https?://firebasestorage\.googleapis\.com/[^\s\"'<>]+|"
    r"https?://[a-z0-9.\-]+\.supabase\.co[^\s\"'<>]*|"
    r"https?://[a-z0-9.\-]+\.blob\.core\.windows\.net[^\s\"'<>]*|"
    r"https?://[a-z0-9.\-]+\.azurewebsites\.net[^\s\"'<>]*|"
    r"https?://[a-z0-9.\-]+\.appspot\.com[^\s\"'<>]*"
    r")"
)
LINK_HEADER_RE = re.compile(r'<([^>]+)>\s*;\s*rel="?([^";,]+)"?', re.IGNORECASE)

EMAIL_NOISE_RE = re.compile(
    r"(?i)@(example\.com|example\.org|test\.com|localhost|sentry\.io|w3\.org|schema\.org|"
    r"googleapis\.com|gstatic\.com)|^(noreply|no-reply|donotreply)@"
)
INTERNAL_HOST_RE = re.compile(
    r"(?i)^("
    r"localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|"
    r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|"
    r"[a-z0-9.\-]+\.(?:local|lan|internal|intranet|corp|home|test|dev|staging|stage|qa)"
    r")$"
)
INTERNAL_NAME_HINT = re.compile(
    r"(?i)\b(staging|stage|dev|devel|qa|uat|internal|intranet|corp|vpn|bastion|jenkins|gitlab)\b"
)

INTERESTING_RELS = {
    "canonical",
    "alternate",
    "manifest",
    "apple-touch-icon",
    "preconnect",
    "dns-prefetch",
    "preload",
    "modulepreload",
    "serviceworker",
    "search",
    "edituri",
}

THIRD_PARTY_HINTS = {
    "google-analytics.com": "Google Analytics",
    "googletagmanager.com": "Google Tag Manager",
    "googleadservices.com": "Google Ads",
    "doubleclick.net": "DoubleClick",
    "facebook.net": "Facebook",
    "facebook.com": "Facebook",
    "connect.facebook.net": "Facebook",
    "hotjar.com": "Hotjar",
    "segment.io": "Segment",
    "segment.com": "Segment",
    "cdn.segment.com": "Segment",
    "sentry.io": "Sentry",
    "browser.sentry-cdn.com": "Sentry",
    "stripe.com": "Stripe",
    "js.stripe.com": "Stripe",
    "paypal.com": "PayPal",
    "cloudflareinsights.com": "Cloudflare Insights",
    "cdn.jsdelivr.net": "jsDelivr",
    "unpkg.com": "unpkg",
    "cdnjs.cloudflare.com": "cdnjs",
    "ajax.googleapis.com": "Google Hosted Libraries",
    "intercom.io": "Intercom",
    "zendesk.com": "Zendesk",
    "newrelic.com": "New Relic",
    "nr-data.net": "New Relic",
    "datadoghq.com": "Datadog",
    "mixpanel.com": "Mixpanel",
    "amplitude.com": "Amplitude",
    "clarity.ms": "Microsoft Clarity",
    "hubspot.com": "HubSpot",
    "hs-scripts.com": "HubSpot",
    "shopify.com": "Shopify",
    "shopifycdn.com": "Shopify",
}

SECURITY_HEADER_KEYS = (
    "strict-transport-security",
    "content-security-policy",
    "content-security-policy-report-only",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "report-to",
    "nel",
)


def extract_sourcemap_urls(text: str, base_url: str) -> Set[str]:
    found: Set[str] = set()
    if not text:
        return found
    for match in SOURCEMAP_RE.finditer(text):
        ref = (match.group(1) or "").strip().rstrip("*/").strip()
        if not ref or ref.startswith("data:"):
            continue
        found.add(urljoin(base_url, ref))
    path = urlparse(base_url).path or ""
    if path.endswith(".js") and "sourceMappingURL" in text:
        found.add(base_url + ".map")
    return found


def extract_websocket_urls(text: str, base_url: str) -> Set[str]:
    found: Set[str] = set()
    if not text:
        return found
    for match in WS_LITERAL_RE.findall(text):
        found.add(match.rstrip("\\"))
    for match in re.finditer(r"(?i)WebSocket\s*\(\s*[\"']([^\"']+)[\"']", text):
        found.add(urljoin(base_url, match.group(1)))
    return {
        u
        for u in found
        if u.startswith(("ws://", "wss://", "http://", "https://")) or u.startswith("/")
    }


def extract_mixed_content(url: str, body_text: str) -> List[str]:
    if not body_text or not url.lower().startswith("https://"):
        return []
    hits = []
    for match in MIXED_CONTENT_RE.finditer(body_text[:200000]):
        resource = match.group(1)
        if resource.lower().startswith("http://"):
            hits.append(resource)
    seen: Set[str] = set()
    out: List[str] = []
    for item in hits:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out[:40]


def detect_login_surface(
    url: str, body_text: str = "", forms: Optional[List[dict]] = None
) -> Optional[str]:
    path = urlparse(url).path or ""
    reasons = []
    if LOGIN_PATH_RE.search(path):
        reasons.append("login-like path")
    if body_text and PASSWORD_FIELD_RE.search(body_text[:100000]):
        reasons.append("password field in page")
    if forms:
        for form in forms:
            fields = [str(f).lower() for f in form.get("fields", [])]
            if any(f in ("password", "passwd", "pass", "pwd") for f in fields):
                reasons.append(f"password form → {form.get('action') or url}")
                break
    if not reasons:
        return None
    return "; ".join(reasons)


def inventory_cookies(headers: dict) -> List[Dict[str, str]]:
    if not headers:
        return []
    raw_parts: List[str] = []
    for key, value in headers.items():
        if key.lower() == "set-cookie":
            raw_parts.extend(_split_set_cookie(str(value)))
    inventory = []
    for part in raw_parts:
        name = part.split("=", 1)[0].strip()
        if not name:
            continue
        lowered = part.lower()
        flags = []
        if "httponly" in lowered:
            flags.append("HttpOnly")
        if "secure" in lowered:
            flags.append("Secure")
        if "samesite=none" in lowered:
            flags.append("SameSite=None")
        elif "samesite=lax" in lowered:
            flags.append("SameSite=Lax")
        elif "samesite=strict" in lowered:
            flags.append("SameSite=Strict")
        inventory.append(
            {
                "name": name,
                "flags": ",".join(flags) if flags else "(none)",
                "snippet": part[:120],
            }
        )
    return inventory


def find_jwt_candidates(text: str, headers: Optional[dict] = None) -> List[Tuple[str, str]]:
    """Return (source, full_token) for JWT-shaped strings."""
    hits: List[Tuple[str, str]] = []
    seen = set()

    def add(source: str, token: str):
        if token in seen:
            return
        seen.add(token)
        hits.append((source, token))

    if headers:
        for key, value in headers.items():
            kl = key.lower()
            if kl in ("authorization", "set-cookie", "cookie"):
                for match in JWT_RE.finditer(str(value)):
                    add(kl, match.group(0))
    if text:
        for match in JWT_RE.finditer(text[:150000]):
            add("body", match.group(0))
    return hits[:20]


def extract_emails(text: str) -> List[str]:
    if not text:
        return []
    found: List[str] = []
    seen: Set[str] = set()
    for match in list(MAILTO_RE.findall(text[:200000])) + list(EMAIL_RE.findall(text[:200000])):
        email = match.strip().lower()
        if email in seen or EMAIL_NOISE_RE.search(email):
            continue
        if len(email) > 80 or ".." in email:
            continue
        seen.add(email)
        found.append(email)
    return found[:50]


def extract_phones(text: str) -> List[str]:
    if not text:
        return []
    found: List[str] = []
    seen: Set[str] = set()
    for match in PHONE_RE.findall(text[:100000]):
        digits = re.sub(r"\D", "", match)
        if len(digits) < 10 or len(digits) > 15:
            continue
        # Skip obvious IDs / years
        if digits.startswith("20") and len(digits) == 10:
            continue
        key = digits
        if key in seen:
            continue
        seen.add(key)
        found.append(re.sub(r"\s+", " ", match.strip())[:32])
    return found[:20]


def extract_link_rels(html: str, base_url: str) -> List[Dict[str, str]]:
    if not html:
        return []
    rows: List[Dict[str, str]] = []
    seen: Set[Tuple[str, str]] = set()
    for tag in re.finditer(r"(?i)<link\b[^>]*>", html[:300000]):
        chunk = tag.group(0)
        rel_m = re.search(r"(?i)rel\s*=\s*[\"']([^\"']+)[\"']", chunk)
        href_m = re.search(r"(?i)href\s*=\s*[\"']([^\"']+)[\"']", chunk)
        if not rel_m or not href_m:
            continue
        rels = [r.strip().lower() for r in rel_m.group(1).split() if r.strip()]
        href = urljoin(base_url, href_m.group(1).strip())
        for rel in rels:
            if rel not in INTERESTING_RELS:
                continue
            key = (rel, href)
            if key in seen:
                continue
            seen.add(key)
            rows.append({"rel": rel, "url": href})
    return rows[:80]


def extract_internal_hosts(text: str, page_host: str = "") -> List[str]:
    if not text:
        return []
    page_host = (page_host or "").lower().split(":")[0]
    found: List[str] = []
    seen: Set[str] = set()
    for host, _path in ABS_URL_RE.findall(text[:250000]):
        host_l = host.lower().split(":")[0]
        if host_l in seen or host_l == page_host:
            continue
        if INTERNAL_HOST_RE.match(host_l) or INTERNAL_NAME_HINT.search(host_l):
            seen.add(host_l)
            found.append(host_l)
    return found[:40]


def extract_third_party_scripts(html: str, page_host: str = "") -> List[Dict[str, str]]:
    if not html:
        return []
    page_host = (page_host or "").lower().split(":")[0]
    rows: List[Dict[str, str]] = []
    seen: Set[str] = set()
    for match in re.finditer(r"(?i)<script[^>]+src\s*=\s*[\"']([^\"']+)[\"']", html[:300000]):
        src = match.group(1).strip()
        if not src.startswith(("http://", "https://", "//")):
            continue
        if src.startswith("//"):
            src = "https:" + src
        host = urlparse(src).netloc.lower().split(":")[0]
        if not host or host == page_host or host in seen:
            continue
        label = None
        for needle, name in THIRD_PARTY_HINTS.items():
            if host == needle or host.endswith("." + needle) or needle in host:
                label = name
                break
        if not label:
            # Unknown third-party still inventoried once (host only)
            label = "Third-party script"
        seen.add(host)
        rows.append({"host": host, "vendor": label, "url": src[:200]})
    return rows[:60]


def inventory_security_headers(headers: dict) -> Dict[str, str]:
    if not headers:
        return {}
    lowered = {str(k).lower(): str(v) for k, v in headers.items() if not str(k).startswith("_")}
    out: Dict[str, str] = {}
    for key in SECURITY_HEADER_KEYS:
        if key in lowered and lowered[key].strip():
            out[key] = lowered[key].strip()[:500]
    return out


def extract_interesting_comments(text: str) -> List[str]:
    if not text:
        return []
    hits: List[str] = []
    seen: Set[str] = set()
    chunks: List[str] = []
    for m in HTML_COMMENT_RE.finditer(text[:200000]):
        chunks.append(m.group(1))
    for m in JS_COMMENT_RE.finditer(text[:200000]):
        chunks.append(m.group(1) or m.group(2) or "")
    for chunk in chunks:
        cleaned = re.sub(r"\s+", " ", (chunk or "").strip())
        if len(cleaned) < 8 or cleaned in seen:
            continue
        if not URLISH_IN_COMMENT.search(cleaned):
            continue
        # Drop boilerplate license walls
        if re.search(r"(?i)copyright|license|spdx|all rights reserved", cleaned) and "http" not in cleaned.lower():
            continue
        seen.add(cleaned)
        hits.append(cleaned[:220])
    return hits[:40]


def extract_dom_sinks(js_or_html: str) -> List[str]:
    """Inventory only when a sink appears near a user-input-ish token (cuts doc FPs)."""
    if not js_or_html:
        return []
    text = js_or_html[:200000]
    hits: List[str] = []
    seen: Set[str] = set()
    for match in DOM_SINK_RE.finditer(text):
        start = max(0, match.start() - 120)
        end = min(len(text), match.end() + 120)
        window = text[start:end]
        if not USER_INPUT_NEAR_RE.search(window):
            continue
        sink = re.sub(r"\s+", " ", match.group(0))[:40]
        key = sink.lower()
        if key in seen:
            continue
        seen.add(key)
        hits.append(f"{sink} near user-input token")
    return hits[:25]


def extract_cloud_urls(text: str) -> List[str]:
    if not text:
        return []
    found: List[str] = []
    seen: Set[str] = set()
    for match in CLOUD_URL_RE.findall(text[:250000]):
        url = match.rstrip(").,;'\"")
        if url in seen:
            continue
        seen.add(url)
        found.append(url)
    return found[:40]


def extract_link_header_urls(headers: dict, base_url: str) -> List[Dict[str, str]]:
    if not headers:
        return []
    rows: List[Dict[str, str]] = []
    seen: Set[Tuple[str, str]] = set()
    for key, value in headers.items():
        if key.lower() != "link":
            continue
        for href, rel in LINK_HEADER_RE.findall(str(value)):
            rel_l = rel.strip().lower()
            if rel_l not in ("next", "prev", "first", "last", "alternate", "service", "describedby"):
                continue
            full = urljoin(base_url, href.strip())
            key_t = (rel_l, full)
            if key_t in seen:
                continue
            seen.add(key_t)
            rows.append({"rel": rel_l, "url": full})
    return rows[:40]


def parse_sitemap_locs(xml_text: str) -> Tuple[List[str], List[str]]:
    """Return (page_urls, child_sitemap_urls) from sitemap or sitemapindex XML."""
    if not xml_text:
        return [], []
    is_index = bool(re.search(r"(?i)<sitemapindex\b", xml_text[:2000]))
    locs = [
        loc.strip()
        for loc in re.findall(r"(?i)<loc>\s*([^<]+)\s*</loc>", xml_text)
        if loc.strip().startswith("http")
    ]
    if is_index:
        return [], locs[:50]
    pages: List[str] = []
    children: List[str] = []
    for url in locs:
        leaf = url.lower().rsplit("/", 1)[-1]
        if leaf.endswith(".xml") or "sitemap" in leaf:
            children.append(url)
        else:
            pages.append(url)
    return pages[:2000], children[:50]


def _split_set_cookie(value: str) -> List[str]:
    if not value:
        return []
    parts = re.split(r",(?=\s*[A-Za-z0-9_\-]+=)", value)
    return [p.strip() for p in parts if p.strip()]
