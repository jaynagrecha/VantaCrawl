"""Structured protection detections — vendor, evidence, confidence, scope.

Turns flat fingerprint names into evidence-backed inventory so the cockpit can
separate confirmed-active edge WAFs from page-level CAPTCHAs and passive JS/cookie
shadows.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse

# category → display bucket in the cockpit
CATEGORY_LABELS = {
    "edge_waf": "Edge / WAF",
    "app_challenge": "Application challenge",
    "rate_limiting": "Rate limiting",
    "auth_control": "Authentication control",
}

VENDOR_META: Dict[str, Dict[str, str]] = {
    "akamai": {"category": "edge_waf", "display": "Akamai"},
    "cloudflare": {"category": "edge_waf", "display": "Cloudflare"},
    "datadome": {"category": "edge_waf", "display": "DataDome"},
    "perimeterx": {"category": "edge_waf", "display": "PerimeterX / HUMAN"},
    "aws_waf": {"category": "edge_waf", "display": "AWS WAF"},
    "imperva": {"category": "edge_waf", "display": "Imperva"},
    "sucuri": {"category": "edge_waf", "display": "Sucuri"},
    "modsecurity": {"category": "edge_waf", "display": "ModSecurity"},
    "recaptcha": {"category": "app_challenge", "display": "Google reCAPTCHA"},
    "hcaptcha": {"category": "app_challenge", "display": "hCaptcha"},
    "cloudflare_turnstile": {"category": "app_challenge", "display": "Cloudflare Turnstile"},
    "rate_limit": {"category": "rate_limiting", "display": "HTTP rate limit"},
}

# Cookie name → vendor (exact / prefix)
_COOKIE_EXACT: Dict[str, str] = {
    "_abck": "akamai",
    "bm_sz": "akamai",
    "ak_bmsc": "akamai",
    "bm_sv": "akamai",
    "bm_mi": "akamai",
    "bm_lso": "akamai",
    "bm_so": "akamai",
    "__cf_bm": "cloudflare",
    "cf_clearance": "cloudflare",
    "datadome": "datadome",
    "_pxvid": "perimeterx",
    "_pxhd": "perimeterx",
    "_px3": "perimeterx",
    "_pxde": "perimeterx",
}

_COOKIE_PREFIX: Tuple[Tuple[str, str], ...] = (
    ("bm_", "akamai"),
    ("_px", "perimeterx"),
    ("dd_", "datadome"),
)

# Response header key (lower) → vendor
_HEADER_VENDOR: Dict[str, str] = {
    "cf-ray": "cloudflare",
    "cf-mitigated": "cloudflare",
    "cf-cache-status": "cloudflare",
    "x-datadome": "datadome",
    "x-datadome-cid": "datadome",
    "x-akamai-request-id": "akamai",
    "akamai-origin-hop": "akamai",
    "x-iinfo": "imperva",
    "x-sucuri-id": "sucuri",
    "x-amzn-waf": "aws_waf",
    "retry-after": "rate_limit",
}

# Body / script markers → (vendor, evidence_prefix)
# js-reference = passive script/CDN mention; deny-body = challenge page copy
_BODY_MARKERS: Tuple[Tuple[str, str, str], ...] = (
    ("google.com/recaptcha", "recaptcha", "js-reference"),
    ("g-recaptcha", "recaptcha", "js-reference"),
    ("recaptcha/api.js", "recaptcha", "js-reference"),
    ("hcaptcha.com", "hcaptcha", "js-reference"),
    ("h-captcha", "hcaptcha", "js-reference"),
    ("challenges.cloudflare.com", "cloudflare_turnstile", "js-reference"),
    ("cf-turnstile", "cloudflare_turnstile", "js-reference"),
    ("datadome.co", "datadome", "js-reference"),
    ("js.datadome", "datadome", "js-reference"),
    ("px-cdn", "perimeterx", "js-reference"),
    ("client.perimeterx", "perimeterx", "js-reference"),
    ("humansecurity", "perimeterx", "js-reference"),
    ("errors.edgesuite.net", "akamai", "deny-body"),
    ("akamaighost", "akamai", "deny-body"),
    ("attention required", "cloudflare", "deny-body"),
    ("cf-browser-verification", "cloudflare", "deny-body"),
    ("challenge-platform", "cloudflare", "deny-body"),
    ("rate-burst", "akamai", "deny-body"),
    ("rate burst", "akamai", "deny-body"),
)

_SIGNAL_VENDOR: Dict[str, str] = {
    "akamai": "akamai",
    "akamai_block": "akamai",
    "akamai_soft_deny": "akamai",
    "akamai_rate_burst": "akamai",
    "cloudflare": "cloudflare",
    "cloudflare_block": "cloudflare",
    "cloudflare_soft_deny": "cloudflare",
    "cf-challenge": "cloudflare",
    "cloudflare_turnstile": "cloudflare_turnstile",
    "datadome": "datadome",
    "perimeterx": "perimeterx",
    "aws_waf": "aws_waf",
    "imperva": "imperva",
    "sucuri": "sucuri",
    "recaptcha": "recaptcha",
    "hcaptcha": "hcaptcha",
    "rate_limit": "rate_limit",
}

_CATCH_STATUSES = frozenset({401, 403, 407, 429, 503})

_COOKIE_PAIR_RE = re.compile(
    r"(?i)(?:^|[;\s,])([^=\s;,]{1,80})\s*="
)


@dataclass
class VendorDetection:
    vendor: str
    evidence: Set[str] = field(default_factory=set)
    urls: List[str] = field(default_factory=list)
    challenge_count: int = 0
    observe_count: int = 0

    def add_evidence(self, items: Iterable[str]) -> None:
        for item in items:
            text = str(item or "").strip()
            if text:
                self.evidence.add(text[:120])

    def note_url(self, url: str, *, challenged: bool = False) -> None:
        self.observe_count += 1
        if challenged:
            self.challenge_count += 1
        u = (url or "").strip()
        if u and u not in self.urls:
            if len(self.urls) < 8:
                self.urls.append(u)

    def to_dict(self) -> Dict[str, Any]:
        meta = VENDOR_META.get(self.vendor, {"category": "edge_waf", "display": self.vendor})
        evidence = sorted(self.evidence)
        groups = _evidence_groups(evidence)
        confidence, active, tier = score_detection(
            vendor=self.vendor,
            category=meta["category"],
            groups=groups,
            challenge_count=self.challenge_count,
            evidence=evidence,
        )
        scope = infer_scope(
            category=meta["category"],
            challenge_count=self.challenge_count,
            urls=self.urls,
            active=active,
        )
        return {
            "vendor": self.vendor,
            "display": meta["display"],
            "category": meta["category"],
            "category_label": CATEGORY_LABELS.get(meta["category"], meta["category"]),
            "confidence": confidence,
            "confidence_label": _confidence_label(confidence),
            "scope": scope,
            "active": active,
            "tier": tier,
            "evidence": evidence,
            "challenge_count": self.challenge_count,
            "sample_urls": list(self.urls)[:5],
        }


def _evidence_groups(evidence: Iterable[str]) -> Set[str]:
    groups: Set[str] = set()
    for raw in evidence:
        e = str(raw)
        if e.startswith("cookie:") or e.startswith("response-header:"):
            groups.add("identity")
        elif e.startswith("challenge-behaviour") or e.startswith("deny-body:"):
            groups.add("behavior")
        elif e.startswith("js-reference:") or e.startswith("body-string:"):
            groups.add("passive")
        elif e.startswith("server:"):
            groups.add("identity")
    return groups


def score_detection(
    *,
    vendor: str,
    category: str,
    groups: Set[str],
    challenge_count: int,
    evidence: List[str],
) -> Tuple[float, bool, str]:
    """Return (confidence 0..1, active, tier).

    Confirmed active edge WAF requires identity + behavior (two independent groups).
    """
    has_id = "identity" in groups
    has_beh = "behavior" in groups
    has_pass = "passive" in groups
    n = len(evidence)

    if category == "app_challenge":
        if has_beh or challenge_count > 0:
            return 0.9, True, "page_level"
        if has_pass or has_id:
            # Script/widget present — page-level control, not site perimeter
            return (0.75 if has_id else 0.55), True, "page_level"
        return 0.3, False, "passive"

    if category == "rate_limiting":
        if has_beh or challenge_count > 0 or any("429" in e or "retry" in e for e in evidence):
            return 0.92, True, "confirmed_active"
        return 0.4, False, "unconfirmed"

    # edge_waf / default — two-group confirmation rule
    if has_id and has_beh:
        conf = 0.96 if n >= 3 else 0.88
        return conf, True, "confirmed_active"
    if has_beh and challenge_count > 0:
        return 0.62, True, "unconfirmed"
    if has_id and challenge_count > 0:
        # Cookie/header seen and this vendor counted on catches, but no deny-body yet
        return 0.7, True, "unconfirmed"
    if has_id and not has_beh:
        return (0.45 if n >= 2 else 0.35), False, "passive"
    if has_pass and not has_id and not has_beh:
        return 0.25, False, "passive"
    if has_beh:
        return 0.5, challenge_count > 0, "unconfirmed"
    return 0.2, False, "unconfirmed"


def infer_scope(
    *,
    category: str,
    challenge_count: int,
    urls: List[str],
    active: bool,
) -> str:
    if category == "app_challenge":
        return "page"
    if category == "rate_limiting":
        return "host" if challenge_count >= 2 else "path"
    if not urls:
        return "host"
    paths = {(urlparse(u).path or "/") for u in urls}
    if active and challenge_count >= 2 and len(paths) >= 2:
        return "host"
    if active and len(paths) == 1 and challenge_count >= 1:
        return "path"
    return "host"


def _confidence_label(confidence: float) -> str:
    if confidence >= 0.85:
        return "High"
    if confidence >= 0.55:
        return "Medium"
    return "Low"


def _cookie_vendor(name: str) -> Optional[str]:
    key = (name or "").strip().lower()
    if not key:
        return None
    if key in _COOKIE_EXACT:
        return _COOKIE_EXACT[key]
    for prefix, vendor in _COOKIE_PREFIX:
        if key.startswith(prefix):
            return vendor
    return None


def _iter_cookie_names(headers: Dict[str, str]) -> List[str]:
    names: List[str] = []
    for key, value in (headers or {}).items():
        lk = str(key).lower()
        if "cookie" not in lk:
            continue
        for match in _COOKIE_PAIR_RE.finditer(str(value)):
            names.append(match.group(1))
    return names


def extract_response_evidence(
    headers: Optional[Dict[str, str]] = None,
    body_preview: str = "",
    *,
    status_code: int = 0,
    signal: str = "",
) -> Dict[str, Set[str]]:
    """Map vendor → evidence strings observed on one response."""
    headers = dict(headers or {})
    headers_l = {str(k).lower(): str(v) for k, v in headers.items()}
    body_l = (body_preview or "").lower()[:8000]
    out: Dict[str, Set[str]] = {}

    def add(vendor: str, item: str) -> None:
        if vendor not in VENDOR_META and vendor not in out:
            return
        out.setdefault(vendor, set()).add(item)

    for name in _iter_cookie_names(headers_l):
        vendor = _cookie_vendor(name)
        if vendor:
            add(vendor, f"cookie:{name.lower()}")

    for hk, vendor in _HEADER_VENDOR.items():
        if hk in headers_l and headers_l[hk]:
            add(vendor, f"response-header:{hk}")

    server = (headers_l.get("server") or "").lower()
    if "akamai" in server or "akamaighost" in server:
        add("akamai", f"server:{headers_l.get('server', '')[:40]}")
    if "cloudflare" in server:
        add("cloudflare", f"server:{headers_l.get('server', '')[:40]}")

    for marker, vendor, kind in _BODY_MARKERS:
        if marker in body_l:
            add(vendor, f"{kind}:{marker}")

    signal_l = (signal or "").strip().lower()
    vendor_from_signal = _SIGNAL_VENDOR.get(signal_l)
    challenged = status_code in _CATCH_STATUSES and bool(signal_l) and signal_l not in (
        "",
        "none",
        "access_deny",
    )
    if challenged and vendor_from_signal:
        label = signal_l.replace(" ", "_")
        add(vendor_from_signal, f"challenge-behaviour:{label}")
        if "rate" in signal_l or "burst" in signal_l or status_code == 429:
            add("rate_limit", f"challenge-behaviour:{label}")
            if status_code == 429:
                add("rate_limit", "challenge-behaviour:http-429")

    # When this response was a catch, tag vendors already evidenced on it.
    if challenged:
        for vendor, items in list(out.items()):
            if vendor == "rate_limit":
                continue
            if vendor_from_signal == vendor or any(
                x.startswith("cookie:")
                or x.startswith("response-header:")
                or x.startswith("deny-body:")
                or x.startswith("server:")
                for x in items
            ):
                add(vendor, f"challenge-behaviour:{signal_l or 'block'}")

    return out


def merge_cookie_inventory_evidence(
    cookies: Optional[List[Dict[str, Any]]],
) -> Dict[str, Set[str]]:
    """Evidence from structured cookie inventory rows."""
    out: Dict[str, Set[str]] = {}
    for row in cookies or []:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "").strip()
        vendor = _cookie_vendor(name)
        if not vendor:
            continue
        out.setdefault(vendor, set()).add(f"cookie:{name.lower()}")
    return out


def sort_detections(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    tier_rank = {
        "confirmed_active": 0,
        "page_level": 1,
        "unconfirmed": 2,
        "passive": 3,
        "conflicting": 4,
    }

    def key(row: Dict[str, Any]) -> Tuple[int, float, str]:
        return (
            tier_rank.get(str(row.get("tier") or ""), 9),
            -float(row.get("confidence") or 0),
            str(row.get("vendor") or ""),
        )

    return sorted(rows, key=key)


def format_protections_label(rows: List[Dict[str, Any]], *, limit: int = 6) -> str:
    if not rows:
        return "none"
    parts: List[str] = []
    for row in rows[:limit]:
        name = str(row.get("display") or row.get("vendor") or "")
        if row.get("active"):
            parts.append(name)
        else:
            parts.append(f"{name}?")
    if len(rows) > limit:
        parts.append(f"+{len(rows) - limit}")
    return ", ".join(parts)
