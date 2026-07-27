"""Edge security checkpoint detection (Vercel and similar).

A uniform edge checkpoint is not a soft-404 / wildcard. It means the scanner
cannot observe the requested resource — candidates are inconclusive, and
enumeration should stop after calibration rather than burning tens of thousands
of probes.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional, Sequence
from urllib.parse import urlparse

# Title / body markers that prove an edge security checkpoint page
_CHECKPOINT_TITLE_RE = re.compile(
    r"(?i)\b("
    r"vercel\s+security\s+checkpoint|"
    r"security\s+checkpoint|"
    r"attention\s+required|"
    r"just\s+a\s+moment|"
    r"checking\s+your\s+browser|"
    r"enable\s+javascript\s+and\s+cookies\s+to\s+continue"
    r")\b"
)
_CHECKPOINT_BODY_MARKERS = (
    "vercel security checkpoint",
    "security checkpoint",
    "/_vercel/insights",
    "cdn.vercel-insights.com",
    "window.vercel",
    "challenge-platform",
    "cf-browser-verification",
    "cf-challenge",
    "checking your browser before accessing",
    "attention required! | cloudflare",
    "enable javascript and cookies to continue",
)
_HTMLISH_RE = re.compile(r"(?i)<!doctype\s+html|<html[\s>]")


def _header_map(headers: Optional[Dict[str, Any]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for key, value in dict(headers or {}).items():
        out[str(key).lower()] = str(value)
    return out


def extract_html_title(body: str | bytes = "") -> str:
    if isinstance(body, (bytes, bytearray)):
        text = bytes(body[:8000]).decode("utf-8", errors="replace")
    else:
        text = (body or "")[:8000]
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
    return re.sub(r"\s+", " ", (m.group(1) if m else "")).strip()[:200]


def is_edge_checkpoint(
    status_code: int,
    body: str | bytes = "",
    headers: Optional[Dict[str, Any]] = None,
    *,
    title: str = "",
) -> str:
    """Return checkpoint signal name, or empty string when not a checkpoint.

    Vercel Security Checkpoint is the primary audited case. Generic PaaS 403s
    without checkpoint markers remain ordinary access denials.
    """
    if int(status_code or 0) not in (401, 403, 429, 503) and int(status_code or 0) != 200:
        # Some checkpoints serve 200 interstitial HTML
        if int(status_code or 0) != 200:
            return ""
    headers_l = _header_map(headers)
    server = (headers_l.get("server") or "").lower()
    if isinstance(body, (bytes, bytearray)):
        body_text = bytes(body[:12000]).decode("utf-8", errors="replace")
    else:
        body_text = (body or "")[:12000]
    body_l = body_text.lower()
    title_text = (title or extract_html_title(body_text) or "").strip()
    title_l = title_text.lower()

    if "vercel security checkpoint" in title_l or "vercel security checkpoint" in body_l:
        return "vercel_security_checkpoint"
    if _CHECKPOINT_TITLE_RE.search(title_text) and (
        "vercel" in server or "vercel" in body_l or "cloudflare" in body_l or "cf-" in " ".join(headers_l)
    ):
        if "vercel" in server or "vercel" in body_l:
            return "vercel_security_checkpoint"
        if "cloudflare" in body_l or headers_l.get("cf-ray"):
            return "cloudflare_challenge"

    htmlish = bool(_HTMLISH_RE.search(body_text[:500]))
    titled = bool(_CHECKPOINT_TITLE_RE.search(title_text))
    for marker in _CHECKPOINT_BODY_MARKERS:
        if marker in body_l or marker in title_l:
            # Status 200 interstitials must look like real HTML/title pages.
            # Bare marker strings (e.g. CDN header bits mis-fed as body) are not checkpoints.
            if int(status_code or 0) == 200 and not (htmlish or titled or headers_l.get("cf-ray")):
                continue
            if "vercel" in marker or "vercel" in server or "vercel" in body_l:
                return "vercel_security_checkpoint"
            if "cloudflare" in marker or "cf-" in marker or headers_l.get("cf-ray"):
                return "cloudflare_challenge"
            if int(status_code or 0) in (401, 403, 503) and htmlish:
                return "edge_security_checkpoint"
    return ""


def checkpoint_vendor(signal: str) -> str:
    sig = (signal or "").lower()
    if "vercel" in sig:
        return "vercel"
    if "cloudflare" in sig:
        return "cloudflare"
    if sig:
        return "edge_checkpoint"
    return ""


def looks_like_html_denial(status_code: int, content_type: str = "", body: str | bytes = "") -> bool:
    """Generic HTML 401/403 denial — not proof of an API/application endpoint."""
    if int(status_code or 0) not in (401, 403):
        return False
    ct = (content_type or "").lower()
    if "json" in ct or "javascript" in ct or "xml" in ct and "html" not in ct:
        return False
    if "text/html" in ct or "html" in ct:
        return True
    if isinstance(body, (bytes, bytearray)):
        sample = bytes(body[:800]).decode("utf-8", errors="replace")
    else:
        sample = (body or "")[:800]
    return bool(_HTMLISH_RE.search(sample))


def is_api_content_type(content_type: str = "", body: str | bytes = "") -> bool:
    ct = (content_type or "").lower()
    if any(tok in ct for tok in ("application/json", "application/problem+json", "+json", "application/xml", "text/xml", "graphql")):
        return True
    if "text/html" in ct or "html" in ct:
        return False
    if isinstance(body, (bytes, bytearray)):
        sample = bytes(body[:400]).decode("utf-8", errors="replace").lstrip()
    else:
        sample = (body or "")[:400].lstrip()
    if sample.startswith("{") or sample.startswith("["):
        return True
    return False


def hosts_in_scope(url: str, start_url: str, *, allow_subdomains: bool = True) -> bool:
    """True when url host is the primary target (or optional same-site subdomain)."""
    try:
        host = (urlparse(url).netloc or "").lower().split("@")[-1]
        base = (urlparse(start_url).netloc or "").lower().split("@")[-1]
    except Exception:
        return False
    if not host or not base:
        return False
    if host.startswith("www."):
        host = host[4:]
    if base.startswith("www."):
        base = base[4:]
    if host == base:
        return True
    if allow_subdomains and host.endswith("." + base):
        return True
    return False


def third_party_storage_host(url: str) -> bool:
    host = (urlparse(url).netloc or "").lower()
    return any(
        tok in host
        for tok in (
            "storage.googleapis.com",
            "amazonaws.com",
            "s3.",
            "blob.core.windows.net",
            "r2.cloudflarestorage.com",
        )
    )


def uniform_checkpoint_across(
    samples: Sequence[Dict[str, Any]],
) -> Optional[str]:
    """If every sample is the same edge checkpoint fingerprint, return the signal."""
    if not samples or len(samples) < 2:
        return None
    signals = []
    hashes = []
    for row in samples:
        sig = is_edge_checkpoint(
            int(row.get("status") or 0),
            row.get("body") or b"",
            row.get("headers") or {},
            title=str(row.get("title") or ""),
        )
        if not sig:
            return None
        signals.append(sig)
        hashes.append(str(row.get("raw_hash") or row.get("normalized_hash") or ""))
    if len(set(signals)) != 1:
        return None
    # Prefer identical hashes when present; still treat as uniform if all checkpoint signals match
    nonempty = [h for h in hashes if h and h not in ("empty", "head-only")]
    if nonempty and len(set(nonempty)) > 1:
        # Different checkpoint bodies — still blocked, but not a single fingerprint
        return signals[0]
    return signals[0]


def enum_blocked_conclusion(*, signal: str, blocked_count: int, http_attempts: int = 0) -> str:
    label = {
        "vercel_security_checkpoint": "Vercel Security Checkpoint",
        "cloudflare_challenge": "Cloudflare challenge",
        "edge_security_checkpoint": "edge security checkpoint",
    }.get(signal or "", "edge security checkpoint")
    n = int(blocked_count or http_attempts or 0)
    return (
        f"Directory enumeration could not be assessed because candidate requests received "
        f"the same {label} response"
        + (f" ({n:,} blocked probe(s))" if n else "")
        + ". Confirmed enum hits: 0. Coverage is inconclusive — not a wildcard soft-404 calibration."
    )
