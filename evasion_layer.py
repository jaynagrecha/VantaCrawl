"""Authorized-lab request stealth layer: browser impersonation, pacing, challenge awareness.

For systems you own or have explicit permission to test.
Does not solve CAPTCHAs or bypass managed bot challenges — it detects them and backs off.
Pairs with chrome_http.curl_cffi TLS impersonation for JA3/HTTP2 alignment.
"""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

# Keep major version aligned with chrome_http.DEFAULT_IMPERSONATE (chrome146).
CHROME_MAJOR = "146"
CHROME_FULL = "146.0.7680.0"

# ---------------------------------------------------------------------------
# Browser impersonation profiles
# ---------------------------------------------------------------------------

BROWSER_PROFILES: Dict[str, Dict] = {
    "chrome": {
        # Windows-only when paired with curl_cffi chrome146 JA3 — Linux UA vs Win TLS
        # is a classic Akamai Bot Manager fingerprint mismatch.
        "user_agents": [
            f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{CHROME_MAJOR}.0.0.0 Safari/537.36",
            f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{CHROME_MAJOR}.0.0.0 Safari/537.36",
            f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{CHROME_MAJOR}.0.0.0 Safari/537.36",
        ],
        "sec_ch_ua": f'"Chromium";v="{CHROME_MAJOR}", "Not A(Brand";v="24", "Google Chrome";v="{CHROME_MAJOR}"',
        "sec_ch_ua_full_version_list": (
            f'"Chromium";v="{CHROME_FULL}", "Not A(Brand";v="10.0.0.0", "Google Chrome";v="{CHROME_FULL}"'
        ),
        "sec_ch_ua_full_version": f'"{CHROME_FULL}"',
        "sec_ch_ua_platform": '"Windows"',
        "sec_ch_ua_platform_version": '"15.0.0"',
        "sec_ch_ua_arch": '"x86"',
        "sec_ch_ua_bitness": '"64"',
        "sec_ch_ua_model": '""',
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "accept_language": ["en-US,en;q=0.9", "en-GB,en;q=0.9", "en-US,en;q=0.8,es;q=0.6"],
        "accept_encoding": "gzip, deflate, br, zstd",
        "sec_fetch_site": "none",
        "sec_fetch_mode": "navigate",
        "sec_fetch_user": "?1",
        "sec_fetch_dest": "document",
        "upgrade_insecure_requests": "1",
    },
    "firefox": {
        "user_agents": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:147.0) Gecko/20100101 Firefox/147.0",
        ],
        "sec_ch_ua": "",
        "sec_ch_ua_full_version_list": "",
        "sec_ch_ua_full_version": "",
        "sec_ch_ua_platform": "",
        "sec_ch_ua_platform_version": "",
        "sec_ch_ua_arch": "",
        "sec_ch_ua_bitness": "",
        "sec_ch_ua_model": "",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "accept_language": ["en-US,en;q=0.5", "en-GB,en;q=0.7,en;q=0.3"],
        "accept_encoding": "gzip, deflate, br, zstd",
        "sec_fetch_site": "none",
        "sec_fetch_mode": "navigate",
        "sec_fetch_user": "?1",
        "sec_fetch_dest": "document",
        "upgrade_insecure_requests": "1",
    },
    "safari": {
        "user_agents": [
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        ],
        "sec_ch_ua": "",
        "sec_ch_ua_full_version_list": "",
        "sec_ch_ua_full_version": "",
        "sec_ch_ua_platform": "",
        "sec_ch_ua_platform_version": "",
        "sec_ch_ua_arch": "",
        "sec_ch_ua_bitness": "",
        "sec_ch_ua_model": "",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept_language": ["en-US,en;q=0.9", "en-AU,en;q=0.8"],
        "accept_encoding": "gzip, deflate, br",
        "sec_fetch_site": "none",
        "sec_fetch_mode": "navigate",
        "sec_fetch_user": "?1",
        "sec_fetch_dest": "document",
        "upgrade_insecure_requests": "1",
    },
    "edge": {
        "user_agents": [
            f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{CHROME_MAJOR}.0.0.0 Safari/537.36 Edg/{CHROME_MAJOR}.0.0.0",
            f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{CHROME_MAJOR}.0.0.0 Safari/537.36 Edg/{CHROME_MAJOR}.0.0.0",
        ],
        "sec_ch_ua": f'"Microsoft Edge";v="{CHROME_MAJOR}", "Chromium";v="{CHROME_MAJOR}", "Not A(Brand";v="24"',
        "sec_ch_ua_full_version_list": (
            f'"Microsoft Edge";v="{CHROME_FULL}", "Chromium";v="{CHROME_FULL}", "Not A(Brand";v="10.0.0.0"'
        ),
        "sec_ch_ua_full_version": f'"{CHROME_FULL}"',
        "sec_ch_ua_platform": '"Windows"',
        "sec_ch_ua_platform_version": '"15.0.0"',
        "sec_ch_ua_arch": '"x86"',
        "sec_ch_ua_bitness": '"64"',
        "sec_ch_ua_model": '""',
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "accept_language": ["en-US,en;q=0.9"],
        "accept_encoding": "gzip, deflate, br, zstd",
        "sec_fetch_site": "none",
        "sec_fetch_mode": "navigate",
        "sec_fetch_user": "?1",
        "sec_fetch_dest": "document",
        "upgrade_insecure_requests": "1",
    },
}

LEVELS = ("off", "basic", "stealth", "aggressive")

CHALLENGE_MARKERS = (
    "cf-browser-verification",
    "cf-challenge",
    "challenge-platform",
    "just a moment",
    "attention required",
    "checking your browser",
    "enable javascript and cookies",
    "captcha",
    "hcaptcha",
    "recaptcha",
    "g-recaptcha",
    "akamai",
    "akamaighost",
    "edgesuite",
    "x-amzn-waf",
    "aws waf",
    # NOTE: bare "access denied" / "request blocked" are NOT challenge markers —
    # S3/Netlify permission pages use those strings. Matched only with WAF context below.
    "bot detection",
    "perimeterx",
    "datadome",
    "sucuri",
    "cloudproxy",
    "x-sucuri",
)

CHALLENGE_STATUS = {403, 429, 503}

# Hosts / servers that emit permission 403s without a bot wall
_STATIC_PERMISSION_SERVERS = (
    "netlify",
    "vercel",
    "github.com",
    "gitlab.io",
    "pages.dev",
    "cloudflare pages",
    "render.com",
    "heroku",
    "amazon s3",
    "amazons3",
)


@dataclass
class EvasionConfig:
    enabled: bool = True
    level: str = "stealth"  # off | basic | stealth | aggressive
    browser_profile: str = "chrome"  # chrome|firefox|safari|edge|random
    ua_strategy: str = "sticky_host"  # sticky_session | sticky_host | rotate
    jitter_min_ms: int = 50
    jitter_max_ms: int = 400
    referer_chain: bool = True
    language_rotate: bool = True
    adaptive_backoff: bool = True
    challenge_detect: bool = True
    decoy_requests: bool = False
    http2: bool = True
    chrome_tls: bool = True
    strip_python_hints: bool = True


@dataclass
class EvasionSession:
    config: EvasionConfig
    _session_ua: str = ""
    _session_profile: str = "chrome"
    _host_ua: Dict[str, str] = field(default_factory=dict)
    _last_url: str = ""
    _accept_language: str = "en-US,en;q=0.9"
    _backoff_until: float = 0.0
    _challenge_hits: int = 0
    _request_count: int = 0
    last_challenge: str = ""

    def __post_init__(self):
        self._session_profile = self._pick_profile_name()
        profile = BROWSER_PROFILES[self._session_profile]
        self._session_ua = random.choice(profile["user_agents"])
        if self.config.language_rotate:
            self._accept_language = random.choice(profile["accept_language"])
        else:
            self._accept_language = profile["accept_language"][0]

    def backoff_remaining(self) -> float:
        """Seconds left on adaptive WAF/rate-limit pause (0 if idle)."""
        return max(0.0, float(self._backoff_until) - time.time())

    def heartbeat_label(self) -> str:
        rem = self.backoff_remaining()
        if rem <= 0.4:
            return ""
        return f"Waiting on WAF backoff… {int(rem + 0.99)}s"

    def _pick_profile_name(self) -> str:
        name = (self.config.browser_profile or "chrome").lower()
        if name == "random":
            return random.choice(list(BROWSER_PROFILES.keys()))
        if name not in BROWSER_PROFILES:
            return "chrome"
        return name

    def effective_level(self) -> str:
        if not self.config.enabled:
            return "off"
        level = (self.config.level or "stealth").lower()
        return level if level in LEVELS else "stealth"

    def base_client_headers(self) -> Dict[str, str]:
        """Default headers for AsyncClient construction."""
        return self.build_headers(self._last_url or "https://localhost/")

    def build_headers(self, url: str, *, is_navigation: bool = True) -> Dict[str, str]:
        level = self.effective_level()
        if level == "off":
            return {
                "User-Agent": self._session_ua
                or (
                    f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    f"(KHTML, like Gecko) Chrome/{CHROME_MAJOR}.0.0.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
            }

        profile_name = self._session_profile
        if level == "aggressive" and self.config.ua_strategy == "rotate" and self._request_count % 17 == 0:
            profile_name = random.choice(list(BROWSER_PROFILES.keys()))
            self._session_profile = profile_name

        profile = BROWSER_PROFILES[profile_name]
        ua = self._select_ua(url, profile)
        # Prefer desktop Windows identity when Chrome TLS impersonation is on —
        # curl_cffi chrome146 JA3 is a Windows Chrome fingerprint.
        if self.config.chrome_tls and profile_name in ("chrome", "edge") and (
            "Linux" in ua or "X11" in ua or "Android" in ua
        ):
            ua = profile["user_agents"][0]
            self._session_ua = ua
        mobile = "?1" if ("iPhone" in ua or ("Android" in ua and "Mobile" in ua)) else "?0"
        platform = profile.get("sec_ch_ua_platform") or '"Windows"'
        platform_version = profile.get("sec_ch_ua_platform_version") or '"15.0.0"'
        if "Macintosh" in ua or "Mac OS X" in ua:
            platform = '"macOS"'
            platform_version = '"14.3.0"'
        elif "Linux" in ua or "X11" in ua:
            platform = '"Linux"'
            platform_version = '"6.5.0"'
        elif "iPhone" in ua:
            platform = '"iOS"'
            platform_version = '"17.2.0"'

        headers: Dict[str, str] = {
            "User-Agent": ua,
            "Accept": profile["accept"],
            "Accept-Language": self._accept_language,
            "Accept-Encoding": profile["accept_encoding"],
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": profile["upgrade_insecure_requests"],
            "Cache-Control": "max-age=0",
        }

        # Full Client Hints bundle (Chrome/Edge) — closes Akamai CH-missing rules
        if profile.get("sec_ch_ua"):
            headers["Sec-CH-UA"] = profile["sec_ch_ua"]
            headers["Sec-CH-UA-Mobile"] = mobile
            headers["Sec-CH-UA-Platform"] = platform
            if profile.get("sec_ch_ua_full_version_list"):
                headers["Sec-CH-UA-Full-Version-List"] = profile["sec_ch_ua_full_version_list"]
            if profile.get("sec_ch_ua_full_version"):
                headers["Sec-CH-UA-Full-Version"] = profile["sec_ch_ua_full_version"]
            headers["Sec-CH-UA-Platform-Version"] = platform_version
            if profile.get("sec_ch_ua_arch"):
                headers["Sec-CH-UA-Arch"] = profile["sec_ch_ua_arch"]
            if profile.get("sec_ch_ua_bitness"):
                headers["Sec-CH-UA-Bitness"] = profile["sec_ch_ua_bitness"]
            if "sec_ch_ua_model" in profile:
                headers["Sec-CH-UA-Model"] = profile.get("sec_ch_ua_model") or '""'
            # Do NOT send Accept-CH on requests — browsers only receive that header.

        # Always emit Sec-Fetch-* when stealth is on (basic included) — closes missing-header gaps
        site = "none"
        if self._last_url:
            prev = urlparse(self._last_url).netloc
            curr = urlparse(url).netloc
            site = "same-origin" if prev == curr else ("same-site" if _same_site(prev, curr) else "cross-site")
        if is_navigation:
            headers["Sec-Fetch-Site"] = site if self._last_url else "none"
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-User"] = "?1"
            headers["Sec-Fetch-Dest"] = "document"
        else:
            headers["Sec-Fetch-Site"] = site if self._last_url else "same-origin"
            headers["Sec-Fetch-Mode"] = "cors"
            headers["Sec-Fetch-Dest"] = "empty"
            headers.pop("Upgrade-Insecure-Requests", None)

        if self.config.referer_chain and self._last_url and level != "basic":
            if urlparse(self._last_url).netloc == urlparse(url).netloc:
                headers["Referer"] = self._last_url

        if level == "aggressive":
            if random.random() < 0.15:
                headers["Cache-Control"] = random.choice(["max-age=0", "no-cache"])
            if random.random() < 0.1:
                headers["DNT"] = "1"
            if self.config.language_rotate and random.random() < 0.08:
                self._accept_language = random.choice(profile["accept_language"])
                headers["Accept-Language"] = self._accept_language

        if self.config.strip_python_hints:
            for key in list(headers.keys()):
                if key.lower().startswith("x-python") or key.lower() == "x-requested-with":
                    headers.pop(key, None)

        return headers

    def _select_ua(self, url: str, profile: Dict) -> str:
        strategy = self.config.ua_strategy
        host = urlparse(url).netloc.lower()
        if strategy == "sticky_session" or self.effective_level() == "basic":
            return self._session_ua
        if strategy == "sticky_host":
            if host not in self._host_ua:
                self._host_ua[host] = random.choice(profile["user_agents"])
            return self._host_ua[host]
        # rotate
        if self.effective_level() == "aggressive" or self._request_count % 5 == 0:
            return random.choice(profile["user_agents"])
        return self._session_ua

    def jitter_range_ms(self) -> Tuple[int, int]:
        level = self.effective_level()
        lo, hi = self.config.jitter_min_ms, self.config.jitter_max_ms
        if level == "off":
            return 0, 0
        if level == "basic":
            return max(0, lo // 2), max(lo // 2, hi // 3)
        if level == "stealth":
            return lo, hi
        # aggressive — slower, more human-like
        return max(lo, 120), max(hi, 900)

    async def before_request(self, url: str, *, is_navigation: bool = True) -> Dict[str, str]:
        self._request_count += 1
        now = time.time()
        if self.config.adaptive_backoff and now < self._backoff_until:
            await asyncio.sleep(self._backoff_until - now)

        lo, hi = self.jitter_range_ms()
        if hi > 0:
            delay = random.uniform(lo, hi) / 1000.0
            # Occasional longer pause in aggressive mode
            if self.effective_level() == "aggressive" and random.random() < 0.04:
                delay += random.uniform(0.8, 2.5)
            await asyncio.sleep(delay)

        headers = self.build_headers(url, is_navigation=is_navigation)
        return headers

    def after_request(
        self,
        url: str,
        status_code: int,
        body_preview: str = "",
        headers: Optional[Dict[str, str]] = None,
    ):
        self._last_url = url
        if not self.config.challenge_detect and not self.config.adaptive_backoff:
            return

        challenge = detect_challenge(status_code, body_preview, headers=headers)
        if challenge:
            self._challenge_hits += 1
            self.last_challenge = challenge
            if self.config.adaptive_backoff:
                # Milder pauses so big WAF sites don't look "stuck" for 30–60s.
                # 429 / rate-limit still backs off harder than a plain WAF 403.
                hits = min(self._challenge_hits, 3)
                rate_limited = challenge == "rate_limit" or status_code == 429
                if rate_limited:
                    seconds = min(18.0, 1.0 * (2**hits))
                else:
                    # sucuri/cf/akamai hard blocks — short pacing, keep crawl moving
                    seconds = min(6.0, 0.5 * (2**hits))
                if self.effective_level() == "aggressive":
                    seconds = min(24.0 if rate_limited else 10.0, seconds * 1.25)
                self._backoff_until = time.time() + seconds
        elif status_code in (200, 204, 301, 302) and self._challenge_hits:
            # Cool down after success
            self._challenge_hits = max(0, self._challenge_hits - 1)

    def decoy_paths(self) -> List[str]:
        if not self.config.decoy_requests or self.effective_level() != "aggressive":
            return []
        return [
            "/favicon.ico",
            "/robots.txt",
            "/",
            "/css/style.css",
            "/js/app.js",
        ]

    def summary(self) -> str:
        return (
            f"Stealth: level={self.effective_level()}, browser={self._session_profile}, "
            f"ua={self.config.ua_strategy}, challenges_seen={self._challenge_hits}, "
            f"chrome_tls={self.config.chrome_tls}"
        )


def _header_map(headers: Optional[Dict[str, str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not headers:
        return out
    try:
        for key, value in dict(headers).items():
            out[str(key).lower()] = str(value)
    except Exception:
        pass
    return out


def is_permission_or_storage_deny(
    status_code: int,
    body: str = "",
    headers: Optional[Dict[str, str]] = None,
) -> bool:
    """True for S3/Netlify/generic Access Denied — not a bot-wall challenge.

    These must not arm WAF backoff or force Chrome escalation; the crawl should
    skip the path and keep moving.
    """
    if status_code not in (401, 403, 405):
        return False
    headers_l = _header_map(headers)
    server = (headers_l.get("server") or "").lower()
    body_l = (body or "").lower()[:8000]
    header_blob = " ".join(f"{k}:{v}" for k, v in headers_l.items())
    combined = f"{body_l}\n{header_blob}\n{server}"

    # Real bot / WAF walls — never treat as soft permission deny
    bot_tokens = (
        "akamaighost",
        "edgesuite",
        "errors.edgesuite.net",
        "x-amzn-waf",
        "aws waf",
        "cf-ray",
        "cf-mitigated",
        "challenge-platform",
        "datadome",
        "perimeterx",
        "sucuri",
    )
    if any(tok in combined for tok in bot_tokens):
        return False
    if "akamai" in server or "cloudflare" in server:
        return False

    if any(tok in server for tok in _STATIC_PERMISSION_SERVERS):
        return True
    # S3 XML error body (often behind CloudFront with Server: AmazonS3)
    compact = body_l.replace(" ", "")
    if "<error>" in body_l and "accessdenied" in compact:
        return True
    if "access denied" in body_l or "request blocked" in body_l:
        # Generic deny copy with no bot markers above
        return True
    return False


def detect_challenge(
    status_code: int,
    body: str = "",
    headers: Optional[Dict[str, str]] = None,
) -> str:
    """Detect bot-wall / rate-limit signals that justify adaptive backoff.

    Requires WAF/challenge evidence (body markers or known WAF response headers).
    Bare HTTP 403 from static hosts (Netlify/Vercel/S3 permission denials, missing
    files) must NOT arm WAF backoff — that was parking enum scans with
    Protections=none and Blocks climbing on every 403.
    """
    body_l = (body or "").lower()[:8000]
    headers_l = _header_map(headers)
    header_blob = " ".join(f"{k}:{v}" for k, v in headers_l.items())
    combined = f"{body_l}\n{header_blob}"
    server_l = (headers_l.get("server") or "").lower()

    if status_code == 429:
        return "rate_limit"

    # Permission / object-storage denies — never a challenge
    if is_permission_or_storage_deny(status_code, body, headers):
        return ""

    soft_denied = (
        ("access denied" in body_l and ("akamai" in body_l or "edgesuite" in body_l or "reference #" in body_l))
        or ("errors.edgesuite.net" in body_l)
        or ("akamaighost" in body_l and "denied" in body_l)
        or ("attention required" in body_l and "cloudflare" in body_l)
        or ("checking your browser before accessing" in body_l)
    )
    if status_code == 200 and soft_denied:
        if "akamai" in body_l or "edgesuite" in body_l or "akamaighost" in body_l:
            return "akamai_soft_deny"
        if "cloudflare" in body_l:
            return "cloudflare_soft_deny"
        return "soft_deny"

    if status_code not in CHALLENGE_STATUS:
        return ""

    is_static_paas = any(tok in server_l or tok in header_blob for tok in _STATIC_PERMISSION_SERVERS)

    for marker in CHALLENGE_MARKERS:
        if marker in body_l or marker in header_blob or marker in server_l:
            if is_static_paas and marker in ("access denied", "request blocked"):
                continue
            return marker
    # Explicit generic deny phrases only count with bot context (already handled above)
    if "access denied" in body_l or "request blocked" in body_l:
        if any(
            w in combined
            for w in (
                "cloudflare",
                "cf-ray",
                "akamai",
                "akamaighost",
                "edgesuite",
                "sucuri",
                "datadome",
                "perimeterx",
                "x-amzn-waf",
            )
        ):
            if "akamai" in combined or "akamaighost" in combined or "edgesuite" in combined:
                return "akamai_block"
            if "cloudflare" in combined or "cf-ray" in combined:
                return "cloudflare_block"
            return "waf_block"
        return ""
    if status_code == 403 and ("cloudflare" in combined or "cf-ray" in combined):
        return "cloudflare_block"
    if status_code == 403 and any(
        x in combined for x in ("akamai", "edgesuite", "akamaighost")
    ):
        return "akamai_block"
    if status_code == 403 and any(x in combined for x in ("sucuri", "cloudproxy", "x-sucuri")):
        return "sucuri"
    if status_code == 403 and any(x in combined for x in ("datadome", "perimeterx", "x-amzn-waf", "aws waf")):
        return "waf_block"
    # Bare 403/503 with no WAF evidence — common for Netlify/authz/missing files.
    # Do NOT arm adaptive WAF backoff.
    if status_code == 503 and any(
        x in combined for x in ("cloudflare", "akamai", "sucuri", "checking your browser")
    ):
        return "unavailable"
    return ""


def _same_site(a: str, b: str) -> bool:
    a = a.lower().split(":")[0]
    b = b.lower().split(":")[0]
    if a == b:
        return True
    parts_a = a.split(".")
    parts_b = b.split(".")
    if len(parts_a) >= 2 and len(parts_b) >= 2:
        return parts_a[-2:] == parts_b[-2:]
    return False


def _evasion_config_from_crawl(config) -> EvasionConfig:
    level = getattr(config, "evasion_level", "stealth") or "stealth"
    enabled = bool(getattr(config, "evasion_enabled", True)) and level != "off"
    econf = EvasionConfig(
        enabled=enabled,
        level=level if enabled else "off",
        browser_profile=getattr(config, "evasion_browser", "chrome") or "chrome",
        ua_strategy=getattr(config, "evasion_ua_strategy", "sticky_host") or "sticky_host",
        jitter_min_ms=int(getattr(config, "evasion_jitter_min_ms", 50) or 0),
        jitter_max_ms=int(getattr(config, "evasion_jitter_max_ms", 400) or 0),
        referer_chain=bool(getattr(config, "evasion_referer_chain", True)),
        language_rotate=bool(getattr(config, "evasion_language_rotate", True)),
        adaptive_backoff=bool(getattr(config, "evasion_adaptive_backoff", True)),
        challenge_detect=bool(getattr(config, "evasion_challenge_detect", True)),
        decoy_requests=bool(getattr(config, "evasion_decoy_requests", False)),
        http2=bool(getattr(config, "evasion_http2", True)),
        chrome_tls=bool(getattr(config, "evasion_chrome_tls", True)),
        strip_python_hints=True,
    )
    if econf.level == "basic":
        econf.jitter_min_ms = min(econf.jitter_min_ms, 20)
        econf.jitter_max_ms = min(econf.jitter_max_ms, 120)
        econf.decoy_requests = False
    elif econf.level == "aggressive":
        econf.jitter_min_ms = max(econf.jitter_min_ms, 100)
        econf.jitter_max_ms = max(econf.jitter_max_ms, 800)
        econf.referer_chain = True
        econf.adaptive_backoff = True
        econf.challenge_detect = True
    return econf


def evasion_from_crawl_config(config) -> EvasionSession:
    return EvasionSession(_evasion_config_from_crawl(config))


def sync_evasion_from_crawl_config(session: EvasionSession, config) -> None:
    """Update a live evasion session after Pause → change settings → Resume."""
    fresh = _evasion_config_from_crawl(config)
    session.config = fresh
    # Keep sticky UA; only switch browser profile if user changed it to a concrete name
    name = (fresh.browser_profile or "chrome").lower()
    if name != "random" and name in BROWSER_PROFILES and name != session._session_profile:
        session._session_profile = name
        session._session_ua = random.choice(BROWSER_PROFILES[name]["user_agents"])


def apply_headers_to_request(request, headers: Dict[str, str]):
    for key, value in headers.items():
        request.headers[key] = value


def make_httpx_hooks(session: Optional[EvasionSession] = None, output_callback=None, defense_tracker=None):
    """httpx event hooks for async client (stealth pacing + defense scoring)."""

    request_hooks = []
    response_hooks = []

    if session is not None:

        async def on_request(request):
            if not session.config.enabled:
                return
            url = str(request.url)
            headers = await session.before_request(url)
            apply_headers_to_request(request, headers)

        request_hooks.append(on_request)

    async def on_response(response):
        url = str(response.request.url)
        header_map = dict(response.headers)
        # Real body peek only when status can be a challenge/error — skip decoding every 200.
        body_preview = ""
        if response.status_code in CHALLENGE_STATUS or response.status_code >= 400:
            try:
                raw = response.content or b""
                body_preview = raw[:2400].decode("utf-8", errors="ignore")
            except Exception:
                body_preview = ""

        if defense_tracker is not None:
            # Headers fingerprint protections; body used for challenge/block scoring
            defense_tracker.record_response(url, response.status_code, header_map, body_preview)

        if session is not None and session.config.enabled:
            before = session._challenge_hits
            session.after_request(url, response.status_code, body_preview, headers=header_map)
            if output_callback and session._challenge_hits > before and session.last_challenge:
                wait = max(1, int(session.backoff_remaining() + 0.99))
                output_callback(
                    f"Protection / challenge signal detected ({session.last_challenge}) — "
                    f"slowing down for a moment (~{wait}s)."
                )

    response_hooks.append(on_response)
    hooks = {}
    if request_hooks:
        hooks["request"] = request_hooks
    if response_hooks:
        hooks["response"] = response_hooks
    return hooks or None


async def run_decoy_warmup(client, base_url: str, session: EvasionSession, output_callback=None):
    paths = session.decoy_paths()
    if not paths:
        return
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    if output_callback:
        output_callback("Warming up with a few ordinary-looking page requests…")
    for path in paths:
        if not session.config.enabled:
            break
        url = origin + path
        try:
            await client.get(url, timeout=8, follow_redirects=True)
        except Exception:
            continue


def pick_user_agent_for_selenium(config=None) -> str:
    if config is None:
        profile = BROWSER_PROFILES["chrome"]
        return random.choice(profile["user_agents"])
    session = evasion_from_crawl_config(config)
    return session._session_ua
