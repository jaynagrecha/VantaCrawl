"""Authorized-lab request stealth layer: browser impersonation, pacing, challenge awareness.

For systems you own or have explicit permission to test.
Does not solve CAPTCHAs or bypass managed bot challenges — it detects them and backs off.
"""

from __future__ import annotations

import asyncio
import random
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Browser impersonation profiles (Option A + aggressive variants for Option B)
# ---------------------------------------------------------------------------

BROWSER_PROFILES: Dict[str, Dict] = {
    "chrome": {
        "user_agents": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        ],
        "sec_ch_ua": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
        "sec_ch_ua_platform": '"Windows"',
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "accept_language": ["en-US,en;q=0.9", "en-GB,en;q=0.9", "en-US,en;q=0.8,es;q=0.6"],
        "accept_encoding": "gzip, deflate, br",
        "sec_fetch_site": "none",
        "sec_fetch_mode": "navigate",
        "sec_fetch_user": "?1",
        "sec_fetch_dest": "document",
        "upgrade_insecure_requests": "1",
    },
    "firefox": {
        "user_agents": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0",
            "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
        ],
        "sec_ch_ua": "",
        "sec_ch_ua_platform": "",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "accept_language": ["en-US,en;q=0.5", "en-GB,en;q=0.7,en;q=0.3"],
        "accept_encoding": "gzip, deflate, br",
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
        "sec_ch_ua_platform": "",
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
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
        ],
        "sec_ch_ua": '"Microsoft Edge";v="122", "Chromium";v="122", "Not(A:Brand";v="24"',
        "sec_ch_ua_platform": '"Windows"',
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        "accept_language": ["en-US,en;q=0.9"],
        "accept_encoding": "gzip, deflate, br",
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
    "access denied",
    "request blocked",
    "bot detection",
    "perimeterx",
    "datadome",
    "sucuri",
    "cloudproxy",
    "x-sucuri",
)

CHALLENGE_STATUS = {403, 429, 503}


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
                or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
                "Accept-Encoding": "gzip, deflate",
            }

        profile_name = self._session_profile
        if level == "aggressive" and self.config.ua_strategy == "rotate" and self._request_count % 17 == 0:
            profile_name = random.choice(list(BROWSER_PROFILES.keys()))
            self._session_profile = profile_name

        profile = BROWSER_PROFILES[profile_name]
        ua = self._select_ua(url, profile)

        headers: Dict[str, str] = {
            "User-Agent": ua,
            "Accept": profile["accept"],
            "Accept-Language": self._accept_language,
            "Accept-Encoding": profile["accept_encoding"],
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": profile["upgrade_insecure_requests"],
        }

        if profile.get("sec_ch_ua"):
            headers["Sec-CH-UA"] = profile["sec_ch_ua"]
            headers["Sec-CH-UA-Mobile"] = "?0" if "iPhone" not in ua else "?1"
            headers["Sec-CH-UA-Platform"] = profile["sec_ch_ua_platform"] or '"Windows"'

        if is_navigation and level in ("stealth", "aggressive"):
            site = "none"
            if self._last_url:
                prev = urlparse(self._last_url).netloc
                curr = urlparse(url).netloc
                site = "same-origin" if prev == curr else ("same-site" if _same_site(prev, curr) else "cross-site")
            headers["Sec-Fetch-Site"] = site
            headers["Sec-Fetch-Mode"] = profile["sec_fetch_mode"]
            headers["Sec-Fetch-User"] = profile["sec_fetch_user"]
            headers["Sec-Fetch-Dest"] = profile["sec_fetch_dest"]

        if self.config.referer_chain and self._last_url and level != "basic":
            if urlparse(self._last_url).netloc == urlparse(url).netloc:
                headers["Referer"] = self._last_url

        if level == "aggressive":
            # Occasional Cache-Control variance looks less like a fixed scanner fingerprint
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

    async def before_request(self, url: str) -> Dict[str, str]:
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

        headers = self.build_headers(url)
        return headers

    def after_request(self, url: str, status_code: int, body_preview: str = ""):
        self._last_url = url
        if not self.config.challenge_detect and not self.config.adaptive_backoff:
            return

        challenge = detect_challenge(status_code, body_preview)
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
            f"ua={self.config.ua_strategy}, challenges_seen={self._challenge_hits}"
        )


def detect_challenge(status_code: int, body: str) -> str:
    """Detect bot-wall / rate-limit signals that justify adaptive backoff.

    Only challenge/block HTTP statuses are considered. Success responses (200 etc.)
    must never trigger backoff — CDN headers like cf-ray on a normal page are not
    a challenge (that false positive used to park the whole crawl).
    """
    body_l = (body or "").lower()[:8000]
    if status_code == 429:
        return "rate_limit"
    if status_code not in CHALLENGE_STATUS:
        return ""
    for marker in CHALLENGE_MARKERS:
        if marker in body_l:
            return marker
    if status_code == 403 and ("cloudflare" in body_l or "cf-ray" in body_l):
        return "cloudflare_block"
    if status_code == 403:
        return "blocked"
    if status_code == 503:
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
        # Real body peek for challenge detection — never invent "cf-challenge" from
        # CDN headers alone (that caused false backoff on every Cloudflare 200).
        body_preview = ""
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
            session.after_request(url, response.status_code, body_preview)
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
