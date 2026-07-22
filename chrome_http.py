"""Scan HTTP client: Chrome TLS impersonation via curl_cffi, httpx fallback.

Authorized-lab traffic shaping — matches real Chrome JA3/HTTP2 when curl_cffi
is installed. Falls back to httpx[http2] if impersonation is unavailable.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace
from typing import Any, Dict, Mapping, Optional

import httpx

log = logging.getLogger(__name__)

# Closest curl_cffi profile to modern Chrome (~150). Keep UA major in sync.
DEFAULT_IMPERSONATE = "chrome146"
DEFAULT_CHROME_MAJOR = "146"

try:
    from curl_cffi.requests import AsyncSession as CurlAsyncSession
    from curl_cffi.requests.exceptions import RequestException as CurlRequestException

    HAS_CURL_CFFI = True
except Exception:  # pragma: no cover - optional dependency
    CurlAsyncSession = None  # type: ignore
    CurlRequestException = Exception  # type: ignore
    HAS_CURL_CFFI = False


class CompatResponse:
    """Minimal httpx-like response used across the crawler."""

    def __init__(self, status_code: int, headers: Mapping[str, str], content: bytes, url: str):
        self.status_code = int(status_code)
        self.headers = httpx.Headers(headers)
        self.content = content or b""
        self.request = SimpleNamespace(url=httpx.URL(url))
        self.url = httpx.URL(url)

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")


class StealthAsyncClient:
    """httpx-shaped async client backed by curl_cffi Chrome impersonation."""

    def __init__(
        self,
        session: Any,
        *,
        default_headers: Optional[Dict[str, str]] = None,
        impersonate: str = DEFAULT_IMPERSONATE,
        evasion=None,
        defense_tracker=None,
        output_callback=None,
    ):
        self._session = session
        self.headers: Dict[str, str] = dict(default_headers or {})
        self.impersonate = impersonate
        self.evasion = evasion
        self.defense_tracker = defense_tracker
        self.output_callback = output_callback

    async def __aenter__(self) -> "StealthAsyncClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        close = getattr(self._session, "close", None)
        if close is not None:
            result = close()
            if hasattr(result, "__await__"):
                await result

    async def get(self, url: str, **kwargs) -> CompatResponse:
        return await self.request("GET", url, **kwargs)

    async def head(self, url: str, **kwargs) -> CompatResponse:
        return await self.request("HEAD", url, **kwargs)

    async def post(self, url: str, **kwargs) -> CompatResponse:
        return await self.request("POST", url, **kwargs)

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Any = 30,
        follow_redirects: bool = True,
        allow_redirects: Optional[bool] = None,
        data: Any = None,
        json: Any = None,
        content: Any = None,
        **kwargs,
    ) -> CompatResponse:
        merged = dict(self.headers)
        if headers:
            merged.update(dict(headers))

        method_u = method.upper()
        # HEAD/OPTIONS/API probes must not claim document navigation — Akamai flags that.
        accept_l = (merged.get("Accept") or "").lower()
        is_navigation = method_u == "GET" and "application/json" not in accept_l
        if self.evasion is not None and getattr(self.evasion.config, "enabled", True):
            try:
                built = await self.evasion.before_request(str(url), is_navigation=is_navigation)
                # Prefer per-request stealth headers; keep explicit caller overrides
                for key, value in built.items():
                    if not headers or key not in headers:
                        merged[key] = value
            except Exception:
                log.debug("evasion before_request failed", exc_info=True)
        # Strip response-only / bot-tells that should never leave on requests
        for bad in ("Accept-CH", "accept-ch", "X-Requested-With", "x-requested-with"):
            merged.pop(bad, None)

        redirects = follow_redirects if allow_redirects is None else allow_redirects
        timeout_s = float(timeout if not isinstance(timeout, tuple) else timeout[0])

        try:
            raw = await self._session.request(
                method.upper(),
                str(url),
                headers=merged,
                timeout=timeout_s,
                allow_redirects=bool(redirects),
                data=data if content is None else content,
                json=json,
                impersonate=self.impersonate,
                **{k: v for k, v in kwargs.items() if k in ("proxy", "auth", "cookies", "verify")},
            )
        except CurlRequestException as exc:
            raise httpx.RequestError(str(exc), request=httpx.Request(method, str(url))) from exc
        except Exception as exc:
            raise httpx.RequestError(str(exc), request=httpx.Request(method, str(url))) from exc

        final_url = str(getattr(raw, "url", url) or url)
        body = raw.content if isinstance(getattr(raw, "content", None), (bytes, bytearray)) else (raw.content or b"")
        header_map = {str(k): str(v) for k, v in dict(getattr(raw, "headers", {}) or {}).items()}
        response = CompatResponse(int(raw.status_code), header_map, bytes(body), final_url)

        body_preview = ""
        try:
            body_preview = response.content[:2400].decode("utf-8", errors="ignore")
        except Exception:
            body_preview = ""

        if self.defense_tracker is not None:
            try:
                self.defense_tracker.record_response(
                    final_url, response.status_code, header_map, body_preview
                )
            except Exception:
                log.debug("defense record failed", exc_info=True)

        if self.evasion is not None and getattr(self.evasion.config, "enabled", True):
            try:
                before = self.evasion._challenge_hits
                self.evasion.after_request(
                    final_url, response.status_code, body_preview, headers=header_map
                )
                if (
                    self.output_callback
                    and self.evasion._challenge_hits > before
                    and self.evasion.last_challenge
                ):
                    wait = max(1, int(self.evasion.backoff_remaining() + 0.99))
                    self.output_callback(
                        f"Protection / challenge signal detected ({self.evasion.last_challenge}) — "
                        f"slowing down for a moment (~{wait}s)."
                    )
            except Exception:
                log.debug("evasion after_request failed", exc_info=True)

        return response


def chrome_impersonate_for_profile(browser_profile: str = "chrome") -> str:
    """TLS impersonation target.

    When Chrome TLS mode is on we always pin ``chrome146`` so Akamai sees one
    JA4/H2 stack. Mapping UA to firefox/safari TLS created mixed fingerprints
    (Safari JA4 ``t13d2014h2_a09f3c656075_…`` showed up beside Chrome).
    """
    _ = browser_profile  # UA profile is separate; TLS stays Chrome
    return DEFAULT_IMPERSONATE


# Stable JA4 for curl_cffi chrome146 (verified via tls.browserleaks.com)
CURL_CFFI_CHROME146_JA4 = "t13d1516h2_8daaf6152771_d8a2da3f94cd"
CURL_CFFI_CHROME146_AKAMAI_H2 = "52d84b11737d980aef856699f885ca86"


async def open_scan_client(
    *,
    config,
    evasion,
    default_headers: Dict[str, str],
    event_hooks=None,
    defense_tracker=None,
    output_callback=None,
):
    """Open the best available scan client (Chrome TLS → httpx fallback)."""
    use_chrome_tls = bool(getattr(config, "evasion_chrome_tls", True))
    use_http2 = bool(getattr(config, "evasion_http2", True))
    level = (getattr(config, "evasion_level", "") or "").lower()
    require_chrome_tls = use_chrome_tls and level in ("stealth", "aggressive", "basic")
    proxy = config.httpx_proxy() if hasattr(config, "httpx_proxy") else None
    auth = config.httpx_auth() if hasattr(config, "httpx_auth") else None
    cookie = (getattr(config, "cookie_string", "") or "").strip()
    headers = dict(default_headers or {})
    # Do NOT put a flattened multi-host Cookie on every request — BM cookie volume
    # is a Bot Manager tell. Seed cookies are applied per-URL via SessionCookieStore.
    start_url = str(getattr(config, "start_url", "") or "")
    if cookie and start_url:
        try:
            from session_cookies import SessionCookieStore

            seed = SessionCookieStore()
            seed.load_cookie_string(cookie, host=start_url)
            scoped = seed.header_for(start_url)
            if scoped:
                headers["Cookie"] = scoped
        except Exception:
            # Fall back: only if cookie string is small (manual paste for one host)
            if cookie.count("=") <= 12:
                headers["Cookie"] = cookie
    elif cookie and cookie.count("=") <= 12:
        headers["Cookie"] = cookie

    if use_chrome_tls and HAS_CURL_CFFI and CurlAsyncSession is not None:
        impersonate = chrome_impersonate_for_profile(getattr(evasion, "_session_profile", "chrome"))
        # Prefer HTTP/2 like real Chrome when enabled (curl_cffi negotiates via ALPN).
        session = CurlAsyncSession(
            impersonate=impersonate,
            headers=headers,
            proxy=proxy,
            http_version="v2" if use_http2 else "v1",
        )
        if output_callback and getattr(evasion.config, "enabled", True):
            output_callback(
                f"Chrome TLS pinned ({impersonate}) — expect Akamai JA4 "
                f"{CURL_CFFI_CHROME146_JA4} / H2 hash {CURL_CFFI_CHROME146_AKAMAI_H2}. "
                "Disable Chrome-first HTML if you need a single fingerprint (real Chrome adds another JA4)."
            )
        return StealthAsyncClient(
            session,
            default_headers=headers,
            impersonate=impersonate,
            evasion=evasion,
            defense_tracker=defense_tracker,
            output_callback=output_callback,
        )

    if use_chrome_tls and output_callback:
        output_callback(
            "Chrome TLS impersonation unavailable (install curl_cffi) — falling back to httpx "
            "(Akamai will see a non-browser JA4; install curl_cffi on the worker)."
        )
    if require_chrome_tls and not HAS_CURL_CFFI:
        # Stealth against Bot Manager without curl_cffi just advertises Python TLS.
        if output_callback:
            output_callback(
                "WARNING: stealth/basic/aggressive requested Chrome TLS but curl_cffi is missing. "
                "Traffic will not match Chrome JA4."
            )

    return httpx.AsyncClient(
        http2=use_http2,
        headers=headers,
        follow_redirects=True,
        proxy=proxy,
        auth=auth,
        event_hooks=event_hooks,
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
    )
