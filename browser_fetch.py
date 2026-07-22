"""Headless Chrome helpers shared by desktop GUI and web worker (no Qt).

Supports:
- browser_primary: Chrome-first HTML navigations
- browser_on_challenge: HTTP first, escalate to Chrome on WAF/challenge
- auto_sync_cookies: push browser cookies into the HTTP client jar (per-host)
"""

from __future__ import annotations

import asyncio
import os
import shutil
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Optional, Tuple

import httpx

from auth_login import selenium_login
from crawler_common import get_random_user_agent, is_html_url
from evasion_layer import detect_challenge, is_permission_or_storage_deny, pick_user_agent_for_selenium
from session_cookies import SessionCookieStore

_executor = ThreadPoolExecutor(max_workers=1)
_selenium_driver = None
_driver_ua = ""
_chrome_probe: Optional[Tuple[bool, str]] = None
_chrome_skip_logged = False

DOM_LINKS_SCRIPT = """
const out = [];
const attrs = ['href','src','poster','action','data-src','data-href','data-url','data-background'];
document.querySelectorAll('[href],[src],[srcset],[poster],[action],[data-src],[data-href],[data-url]').forEach(el => {
  attrs.forEach(attr => {
    const value = el.getAttribute(attr);
    if (value) out.push(value);
  });
});
return out;
"""

# Akamai Bot Manager client cookies — presence means the sensor ran far enough to set state.
# Missing these after a Chrome navigation → Akamai often logs "javascript fingerprint not
# received" / "Client Disabled Javascript (NoScript Triggered)" for later HTTP traffic.
BM_COOKIE_NAMES = ("_abck", "bm_sz", "ak_bmsc", "bm_sv", "bm_mi", "bm_so")
BM_PAGE_MARKERS = (
    "akamai",
    "_abck",
    "bmak.",
    "bm_sz",
    "ak_bmsc",
    "edgesuite",
    "sec-cpt",
    "challenge-platform",
    "cf-browser-verification",
)


def bm_cookie_names_present(cookies) -> list[str]:
    """Return which BM cookie names appear in a Selenium cookie list or name→value map."""
    names: set[str] = set()
    if isinstance(cookies, dict):
        names = {str(k).lower() for k in cookies.keys()}
    else:
        for row in cookies or []:
            if isinstance(row, dict):
                names.add(str(row.get("name") or "").lower())
            else:
                names.add(str(row).lower())
    return [n for n in BM_COOKIE_NAMES if n in names]


def page_suggests_bot_manager(html: str) -> bool:
    low = (html or "").lower()
    return any(m in low for m in BM_PAGE_MARKERS)


def _seed_driver_cookies(driver, url: str, cookie_header: str) -> int:
    """Push `a=b; c=d` into Chrome before navigation via CDP (best-effort)."""
    raw = (cookie_header or "").strip()
    if not raw:
        return 0
    try:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        host = (parsed.hostname or "").strip()
        if not host:
            return 0
        secure = (parsed.scheme or "https").lower() == "https"
        seeded = 0
        for part in raw.split(";"):
            part = part.strip()
            if not part or "=" not in part:
                continue
            name, value = part.split("=", 1)
            name = name.strip()
            if not name:
                continue
            payload = {
                "name": name,
                "value": value.strip(),
                "domain": host,
                "path": "/",
                "secure": secure,
            }
            try:
                driver.execute_cdp_cmd("Network.setCookie", payload)
                seeded += 1
            except Exception:
                try:
                    # Fallback: some drivers want url instead of domain
                    payload2 = {
                        "name": name,
                        "value": value.strip(),
                        "url": f"{parsed.scheme}://{host}/",
                        "path": "/",
                    }
                    driver.execute_cdp_cmd("Network.setCookie", payload2)
                    seeded += 1
                except Exception:
                    continue
        return seeded
    except Exception:
        return 0


def _wait_for_bm_cookies(driver, *, timeout_seconds: float) -> list[str]:
    """Poll document cookies until at least one BM cookie appears or timeout."""
    deadline = time.time() + max(0.0, float(timeout_seconds or 0))
    found: list[str] = []
    while time.time() < deadline:
        try:
            rows = driver.get_cookies() or []
        except Exception:
            rows = []
        found = bm_cookie_names_present(rows)
        if found:
            return found
        # Also check document.cookie in case HttpOnly lags get_cookies
        try:
            doc = driver.execute_script("return document.cookie || '';") or ""
            for name in BM_COOKIE_NAMES:
                if f"{name}=" in doc and name not in found:
                    found.append(name)
            if found:
                return found
        except Exception:
            pass
        time.sleep(0.35)
    return found


def _candidate_chrome_bins() -> list[str]:
    env_bins = [
        os.environ.get("CHROME_BIN"),
        os.environ.get("GOOGLE_CHROME_BIN"),
        os.environ.get("CHROMIUM_PATH"),
    ]
    cache = os.path.expanduser("~/.cache/vantacrawl-chrome")
    path_file = os.path.join(cache, "chrome_bin.path")
    if os.path.isfile(path_file):
        try:
            with open(path_file, encoding="utf-8") as handle:
                env_bins.append(handle.read().strip())
        except OSError:
            pass
    which = [
        shutil.which("google-chrome"),
        shutil.which("google-chrome-stable"),
        shutil.which("chromium"),
        shutil.which("chromium-browser"),
        shutil.which("chrome"),
    ]
    fixed = [
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    ]
    out = []
    for item in env_bins + which + fixed:
        if item and item not in out:
            out.append(item)
    return out


def probe_chrome() -> Tuple[bool, str]:
    """Return (available, detail). Result is cached for the process."""
    global _chrome_probe
    if _chrome_probe is not None:
        return _chrome_probe
    for path in _candidate_chrome_bins():
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            _chrome_probe = (True, path)
            return _chrome_probe
        # Windows executables are "accessible" without X_OK semantics
        if path and os.path.isfile(path):
            _chrome_probe = (True, path)
            return _chrome_probe
    _chrome_probe = (False, "Chrome/Chromium binary not found")
    return _chrome_probe


def chrome_available() -> bool:
    return probe_chrome()[0]


def reset_chrome_probe_cache() -> None:
    """Test helper."""
    global _chrome_probe, _chrome_skip_logged
    _chrome_probe = None
    _chrome_skip_logged = False


def _chromedriver_service():
    from selenium.webdriver.chrome.service import Service as ChromeService

    driver_path = os.environ.get("CHROMEDRIVER_PATH") or os.environ.get("CHROMEDRIVER")
    cache = os.path.expanduser("~/.cache/vantacrawl-chrome")
    path_file = os.path.join(cache, "chromedriver.path")
    if not driver_path and os.path.isfile(path_file):
        try:
            with open(path_file, encoding="utf-8") as handle:
                driver_path = handle.read().strip()
        except OSError:
            driver_path = None
    kwargs = {}
    if driver_path and os.path.isfile(driver_path):
        kwargs["executable_path"] = driver_path
    try:
        return ChromeService(log_output=os.devnull, **kwargs)
    except TypeError:
        try:
            return ChromeService(**kwargs)
        except TypeError:
            return ChromeService()


def get_selenium_driver(proxy_url: str = "", user_agent: str = ""):
    global _selenium_driver, _driver_ua
    ua = (user_agent or "").strip() or get_random_user_agent()

    if _selenium_driver is not None:
        # Recreate if UA policy changed (keeps browser UA aligned with sticky stealth UA)
        if ua and _driver_ua and ua != _driver_ua:
            quit_selenium_driver()
        else:
            return _selenium_driver

    ok, detail = probe_chrome()
    if not ok:
        raise RuntimeError(f"Browser automation unavailable: {detail}")

    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options

    options = Options()
    options.binary_location = detail
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument(f"user-agent={ua}")
    # Reduce obvious automation flags where possible
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option("useAutomationExtension", False)
    options.add_argument("--window-size=1280,720")
    if proxy_url:
        options.add_argument(f"--proxy-server={proxy_url}")
    service = _chromedriver_service()
    _selenium_driver = webdriver.Chrome(service=service, options=options)
    _selenium_driver.set_page_load_timeout(30)
    _selenium_driver.set_script_timeout(20)
    _driver_ua = ua
    try:
        _selenium_driver.execute_cdp_cmd(
            "Page.addScriptToEvaluateOnNewDocument",
            {"source": "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"},
        )
    except Exception:
        pass
    return _selenium_driver


def fetch_with_selenium(
    url,
    settle_seconds=2,
    proxy_url="",
    screenshot_path=None,
    user_agent: str = "",
    *,
    cookie_header: str = "",
    bm_wait_seconds: float = 12.0,
    bm_post_settle_seconds: float = 1.5,
):
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.support.ui import WebDriverWait

    driver = get_selenium_driver(proxy_url, user_agent=user_agent)
    try:
        driver.execute_cdp_cmd("Network.enable", {})
    except Exception:
        pass
    if cookie_header:
        _seed_driver_cookies(driver, url, cookie_header)
    try:
        driver.get(url)
    except Exception:
        # PageLoadTimeout / WebDriverException — still try to scrape whatever loaded
        pass
    try:
        WebDriverWait(driver, 15).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
    except Exception:
        pass

    html_preview = ""
    try:
        html_preview = driver.page_source or ""
    except Exception:
        html_preview = ""

    bm_found: list[str] = []
    needs_bm_wait = page_suggests_bot_manager(html_preview) or float(bm_wait_seconds or 0) > 0
    if needs_bm_wait and float(bm_wait_seconds or 0) > 0:
        # Always give BM sensor time on Chrome-first navigations — interstitial HTML
        # may not include obvious markers until scripts run.
        bm_found = _wait_for_bm_cookies(driver, timeout_seconds=float(bm_wait_seconds))
        if bm_found and float(bm_post_settle_seconds or 0) > 0:
            time.sleep(min(float(bm_post_settle_seconds), 5.0))
    elif settle_seconds:
        time.sleep(min(float(settle_seconds), 5.0))

    if screenshot_path:
        os.makedirs(os.path.dirname(screenshot_path), exist_ok=True)
        driver.save_screenshot(screenshot_path)
    try:
        dom_urls = driver.execute_script(DOM_LINKS_SCRIPT) or []
    except Exception:
        dom_urls = []
    try:
        cookies = driver.get_cookies() or []
    except Exception:
        cookies = []
    if not bm_found:
        bm_found = bm_cookie_names_present(cookies)
    try:
        page_html = driver.page_source or ""
    except Exception:
        page_html = html_preview
    return page_html, cookies, dom_urls, bm_found


def quit_selenium_driver() -> None:
    global _selenium_driver, _driver_ua
    if _selenium_driver is not None:
        try:
            _selenium_driver.quit()
        except Exception:
            pass
        _selenium_driver = None
        _driver_ua = ""


def _response_looks_challenged(
    status_code: int,
    body_text: str,
    headers: Optional[dict] = None,
) -> bool:
    """True only for real bot-wall / rate-limit challenges.

    Bare 403 Access Denied (S3/Netlify/permission) must NOT escalate to Chrome
    or look like a WAF block — that was stalling crawls on every missing path.
    """
    if is_permission_or_storage_deny(status_code, body_text or "", headers):
        return False
    if detect_challenge(status_code, body_text or "", headers=headers):
        return True
    if status_code == 429:
        return True
    low = (body_text or "").lower()
    # Soft interstitials sometimes return 200
    markers = (
        "attention required",
        "checking your browser",
        "cf-browser-verification",
        "challenge-platform",
    )
    return any(m in low for m in markers)


def make_browser_fetcher(
    config,
    reporter=None,
    cookie_store: Optional[SessionCookieStore] = None,
    output: Optional[Callable[[str], Any]] = None,
):
    store = cookie_store or SessionCookieStore()
    if getattr(config, "cookie_string", ""):
        store.load_cookie_string(config.cookie_string, host=getattr(config, "start_url", "") or "")

    auto_cookies = bool(getattr(config, "auto_sync_cookies", True))
    # Re-read primary/challenge flags per request so mid-scan BM → Chrome-first takes effect.
    on_challenge_default = bool(
        getattr(config, "browser_on_challenge", True) or getattr(config, "selenium_fallback", False)
    )
    _bm_cookie_warn_hosts: set[str] = set()

    def _ua_for(url: str) -> str:
        try:
            return pick_user_agent_for_selenium(config)
        except Exception:
            return get_random_user_agent()

    async def _selenium_fetch(url: str, screenshot_path=None) -> Tuple[str, list, list, list]:
        loop = asyncio.get_running_loop()
        cookie_header = ""
        if bool(getattr(config, "auto_sync_cookies", True)):
            cookie_header = store.header_for(url) or store.as_cookie_string()
        bm_wait = float(getattr(config, "bm_cookie_wait_seconds", 12.0) or 0)
        bm_settle = float(getattr(config, "bm_post_cookie_settle_seconds", 1.5) or 0)
        # Overall timeout must cover BM wait + page load
        overall = max(45.0, 25.0 + bm_wait + bm_settle)
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(
                    _executor,
                    lambda: fetch_with_selenium(
                        url,
                        2,
                        getattr(config, "proxy_url", "") or "",
                        screenshot_path,
                        _ua_for(url),
                        cookie_header=cookie_header,
                        bm_wait_seconds=bm_wait,
                        bm_post_settle_seconds=bm_settle,
                    ),
                ),
                timeout=overall,
            )
        except asyncio.TimeoutError as exc:
            quit_selenium_driver()
            raise TimeoutError(f"Browser fetch timed out for {url}") from exc

    def _sync_cookies(
        client,
        url: str,
        cookies: list,
        output_note: Optional[Callable[[str], None]] = None,
        *,
        bm_found: Optional[list] = None,
    ):
        if not bool(getattr(config, "auto_sync_cookies", True)):
            return
        changed, new_names, _changed_names = store.ingest_selenium_cookies(cookies, url)
        header = store.apply_to_client(client, url)
        if header:
            config.cookie_string = store.as_cookie_string()
        present = list(bm_found or []) or bm_cookie_names_present(cookies)
        host = _host_label(url)
        if output_note:
            # Only log *new* cookie names — BM cookies mutate every page and spam the log
            if new_names:
                output_note(
                    f"Synced {len(new_names)} new browser cookie(s) into HTTP jar "
                    f"for {host}: {', '.join(new_names[:12])}"
                    + ("…" if len(new_names) > 12 else "")
                )
            elif changed and host not in _bm_cookie_warn_hosts and present:
                # First successful BM-ready sync acknowledgment (once per host)
                output_note(
                    f"BM cookies on HTTP jar after Chrome: {', '.join(present)}"
                )
                _bm_cookie_warn_hosts.add(host)
            elif not present and host not in _bm_cookie_warn_hosts:
                _bm_cookie_warn_hosts.add(host)
                output_note(
                    "Chrome finished HTML load but no Akamai BM cookies "
                    "(_abck/bm_sz/ak_bmsc) were set — sensor likely incomplete "
                    "(headless fingerprint / script blocked). HTTP follow-ups may "
                    "still be scored as NoScript / JS fingerprint missing."
                )

    async def browser_page_fetcher(client, url, deep_render=False):
        global _chrome_skip_logged
        browser_primary = bool(
            getattr(config, "browser_primary", False) or getattr(config, "deep_mirror", False)
        )
        on_challenge = bool(
            getattr(config, "browser_on_challenge", True)
            or getattr(config, "selenium_fallback", False)
            or on_challenge_default
        )
        # Capability-preserving hybrid: Chrome until BM cookies exist, then HTTP-first
        # with challenge escalate (recovers pages/min without dropping browser power).
        http_first_ready = bool(getattr(config, "http_first_when_bm_ready", True))
        bm_ready = False
        if http_first_ready and browser_primary and not getattr(config, "deep_mirror", False):
            try:
                hdr = store.header_for(url) or ""
                names = {}
                for part in hdr.split(";"):
                    part = part.strip()
                    if "=" in part:
                        names[part.split("=", 1)[0].strip()] = "1"
                bm_ready = bool(bm_cookie_names_present(names))
            except Exception:
                bm_ready = False
        force_browser = bool(deep_render or (browser_primary and not bm_ready))
        if getattr(config, "deep_mirror", False):
            force_browser = True
        screenshot_path = None
        if getattr(config, "screenshot_capture", False) and reporter and is_html_url(url):
            screenshot_path = reporter.screenshot_path(url)

        # Keep HTTP client cookie header fresh for this host before any probe
        if bool(getattr(config, "auto_sync_cookies", True)):
            store.apply_to_client(client, url)

        if not force_browser:
            try:
                response = await client.get(url, timeout=15, follow_redirects=True)
                body_text = ""
                try:
                    body_text = response.text
                except Exception:
                    body_text = (response.content or b"").decode("utf-8", errors="replace")
                challenged = _response_looks_challenged(
                    response.status_code,
                    body_text,
                    headers=dict(response.headers) if response.headers is not None else None,
                )
                if not challenged and 200 <= response.status_code < 400:
                    # Opportunistic Set-Cookie capture from HTTP path
                    if bool(getattr(config, "auto_sync_cookies", True)):
                        _ingest_set_cookie_headers(store, url, response.headers)
                        store.apply_to_client(client, url)
                        config.cookie_string = store.as_cookie_string()
                    return body_text, []
                if not on_challenge:
                    response.raise_for_status()
                    return body_text, []
                # Escalate to real Chrome
            except (httpx.HTTPError, OSError, ValueError):
                if not on_challenge and not force_browser:
                    raise

        if not chrome_available():
            if output and not _chrome_skip_logged:
                _chrome_skip_logged = True
                _, detail = probe_chrome()
                output(
                    f"Browser render skipped — {detail}. "
                    "Install Chrome/Chromium or set CHROME_BIN; continuing with HTTP only."
                )
            response = await client.get(url, timeout=20, follow_redirects=True)
            response.raise_for_status()
            return response.text, []

        try:
            page_html, cookies, dom_urls, bm_found = await _selenium_fetch(
                url, screenshot_path=screenshot_path
            )
        except Exception:
            if force_browser:
                raise
            # Challenge escalation failed (no Chrome / timeout) — caller continues via HTTP
            return "", []
        _sync_cookies(client, url, cookies, output_note=output, bm_found=bm_found)
        return page_html, dom_urls or []

    # Expose store for orchestrator / tests
    browser_page_fetcher.cookie_store = store  # type: ignore[attr-defined]
    return browser_page_fetcher


def _host_label(url: str) -> str:
    try:
        from urllib.parse import urlparse

        return urlparse(url).netloc or url
    except Exception:
        return url


def _ingest_set_cookie_headers(store: SessionCookieStore, url: str, headers) -> None:
    try:
        # httpx Headers may have multiple set-cookie
        raw_list = []
        get_list = getattr(headers, "get_list", None)
        if callable(get_list):
            raw_list = get_list("set-cookie") or []
        else:
            headers_l = {str(key).lower(): value for key, value in headers.items()}
            one = headers_l.get("set-cookie")
            if one:
                raw_list = [one]
        for item in raw_list:
            # name=value; Path=...
            first = str(item).split(";", 1)[0]
            if "=" in first:
                name, value = first.split("=", 1)
                store.ingest_selenium_cookies(
                    [{"name": name.strip(), "value": value.strip(), "domain": _host_label(url)}],
                    url,
                )
    except Exception:
        pass


def apply_selenium_login(config, output: Optional[Callable[[str], Any]] = None, cookie_store: Optional[SessionCookieStore] = None):
    if not config.use_selenium_login or not config.login_url:
        return config
    if not chrome_available():
        if output:
            _, detail = probe_chrome()
            output(f"Browser login skipped — {detail}")
        return config
    if output:
        output("Running browser login to capture cookies…")
    ua = ""
    try:
        ua = pick_user_agent_for_selenium(config)
    except Exception:
        ua = ""
    cookies, message = selenium_login(
        config.login_url,
        config.login_username,
        config.login_password,
        driver_factory=lambda: get_selenium_driver(config.proxy_url, user_agent=ua),
    )
    if output:
        output(message)
    if cookies:
        config.cookie_string = cookies
        store = cookie_store or SessionCookieStore()
        store.load_cookie_string(cookies, host=config.login_url or config.start_url)
        config.cookie_string = store.as_cookie_string() or cookies
    return config
