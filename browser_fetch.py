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


def fetch_with_selenium(url, settle_seconds=2, proxy_url="", screenshot_path=None, user_agent: str = ""):
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.support.ui import WebDriverWait

    driver = get_selenium_driver(proxy_url, user_agent=user_agent)
    try:
        driver.get(url)
    except Exception:
        # PageLoadTimeout / WebDriverException — still try to scrape whatever loaded
        pass
    try:
        WebDriverWait(driver, 15).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
    except Exception:
        pass
    if settle_seconds:
        time.sleep(min(float(settle_seconds), 3.0))
    if screenshot_path:
        os.makedirs(os.path.dirname(screenshot_path), exist_ok=True)
        driver.save_screenshot(screenshot_path)
    try:
        dom_urls = driver.execute_script(DOM_LINKS_SCRIPT) or []
    except Exception:
        dom_urls = []
    return driver.page_source, driver.get_cookies(), dom_urls


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
    browser_primary = bool(getattr(config, "browser_primary", False) or getattr(config, "deep_mirror", False))
    on_challenge = bool(getattr(config, "browser_on_challenge", True) or getattr(config, "selenium_fallback", False))

    def _ua_for(url: str) -> str:
        try:
            return pick_user_agent_for_selenium(config)
        except Exception:
            return get_random_user_agent()

    async def _selenium_fetch(url: str, screenshot_path=None) -> Tuple[str, list, list]:
        loop = asyncio.get_running_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(
                    _executor,
                    fetch_with_selenium,
                    url,
                    2,
                    getattr(config, "proxy_url", "") or "",
                    screenshot_path,
                    _ua_for(url),
                ),
                timeout=45.0,
            )
        except asyncio.TimeoutError as exc:
            quit_selenium_driver()
            raise TimeoutError(f"Browser fetch timed out for {url}") from exc

    def _sync_cookies(client, url: str, cookies: list, output_note: Optional[Callable[[str], None]] = None):
        if not auto_cookies:
            return
        updated = store.ingest_selenium_cookies(cookies, url)
        header = store.apply_to_client(client, url)
        if header:
            config.cookie_string = store.as_cookie_string()
        if updated and output_note:
            output_note(f"Synced {updated} browser cookie(s) into HTTP jar for {_host_label(url)}")

    async def browser_page_fetcher(client, url, deep_render=False):
        global _chrome_skip_logged
        force_browser = bool(deep_render or browser_primary)
        screenshot_path = None
        if getattr(config, "screenshot_capture", False) and reporter and is_html_url(url):
            screenshot_path = reporter.screenshot_path(url)

        # Keep HTTP client cookie header fresh for this host before any probe
        if auto_cookies:
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
                    if auto_cookies:
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
            page_html, cookies, dom_urls = await _selenium_fetch(url, screenshot_path=screenshot_path)
        except Exception:
            if force_browser:
                raise
            # Challenge escalation failed (no Chrome / timeout) — caller continues via HTTP
            return "", []
        _sync_cookies(client, url, cookies)
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
