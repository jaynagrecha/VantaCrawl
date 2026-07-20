"""Headless Chrome helpers shared by desktop GUI and web worker (no Qt)."""

from __future__ import annotations

import asyncio
import os
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Optional

import httpx

from auth_login import selenium_login
from crawler_common import get_random_user_agent, is_html_url

_executor = ThreadPoolExecutor(max_workers=1)
_selenium_driver = None

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


def get_selenium_driver(proxy_url: str = ""):
    global _selenium_driver
    if _selenium_driver is not None:
        return _selenium_driver

    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service as ChromeService

    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument(f"user-agent={get_random_user_agent()}")
    if proxy_url:
        options.add_argument(f"--proxy-server={proxy_url}")
    _selenium_driver = webdriver.Chrome(service=ChromeService(), options=options)
    return _selenium_driver


def fetch_with_selenium(url, settle_seconds=2, proxy_url="", screenshot_path=None):
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.support.ui import WebDriverWait

    driver = get_selenium_driver(proxy_url)
    driver.get(url)
    try:
        WebDriverWait(driver, 15).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
    except Exception:
        pass
    if settle_seconds:
        time.sleep(settle_seconds)
    if screenshot_path:
        os.makedirs(os.path.dirname(screenshot_path), exist_ok=True)
        driver.save_screenshot(screenshot_path)
    dom_urls = driver.execute_script(DOM_LINKS_SCRIPT) or []
    return driver.page_source, driver.get_cookies(), dom_urls


def quit_selenium_driver() -> None:
    global _selenium_driver
    if _selenium_driver is not None:
        _selenium_driver.quit()
        _selenium_driver = None


def make_browser_fetcher(config, reporter=None):
    async def browser_page_fetcher(client, url, deep_render=False):
        if not deep_render:
            try:
                response = await client.get(url, timeout=15)
                response.raise_for_status()
                return response.text
            except httpx.HTTPError:
                pass

        loop = asyncio.get_running_loop()
        screenshot_path = None
        if config.screenshot_capture and reporter and is_html_url(url):
            screenshot_path = reporter.screenshot_path(url)
        page_html, cookies, dom_urls = await loop.run_in_executor(
            _executor,
            fetch_with_selenium,
            url,
            2,
            config.proxy_url,
            screenshot_path,
        )
        for cookie in cookies:
            client.cookies.set(cookie["name"], cookie["value"], domain=cookie.get("domain"))
        return page_html, dom_urls

    return browser_page_fetcher


def apply_selenium_login(config, output: Optional[Callable[[str], Any]] = None):
    if not config.use_selenium_login or not config.login_url:
        return config
    if output:
        output("Running browser login to capture cookies…")
    cookies, message = selenium_login(
        config.login_url,
        config.login_username,
        config.login_password,
        driver_factory=lambda: get_selenium_driver(config.proxy_url),
    )
    if output:
        output(message)
    if cookies:
        config.cookie_string = cookies
    return config
