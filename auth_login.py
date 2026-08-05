"""Browser-based login to capture session cookies for authenticated crawling."""

from __future__ import annotations

import time
from typing import Callable, Optional, Tuple


def cookies_to_header(cookies: list) -> str:
    parts = []
    for cookie in cookies:
        name = cookie.get("name")
        value = cookie.get("value")
        if name and value is not None:
            parts.append(f"{name}={value}")
    return "; ".join(parts)


def _require_shared_selenium_lock() -> None:
    """Fail closed unless the process-global shared driver lock is held.

    Lazy-imports browser_fetch to avoid an import cycle at module load
    (browser_fetch imports selenium_login).
    """
    from browser_fetch import selenium_driver_lock

    lock = selenium_driver_lock()
    owned = getattr(lock, "_is_owned", None)
    if not callable(owned):
        raise RuntimeError(
            "selenium_login cannot verify selenium_driver_lock ownership "
            "(RLock._is_owned unavailable)"
        )
    if not owned():
        raise RuntimeError(
            "selenium_login requires browser_fetch.selenium_driver_lock "
            "to be held by the calling thread"
        )


def selenium_login(
    login_url: str,
    username: str,
    password: str,
    username_selector: str = "input[name='username'], input[name='email'], input[type='email'], #username, #email",
    password_selector: str = "input[name='password'], input[type='password'], #password",
    submit_selector: str = "button[type='submit'], input[type='submit'], button.login, #login",
    success_url_contains: str = "",
    settle_seconds: float = 2,
    driver_factory: Optional[Callable] = None,
) -> Tuple[str, str]:
    """
    Perform form login via Selenium. Returns (cookie_string, message).
    Authorized targets only.

    Callers must hold browser_fetch.selenium_driver_lock for the entire
    shared-driver transaction. apply_selenium_login is the production entry.
    """
    if driver_factory is None:
        raise RuntimeError("driver_factory required")
    _require_shared_selenium_lock()

    driver = driver_factory()
    try:
        driver.get(login_url)
        time.sleep(1)
        user_el = _find_first(driver, username_selector)
        pass_el = _find_first(driver, password_selector)
        if not user_el or not pass_el:
            return "", "Could not find username/password fields on login page"
        user_el.clear()
        user_el.send_keys(username)
        pass_el.clear()
        pass_el.send_keys(password)
        submit = _find_first(driver, submit_selector)
        if submit:
            submit.click()
        else:
            pass_el.submit()
        time.sleep(settle_seconds)
        if success_url_contains and success_url_contains not in driver.current_url:
            return cookies_to_header(driver.get_cookies()), f"Login may have failed (URL: {driver.current_url})"
        return cookies_to_header(driver.get_cookies()), f"Login OK — cookies captured from {driver.current_url}"
    finally:
        pass


def _find_first(driver, css_selectors: str):
    from selenium.webdriver.common.by import By

    for selector in css_selectors.split(","):
        selector = selector.strip()
        if not selector:
            continue
        try:
            elements = driver.find_elements(By.CSS_SELECTOR, selector)
            if elements:
                return elements[0]
        except Exception:
            continue
    return None
