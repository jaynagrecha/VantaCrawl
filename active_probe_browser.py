"""Production browser evaluator for active XSS confirmation.

Uses the shared Selenium Chrome driver from browser_fetch when available.
Confirms only when ``document.body.dataset.vc === '<token>'`` evaluates true.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Callable, Dict, Optional
from urllib.parse import urlencode, urlparse, urlunparse


def _build_get_url(page_url: str) -> str:
    return str(page_url or "")


def chrome_evaluator_available() -> bool:
    try:
        from browser_fetch import chrome_available

        return bool(chrome_available())
    except Exception:
        return False


def make_browser_evaluate(
    config=None,
    *,
    output_callback: Optional[Callable[[str], Any]] = None,
    stats=None,
    wait_seconds: float = 1.25,
) -> Optional[Callable[..., Any]]:
    """Return async browser_evaluate(page_url, js_expr, **kwargs) or None if Chrome missing."""
    try:
        from browser_fetch import chrome_available, get_selenium_driver
        from evasion_layer import pick_user_agent_for_selenium
    except Exception:
        return None
    if not chrome_available():
        return None

    proxy = str(getattr(config, "proxy_url", "") or "") if config is not None else ""
    try:
        ua = pick_user_agent_for_selenium(config) if config is not None else ""
    except Exception:
        ua = ""

    def _sync_evaluate(
        page_url: str,
        js_expr: str,
        *,
        method: str = "GET",
        post_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        from selenium.webdriver.support.ui import WebDriverWait

        driver = get_selenium_driver(proxy, user_agent=ua or "")
        console_errors: list = []
        csp_blocked: list = []
        final_url = page_url
        executed = False
        value = None
        t0 = time.monotonic()
        try:
            # Best-effort CSP / console capture via CDP
            try:
                driver.execute_cdp_cmd("Network.enable", {})
                driver.execute_cdp_cmd("Log.enable", {})
            except Exception:
                pass

            method_u = (method or "GET").upper()
            if method_u == "POST" and post_data:
                # Reproduce safe POST via data URL form submit (same-origin relative action)
                from html import escape

                fields = "".join(
                    f'<input type="hidden" name="{escape(str(k))}" value="{escape(str(v))}"/>'
                    for k, v in dict(post_data).items()
                )
                html = (
                    "<html><body>"
                    f'<form id="vc" method="POST" action="{escape(page_url)}">{fields}</form>'
                    "<script>document.getElementById('vc').submit()</script>"
                    "</body></html>"
                )
                driver.get("data:text/html;charset=utf-8," + html)
            else:
                driver.get(_build_get_url(page_url))

            try:
                WebDriverWait(driver, max(2.0, float(wait_seconds) + 1.0)).until(
                    lambda d: d.execute_script("return document.readyState") == "complete"
                )
            except Exception:
                pass
            time.sleep(max(0.2, float(wait_seconds or 0)))

            final_url = str(getattr(driver, "current_url", None) or page_url)
            try:
                value = driver.execute_script(f"return ({js_expr});")
                executed = bool(value) is True or value is True
                if value is True:
                    executed = True
                elif isinstance(value, str) and value.lower() in ("true", "1"):
                    executed = True
                else:
                    executed = bool(value) and value is not False
            except Exception as exc:
                console_errors.append(str(exc)[:300])
                executed = False

            # Pull recent browser log / CDP issues when available
            try:
                for entry in driver.get_log("browser") or []:
                    msg = str((entry or {}).get("message") or "")[:400]
                    if not msg:
                        continue
                    low = msg.lower()
                    if "content security policy" in low or "csp" in low:
                        csp_blocked.append(msg)
                    elif (entry or {}).get("level") in ("SEVERE", "ERROR", "WARNING"):
                        console_errors.append(msg)
            except Exception:
                pass
        except Exception as exc:
            console_errors.append(str(exc)[:300])
            executed = False

        duration_ms = (time.monotonic() - t0) * 1000.0
        result = {
            "executed": bool(executed),
            "value": value,
            "final_url": final_url,
            "console_errors": console_errors[:12],
            "csp_blocked": csp_blocked[:12],
            "duration_ms": duration_ms,
            "browser_request_id": f"selenium:{int(time.time() * 1000)}",
            "evidence": f"dataset_eval={'true' if executed else 'false'}",
        }
        if stats is not None and hasattr(stats, "record_request"):
            try:
                stats.record_request(
                    phase="active_probe",
                    source="browser_evaluate",
                    url=page_url,
                    status=200 if executed else 0,
                    final_url=final_url,
                    duration_ms=duration_ms,
                    outcome="browser_exec_true" if executed else "browser_exec_false",
                    classification="browser_evaluate",
                    probe_role="browser_confirmation",
                    result_state="browser_execution_confirmed" if executed else "negative",
                )
            except Exception:
                pass
        return result

    async def browser_evaluate(page_url: str, js_expr: str, **kwargs) -> Dict[str, Any]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            lambda: _sync_evaluate(
                page_url,
                js_expr,
                method=str(kwargs.get("method") or "GET"),
                post_data=kwargs.get("post_data"),
            ),
        )

    if output_callback:
        try:
            output_callback("Active-probe browser XSS evaluator wired (Chrome/Selenium).")
        except Exception:
            pass
    return browser_evaluate


def build_probe_page_url(endpoint: str, method: str, values: Dict[str, Any]) -> str:
    """Build a navigable URL for GET XSS confirmation."""
    if (method or "GET").upper() != "GET":
        return endpoint
    parsed = urlparse(endpoint)
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            urlencode(values or {}, doseq=True),
            parsed.fragment,
        )
    )
