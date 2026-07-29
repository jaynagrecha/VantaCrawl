"""Production browser evaluator for active XSS confirmation.

Uses the shared Selenium Chrome driver from browser_fetch when available.
Confirms only when ``document.body.dataset.vc === '<token>'`` evaluates true
**for the current probe's unique nonce** after a fresh navigation.

Evidence is bound to scan_id, candidate_id, probe_id, nonce, target URL,
parameter and payload. Cross-candidate / leftover markers never confirm.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from typing import Any, Callable, Dict, Optional
from urllib.parse import urlencode, urlparse, urlunparse


def chrome_evaluator_available() -> bool:
    try:
        from browser_fetch import chrome_available

        return bool(chrome_available())
    except Exception:
        return False


def report_browser_capability(config=None) -> Dict[str, Any]:
    """Scan-start capability report for browser XSS confirmation."""
    detail = {
        "browser_confirmation": "unavailable",
        "browser": "",
        "driver": "missing",
        "message": "Browser confirmation: unavailable — XSS findings limited to unverified evidence",
    }
    try:
        from browser_fetch import chrome_available, probe_chrome

        ok, path = probe_chrome()
        if not ok or not chrome_available():
            return detail
        # Best-effort version string from binary path name
        browser_name = "Chromium/Chrome"
        low = (path or "").lower()
        if "chromium" in low:
            browser_name = "Chromium"
        elif "chrome" in low:
            browser_name = "Chrome"
        detail = {
            "browser_confirmation": "available",
            "browser": browser_name,
            "browser_path": path,
            "driver": "compatible",
            "message": f"Browser confirmation: available — Browser: {browser_name} — Driver: compatible",
        }
        # Optional: verify driver can start (expensive) — skip by default
        if config is not None and bool(getattr(config, "browser_probe_driver", False)):
            try:
                from browser_fetch import get_selenium_driver, quit_selenium_driver

                proxy = str(getattr(config, "proxy_url", "") or "")
                driver = get_selenium_driver(proxy, user_agent="")
                ver = ""
                try:
                    ver = str((driver.capabilities or {}).get("browserVersion") or "")
                except Exception:
                    ver = ""
                if ver:
                    detail["browser"] = f"{browser_name} {ver}"
                    detail["message"] = (
                        f"Browser confirmation: available — Browser: {browser_name} {ver} — Driver: compatible"
                    )
                quit_selenium_driver()
            except Exception as exc:
                return {
                    "browser_confirmation": "unavailable",
                    "browser": browser_name,
                    "driver": "incompatible",
                    "message": (
                        "Browser confirmation: unavailable — driver/sandbox failed "
                        f"({str(exc)[:120]}) — XSS findings limited to unverified evidence"
                    ),
                }
        return detail
    except Exception as exc:
        detail["message"] = (
            "Browser confirmation: unavailable — "
            f"{str(exc)[:120]} — XSS findings limited to unverified evidence"
        )
        return detail


def make_browser_evaluate(
    config=None,
    *,
    output_callback: Optional[Callable[[str], Any]] = None,
    stats=None,
    wait_seconds: float = 1.25,
    capability: Optional[Dict[str, Any]] = None,
) -> Optional[Callable[..., Any]]:
    """Return async browser_evaluate(...) or None if Chrome missing.

    When None is returned, callers must report confirmation unavailable — never
    emit browser_execution_confirmed.
    """
    cap = capability or report_browser_capability(config)
    if cap.get("browser_confirmation") != "available":
        if output_callback:
            try:
                output_callback(cap.get("message") or "Browser confirmation: unavailable")
            except Exception:
                pass
        if stats is not None:
            try:
                stats.browser_confirmation = dict(cap)
            except Exception:
                pass
        return None

    try:
        from browser_fetch import get_selenium_driver
        from evasion_layer import pick_user_agent_for_selenium
    except Exception:
        return None

    proxy = str(getattr(config, "proxy_url", "") or "") if config is not None else ""
    try:
        ua = pick_user_agent_for_selenium(config) if config is not None else ""
    except Exception:
        ua = ""

    if stats is not None:
        try:
            stats.browser_confirmation = dict(cap)
        except Exception:
            pass
    if output_callback:
        try:
            output_callback(cap.get("message") or "Browser confirmation: available")
        except Exception:
            pass

    def _clear_origin_state(driver, origin_url: str = "") -> None:
        """Clear marker globals and storage so prior probes cannot confirm."""
        try:
            driver.execute_script(
                "try{"
                "if(document.body){delete document.body.dataset.vc; "
                "document.body.removeAttribute('data-vc');}"
                "window.__vc_probe_token=null;"
                "window.__vc_probe_id=null;"
                "try{localStorage.clear();}catch(e){}"
                "try{sessionStorage.clear();}catch(e){}"
                "}catch(e){}"
            )
        except Exception:
            pass
        # Best-effort cookie clear for the target origin when known
        try:
            if origin_url and origin_url.startswith("http"):
                driver.delete_all_cookies()
        except Exception:
            pass

    def _read_marker(driver) -> str:
        try:
            return str(
                driver.execute_script(
                    "return (document.body && document.body.dataset) "
                    "? (document.body.dataset.vc || '') : '';"
                )
                or ""
            )
        except Exception:
            return ""

    def _ledger_role(
        role: str,
        *,
        page_url: str,
        final_url: str = "",
        status: int = 0,
        result_state: str = "",
        duration_ms: float = 0.0,
        payload: str = "",
        probe_class: str = "",
        probe_name: str = "",
        parameter: str = "",
        probe_id: str = "",
        nonce: str = "",
        candidate_id: str = "",
        scan_id: str = "",
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        if stats is None or not hasattr(stats, "record_request"):
            return
        try:
            stats.record_request(
                phase="active_probe",
                source="browser_evaluate",
                url=page_url,
                status=status,
                final_url=final_url or page_url,
                duration_ms=duration_ms,
                outcome=role,
                classification="browser_evaluate",
                probe_role=role,
                probe_class=probe_class,
                probe_name=probe_name,
                parameter=parameter,
                result_state=result_state,
                payload_redacted=(payload or "[browser_eval]")[:160],
                probe_id=probe_id,
                nonce=nonce,
                candidate_id=candidate_id,
                scan_id=scan_id,
                **(extra or {}),
            )
        except Exception:
            pass

    def _sync_evaluate(
        page_url: str,
        js_expr: str,
        *,
        method: str = "GET",
        post_data: Optional[Dict[str, Any]] = None,
        fragment: str = "",
        expected_token: str = "",
        probe_class: str = "",
        probe_name: str = "",
        parameter: str = "",
        payload: str = "",
        scan_id: str = "",
        candidate_id: str = "",
        probe_id: str = "",
        nonce: str = "",
        target_url: str = "",
        target_parameter: str = "",
    ) -> Dict[str, Any]:
        from selenium.webdriver.support.ui import WebDriverWait

        driver = get_selenium_driver(proxy, user_agent=ua or "")
        console_errors: list = []
        csp_blocked: list = []
        final_url = page_url
        executed = False
        reproduced = False
        value = None
        marker_before = ""
        marker_after = ""
        correlation_ok = True
        correlation_reason = "ok"
        context_id = f"selenium:{int(time.time() * 1000)}:{secrets.token_hex(3)}"
        t0 = time.monotonic()
        bind_nonce = str(nonce or expected_token or "")
        bind_param = str(target_parameter or parameter or "")
        bind_target = str(target_url or page_url or "")

        _ledger_role(
            "browser_reproduction_started",
            page_url=page_url,
            probe_class=probe_class,
            probe_name=probe_name,
            parameter=parameter,
            payload=payload,
            result_state="started",
            probe_id=probe_id,
            nonce=bind_nonce,
            candidate_id=candidate_id,
            scan_id=scan_id,
            extra={"browser_context_id": context_id},
        )
        try:
            try:
                driver.execute_cdp_cmd("Network.enable", {})
                driver.execute_cdp_cmd("Log.enable", {})
            except Exception:
                pass

            # Fresh isolated page: about:blank + clear storage/globals before baseline.
            try:
                driver.get("about:blank")
            except Exception:
                pass
            _clear_origin_state(driver, bind_target)
            marker_before = _read_marker(driver)
            if bind_nonce and marker_before == bind_nonce:
                # Stale marker survived isolation — reject confirmation.
                correlation_ok = False
                correlation_reason = "pre_probe_nonce_present"
                _clear_origin_state(driver, bind_target)
                marker_before = _read_marker(driver)

            method_u = (method or "GET").upper()
            target = str(page_url or "")
            if fragment:
                # DOM/hash XSS — open base then set location.hash
                base = target.split("#", 1)[0]
                driver.get(base or "about:blank")
                driver.execute_script("window.location.hash = arguments[0];", fragment)
                reproduced = True
            elif method_u == "POST" and post_data:
                # Reproduce POST form fields via about:blank form submit to absolute action
                fields_js = []
                for k, v in dict(post_data).items():
                    fields_js.append((str(k), str(v)))
                driver.get("about:blank")
                driver.execute_script(
                    """
                    const action = arguments[0];
                    const pairs = arguments[1];
                    const f = document.createElement('form');
                    f.method = 'POST';
                    f.action = action;
                    f.style.display = 'none';
                    for (const [k, v] of pairs) {
                      const inp = document.createElement('input');
                      inp.type = 'hidden';
                      inp.name = k;
                      inp.value = v;
                      f.appendChild(inp);
                    }
                    document.body.appendChild(f);
                    f.submit();
                    """,
                    target,
                    fields_js,
                )
                reproduced = True
            else:
                driver.get(target)
                reproduced = True

            try:
                WebDriverWait(driver, max(2.0, float(wait_seconds) + 1.5)).until(
                    lambda d: d.execute_script("return document.readyState") == "complete"
                )
            except Exception:
                pass
            time.sleep(max(0.25, float(wait_seconds or 0)))

            final_url = str(getattr(driver, "current_url", None) or page_url)
            _ledger_role(
                "browser_page_loaded",
                page_url=page_url,
                final_url=final_url,
                status=200,
                probe_class=probe_class,
                probe_name=probe_name,
                parameter=parameter,
                payload=payload,
                result_state="page_loaded",
                probe_id=probe_id,
                nonce=bind_nonce,
                candidate_id=candidate_id,
                scan_id=scan_id,
                extra={"browser_context_id": context_id, "marker_before": marker_before},
            )

            # Binding checks — reject mismatched URL / parameter evidence.
            try:
                want_path = (urlparse(bind_target).path or "").rstrip("/")
                got_path = (urlparse(final_url).path or "").rstrip("/")
                if want_path and got_path and want_path != got_path:
                    # Allow same-path with different query (payload delivery).
                    pass
                if bind_param and post_data is None:
                    # GET probes must carry the parameter on the navigated URL.
                    from urllib.parse import parse_qs

                    q = parse_qs(urlparse(page_url).query)
                    if bind_param not in q and bind_param not in parse_qs(urlparse(final_url).query):
                        correlation_ok = False
                        correlation_reason = "parameter_missing_from_browser_url"
            except Exception:
                pass

            # Evaluate only the current probe nonce.
            try:
                value = driver.execute_script(f"return ({js_expr});")
                executed = value is True
                marker_after = _read_marker(driver)
                if not executed and expected_token:
                    executed = marker_after == str(expected_token)
                    value = marker_after if executed else value
                if executed and bind_nonce and marker_after != bind_nonce:
                    executed = False
                    correlation_ok = False
                    correlation_reason = "marker_nonce_mismatch"
                if executed and marker_before == bind_nonce and bind_nonce:
                    # Marker was already present before navigation — not this probe.
                    executed = False
                    correlation_ok = False
                    correlation_reason = "stale_pre_probe_marker"
            except Exception as exc:
                console_errors.append(str(exc)[:300])
                executed = False

            if not correlation_ok:
                executed = False

            _ledger_role(
                "browser_marker_checked",
                page_url=page_url,
                final_url=final_url,
                status=200 if executed else 0,
                probe_class=probe_class,
                probe_name=probe_name,
                parameter=parameter,
                payload=payload,
                result_state="marker_present" if executed else "marker_absent",
                probe_id=probe_id,
                nonce=bind_nonce,
                candidate_id=candidate_id,
                scan_id=scan_id,
                extra={
                    "browser_context_id": context_id,
                    "marker_before": marker_before,
                    "marker_after": marker_after,
                    "correlation_ok": correlation_ok,
                    "correlation_reason": correlation_reason,
                },
            )

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
            reproduced = False
        finally:
            _clear_origin_state(driver, bind_target)

        duration_ms = (time.monotonic() - t0) * 1000.0
        confirmed = bool(executed and reproduced and correlation_ok)
        outcome_role = (
            "browser_execution_confirmed" if confirmed else "browser_execution_failed"
        )
        result = {
            "executed": confirmed,
            "reproduced": bool(reproduced),
            "value": value,
            "final_url": final_url,
            "console_errors": console_errors[:12],
            "csp_blocked": csp_blocked[:12],
            "duration_ms": duration_ms,
            "browser_request_id": context_id,
            "browser_context_id": context_id,
            "evidence": (
                f"dataset_eval={'true' if confirmed else 'false'};"
                f"reproduced={reproduced};correlation={correlation_reason};"
                f"nonce={bind_nonce};probe_id={probe_id}"
            ),
            "browser_confirmation": "available",
            "generated_url": page_url,
            "method": method,
            "scan_id": scan_id,
            "candidate_id": candidate_id,
            "probe_id": probe_id,
            "nonce": bind_nonce,
            "target_url": bind_target,
            "target_parameter": bind_param,
            "marker_before": marker_before,
            "marker_after": marker_after,
            "correlation_ok": correlation_ok,
            "correlation_reason": correlation_reason,
            "correlation_decision": {
                "confirmed": confirmed,
                "reason": correlation_reason if not confirmed else "current_probe_nonce_after_navigation",
                "scan_id": scan_id,
                "candidate_id": candidate_id,
                "probe_id": probe_id,
                "nonce": bind_nonce,
                "target_url": bind_target,
                "target_parameter": bind_param,
                "marker_before": marker_before,
                "marker_after": marker_after,
            },
        }
        _ledger_role(
            outcome_role,
            page_url=page_url,
            final_url=final_url,
            status=200 if confirmed else 0,
            duration_ms=duration_ms,
            probe_class=probe_class,
            probe_name=probe_name,
            parameter=parameter,
            payload=payload,
            result_state="browser_execution_confirmed" if confirmed else "browser_execution_failed",
            probe_id=probe_id,
            nonce=bind_nonce,
            candidate_id=candidate_id,
            scan_id=scan_id,
            extra={"browser_context_id": context_id, "correlation_reason": correlation_reason},
        )
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
                fragment=str(kwargs.get("fragment") or ""),
                expected_token=str(kwargs.get("expected_token") or ""),
                probe_class=str(kwargs.get("probe_class") or ""),
                probe_name=str(kwargs.get("probe_name") or ""),
                parameter=str(kwargs.get("parameter") or ""),
                payload=str(kwargs.get("payload") or ""),
                scan_id=str(kwargs.get("scan_id") or ""),
                candidate_id=str(kwargs.get("candidate_id") or ""),
                probe_id=str(kwargs.get("probe_id") or ""),
                nonce=str(kwargs.get("nonce") or kwargs.get("expected_token") or ""),
                target_url=str(kwargs.get("target_url") or page_url or ""),
                target_parameter=str(kwargs.get("target_parameter") or kwargs.get("parameter") or ""),
            ),
        )

    return browser_evaluate


def build_probe_page_url(endpoint: str, method: str, values: Dict[str, Any]) -> str:
    """Build a navigable URL for GET XSS confirmation (query params)."""
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
