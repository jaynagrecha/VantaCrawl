"""Browser CORS proof under shared selenium_driver_lock."""

from __future__ import annotations

import json
import secrets
import time
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from browser_fetch import get_selenium_driver, selenium_driver_lock


def _new_context_id() -> str:
    return f"selenium:{int(time.time() * 1000)}:{secrets.token_hex(3)}"


def _clear_driver_state(driver: Any) -> None:
    try:
        driver.get("about:blank")
    except Exception:
        pass
    try:
        driver.delete_all_cookies()
    except Exception:
        pass
    try:
        driver.execute_script(
            "try{localStorage.clear();}catch(e){}"
            "try{sessionStorage.clear();}catch(e){}"
            "try{document.documentElement.removeAttribute('data-vc-cors');}catch(e){}"
        )
    except Exception:
        pass


def run_cors_browser_proof(
    *,
    proof_page_url: str,
    expected_scan_id: str,
    expected_candidate_id: str,
    expected_probe_id: str,
    expected_nonce: str,
    expected_target_url: str,
    expected_canary: str,
    timeout_sec: float = 20.0,
) -> Dict[str, Any]:
    """Navigate proof origin page and read structured fetch result.

    Holds selenium_driver_lock for the complete transaction.
    """
    ctx_id = _new_context_id()
    out: Dict[str, Any] = {
        "ok": False,
        "readable": False,
        "status": 0,
        "canary_found": False,
        "canary_expected": expected_canary,
        "error": "",
        "browser_context_id": ctx_id,
        "proof_final_url": "",
        "content_type": "",
        "body_len": 0,
        "body_hash": "",
        "correlation_ok": False,
        "decision": "no_result",
        "scan_id": expected_scan_id,
        "candidate_id": expected_candidate_id,
        "probe_id": expected_probe_id,
        "nonce": expected_nonce,
        "target_url": expected_target_url,
    }
    with selenium_driver_lock():
        driver = get_selenium_driver()
        if driver is None:
            out["error"] = "browser_unavailable"
            out["decision"] = "browser_unavailable"
            return out
        try:
            _clear_driver_state(driver)
            driver.set_page_load_timeout(max(5, int(timeout_sec)))
            driver.get(proof_page_url)
            out["proof_final_url"] = str(getattr(driver, "current_url", "") or "")
            # Wait for result element
            deadline = time.time() + timeout_sec
            raw = ""
            while time.time() < deadline:
                try:
                    el = driver.find_element("id", "vc-cors-result")
                    raw = (el.text or el.get_attribute("textContent") or "").strip()
                    if raw and raw != "pending":
                        break
                except Exception:
                    raw = ""
                time.sleep(0.15)
            if not raw or raw == "pending":
                out["error"] = "timeout_waiting_result"
                out["decision"] = "navigation_or_timeout"
                return out
            try:
                data = json.loads(raw)
            except Exception:
                out["error"] = "malformed_result_json"
                out["decision"] = "inconclusive"
                return out
            # Page embeds binding metadata for correlation
            page_meta = {}
            try:
                meta_el = driver.find_element("id", "vc-cors-meta")
                page_meta = json.loads((meta_el.text or "").strip() or "{}")
            except Exception:
                page_meta = {}

            out["readable"] = bool(data.get("readable"))
            out["status"] = int(data.get("status") or 0)
            out["canary_found"] = bool(data.get("canary_found"))
            out["content_type"] = str(data.get("content_type") or "")
            out["body_len"] = int(data.get("body_len") or 0)
            out["body_hash"] = str(data.get("body_hash") or "")
            out["error"] = str(data.get("error") or "")

            mismatches = []
            for key, expect, got in (
                ("scan_id", expected_scan_id, page_meta.get("sid")),
                ("candidate_id", expected_candidate_id, page_meta.get("cid")),
                ("probe_id", expected_probe_id, page_meta.get("pid")),
                ("nonce", expected_nonce, page_meta.get("n")),
            ):
                if expect and got and str(got) != str(expect):
                    mismatches.append(key)
            page_tu = str(page_meta.get("tu") or "")
            if expected_target_url and page_tu and page_tu != expected_target_url:
                mismatches.append("target_url")
            # Proof page must remain on proof origin path
            try:
                path = urlparse(out["proof_final_url"]).path or ""
                if "/api/cors-proof/" not in path:
                    mismatches.append("proof_path")
            except Exception:
                mismatches.append("proof_path")

            if mismatches:
                out["correlation_ok"] = False
                out["decision"] = "stale_or_mismatched_evidence"
                out["mismatches"] = mismatches
                out["readable"] = False
                out["canary_found"] = False
                return out

            out["correlation_ok"] = True
            if out["readable"] and expected_canary and out["canary_found"]:
                out["ok"] = True
                out["decision"] = "confirmed_current_probe"
            elif out["readable"] and not expected_canary:
                out["ok"] = True
                out["decision"] = "readable_without_canary"
            elif not out["readable"]:
                out["decision"] = "browser_read_blocked"
            else:
                out["decision"] = "readable_canary_missing"
            return out
        except Exception as exc:
            out["error"] = f"browser_exception:{type(exc).__name__}"
            out["decision"] = "navigation_or_timeout"
            return out
        finally:
            try:
                _clear_driver_state(driver)
            except Exception:
                pass
