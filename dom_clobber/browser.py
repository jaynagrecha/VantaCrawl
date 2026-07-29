"""Browser instrumentation for DOM-clobber verification (Selenium + CDP).

Records property resolution, sink assignments, network requests, CSP, and
execution markers. Scanner-injected scripts never count as confirmation —
only application-originated sink use + proof correlation.
"""

from __future__ import annotations

import json
import secrets
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


# Instrumenting helpers injected into the page AFTER load for inventory only.
# These must not themselves assign script.src to the proof URL.
_INVENTORY_JS = r"""
return (function() {
  const out = { namedWindow: [], namedDocument: [], elements: [], errors: [] };
  try {
    for (const k of Object.getOwnPropertyNames(window)) {
      try {
        const v = window[k];
        if (v && typeof v === 'object' && v.tagName) {
          out.namedWindow.push(k);
        }
      } catch (e) {}
    }
  } catch (e) { out.errors.push(String(e)); }
  try {
    document.querySelectorAll('[id],[name]').forEach(el => {
      out.elements.push({
        tag: el.tagName,
        id: el.id || '',
        name: el.getAttribute('name') || ''
      });
    });
  } catch (e) { out.errors.push(String(e)); }
  return out;
})();
"""

_RESOLVE_PROP_JS = r"""
const path = arguments[0];
try {
  const parts = String(path || '').split('.');
  let cur = window;
  for (const p of parts) {
    if (cur == null) return { ok: false, type: 'undefined', isElement: false, href: null, value: null };
    cur = cur[p];
  }
  const isElement = !!(cur && cur.tagName);
  let href = null;
  let value = null;
  if (cur && typeof cur.href === 'string') href = cur.href;
  if (cur && typeof cur.value === 'string') value = cur.value;
  if (cur && cur.url && typeof cur.url === 'string') value = cur.url;
  if (cur && cur.url && typeof cur.url.value === 'string') value = cur.url.value;
  return {
    ok: true,
    type: (cur === null) ? 'null' : typeof cur,
    tagName: isElement ? cur.tagName : null,
    isElement: isElement,
    href: href,
    value: value,
    id: isElement ? (cur.id || null) : null
  };
} catch (e) {
  return { ok: false, type: 'error', error: String(e), isElement: false, href: null, value: null };
}
"""

# Hook sinks AFTER navigation using a page script that records app activity.
# Installed via CDP Page.addScriptToEvaluateOnNewDocument when possible.
_SINK_HOOK_SOURCE = r"""
(function() {
  if (window.__vcDcHooks) return;
  window.__vcDcHooks = { sinks: [], reads: [], scriptsCreated: [] };
  const H = window.__vcDcHooks;
  function rec(kind, detail) {
    try { H.sinks.push({ kind: kind, detail: detail, t: Date.now() }); } catch (e) {}
  }
  try {
    const desc = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'src');
    if (desc && desc.set) {
      Object.defineProperty(HTMLScriptElement.prototype, 'src', {
        configurable: true,
        enumerable: true,
        get: function() { return desc.get.call(this); },
        set: function(v) {
          rec('script.src', String(v));
          H.scriptsCreated.push({ src: String(v), by: 'property_set' });
          return desc.set.call(this, v);
        }
      });
    }
  } catch (e) {}
  try {
    const ap = Element.prototype.appendChild;
    Element.prototype.appendChild = function(child) {
      try {
        if (child && child.tagName === 'SCRIPT') {
          rec('appendChild.script', String(child.src || ''));
          H.scriptsCreated.push({ src: String(child.src || ''), by: 'appendChild' });
        }
      } catch (e) {}
      return ap.call(this, child);
    };
  } catch (e) {}
  try {
    const _fetch = window.fetch;
    if (_fetch) {
      window.fetch = function() {
        try { rec('fetch', String(arguments[0])); } catch (e) {}
        return _fetch.apply(this, arguments);
      };
    }
  } catch (e) {}
})();
"""


def install_sink_hooks(driver) -> bool:
    try:
        driver.execute_cdp_cmd(
            "Page.addScriptToEvaluateOnNewDocument",
            {"source": _SINK_HOOK_SOURCE},
        )
        return True
    except Exception:
        try:
            driver.execute_script(_SINK_HOOK_SOURCE)
            return True
        except Exception:
            return False


def inventory_page(driver) -> Dict[str, Any]:
    try:
        return driver.execute_script(_INVENTORY_JS) or {}
    except Exception as exc:
        return {"namedWindow": [], "namedDocument": [], "elements": [], "errors": [str(exc)]}


def resolve_property(driver, property_path: str) -> Dict[str, Any]:
    try:
        return driver.execute_script(_RESOLVE_PROP_JS, property_path) or {}
    except Exception as exc:
        return {"ok": False, "type": "error", "error": str(exc), "isElement": False}


def read_sink_hooks(driver) -> Dict[str, Any]:
    try:
        return driver.execute_script("return window.__vcDcHooks || {sinks:[],reads:[],scriptsCreated:[]};") or {}
    except Exception:
        return {"sinks": [], "reads": [], "scriptsCreated": []}


def check_execution_marker(driver, nonce: str) -> bool:
    """True when scanner-owned proof script set the nonce-derived dataset marker."""
    key = f"vcDc_{nonce[:12]}"
    try:
        val = driver.execute_script(
            "return document.documentElement.dataset[arguments[0]] || "
            "document.body.dataset[arguments[0]] || null;",
            key,
        )
        return str(val or "") == str(nonce)
    except Exception:
        return False


def collect_network_proof_requests(driver, nonce: str) -> List[Dict[str, str]]:
    """Best-effort: performance resource entries mentioning the nonce/proof."""
    try:
        entries = driver.execute_script(
            """
            const nonce = arguments[0];
            const out = [];
            try {
              const list = performance.getEntriesByType('resource') || [];
              for (const e of list) {
                const n = String(e.name || '');
                if (n.indexOf(nonce) >= 0 || n.indexOf('proof.js') >= 0) {
                  out.push({ url: n, initiatorType: e.initiatorType || '' });
                }
              }
            } catch (err) {}
            return out;
            """,
            nonce,
        )
        return list(entries or [])
    except Exception:
        return []


def open_probe_url(driver, page_url: str, *, wait_seconds: float = 1.5) -> Dict[str, Any]:
    """Navigate to the crafted URL (victim only opens URL — no click required)."""
    from browser_fetch import selenium_driver_lock

    with selenium_driver_lock():
        return _open_probe_url_unlocked(driver, page_url, wait_seconds=wait_seconds)


def open_and_inventory_page(
    driver,
    page_url: str,
    *,
    wait_seconds: float = 1.5,
) -> Dict[str, Any]:
    """Open *page_url* and inventory named DOM under one shared-driver lock."""
    from browser_fetch import selenium_driver_lock

    with selenium_driver_lock():
        _open_probe_url_unlocked(driver, page_url, wait_seconds=wait_seconds)
        return inventory_page(driver)


def _open_probe_url_unlocked(driver, page_url: str, *, wait_seconds: float = 1.5) -> Dict[str, Any]:
    console_errors: List[str] = []
    csp_blocked: List[str] = []
    session_id = f"bs_{secrets.token_hex(6)}"
    try:
        driver.execute_cdp_cmd("Network.enable", {})
        driver.execute_cdp_cmd("Log.enable", {})
    except Exception:
        pass
    install_sink_hooks(driver)
    try:
        driver.get("about:blank")
    except Exception:
        pass
    driver.get(page_url)
    time.sleep(max(0.3, float(wait_seconds or 0)))
    try:
        from selenium.webdriver.support.ui import WebDriverWait

        WebDriverWait(driver, max(2.0, float(wait_seconds) + 1.0)).until(
            lambda d: d.execute_script("return document.readyState") == "complete"
        )
    except Exception:
        pass
    time.sleep(0.4)
    try:
        for entry in driver.get_log("browser") or []:
            msg = str((entry or {}).get("message") or "")
            console_errors.append(msg[:500])
            low = msg.lower()
            if "content security policy" in low or "csp" in low:
                csp_blocked.append(msg[:500])
    except Exception:
        pass
    return {
        "browser_session_id": session_id,
        "final_url": str(getattr(driver, "current_url", None) or page_url),
        "console_errors": console_errors,
        "csp_blocked": csp_blocked,
    }


def analyze_clobber_page(
    driver,
    *,
    property_path: str,
    proof_url: str,
    nonce: str,
    page_url: str,
    wait_seconds: float = 1.5,
) -> Dict[str, Any]:
    """Full browser analysis for one clobber attempt."""
    from browser_fetch import selenium_driver_lock

    with selenium_driver_lock():
        nav = _open_probe_url_unlocked(driver, page_url, wait_seconds=wait_seconds)
        inv = inventory_page(driver)
        prop = resolve_property(driver, property_path)
        # Also resolve root if nested
        root = property_path.split(".", 1)[0]
        root_prop = resolve_property(driver, root) if root != property_path else prop
        hooks = read_sink_hooks(driver)
        net = collect_network_proof_requests(driver, nonce)
        executed = check_execution_marker(driver, nonce)

        sinks = list(hooks.get("sinks") or [])
        scripts = list(hooks.get("scriptsCreated") or [])
        proof_in_sink = False
        sink_name = ""
        sink_arg = ""
        for s in sinks:
            detail = str((s or {}).get("detail") or "")
            kind = str((s or {}).get("kind") or "")
            if proof_url and proof_url in detail or (nonce and nonce in detail):
                proof_in_sink = True
                sink_name = kind
                sink_arg = detail[:300]
                break
        if not proof_in_sink:
            for s in scripts:
                src = str((s or {}).get("src") or "")
                if (proof_url and proof_url in src) or (nonce and nonce in src):
                    proof_in_sink = True
                    sink_name = "script.src"
                    sink_arg = src[:300]
                    break

        # Application-originated network to proof
        app_request = False
        for n in net:
            url = str((n or {}).get("url") or "")
            init = str((n or {}).get("initiatorType") or "")
            if nonce in url or (proof_url and proof_url.split("?")[0] in url):
                if init in ("script", "other", "fetch", "xmlhttprequest", "img", ""):
                    app_request = True
                    break

        named_clobber = bool(
            (prop.get("isElement") or root_prop.get("isElement"))
            and (prop.get("ok") or root_prop.get("ok"))
        )
        # Value consumed ≈ sink saw proof URL or retained assignment matched proof
        href = prop.get("href") or root_prop.get("href") or ""
        value = prop.get("value") or root_prop.get("value") or ""
        consumed_hint = bool(
            proof_in_sink
            or (proof_url and (proof_url in str(href) or proof_url in str(value)))
            or (nonce and (nonce in str(href) or nonce in str(value)))
        )

        return {
            **nav,
            "inventory": inv,
            "property": prop,
            "root_property": root_prop,
            "hooks": hooks,
            "network": net,
            "named_property_clobbered": named_clobber,
            "proof_in_sink": proof_in_sink,
            "sink_name": sink_name,
            "sink_argument": sink_arg,
            "app_network_proof": app_request,
            "execution_marker": executed,
            "consumed_hint": consumed_hint,
            "original_snapshot": None,
        }


def make_dom_clobber_browser(config=None) -> Optional[Any]:
    """Return a thin driver factory or None if Chrome unavailable."""
    try:
        from active_probe_browser import report_browser_capability
        from browser_fetch import get_selenium_driver
        from evasion_layer import pick_user_agent_for_selenium
    except Exception:
        return None
    cap = report_browser_capability(config)
    if cap.get("browser_confirmation") != "available":
        return None
    proxy = str(getattr(config, "proxy_url", "") or "") if config is not None else ""
    try:
        ua = pick_user_agent_for_selenium(config) if config is not None else ""
    except Exception:
        ua = ""

    class _Session:
        def __init__(self) -> None:
            self.driver = get_selenium_driver(proxy, user_agent=ua or "")

        def analyze(self, **kwargs: Any) -> Dict[str, Any]:
            return analyze_clobber_page(self.driver, **kwargs)

        def inventory(self) -> Dict[str, Any]:
            from browser_fetch import selenium_driver_lock

            with selenium_driver_lock():
                return inventory_page(self.driver)

    def _factory() -> _Session:
        return _Session()

    return _factory
