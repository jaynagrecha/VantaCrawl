"""Browser integration tests for DOM-clobber verification (mocked + optional Chrome)."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

from dom_clobber.contract import (
    STATE_BROWSER_EXECUTION_CONFIRMED,
    STATE_CLOBBER_WITHOUT_SINK,
    STATE_HTML_INJECTION_CONFIRMED,
    STATE_SINK_CONTEXT_CANDIDATE,
)
from dom_clobber.verify import decide_state, verify_dom_clobber_on_url


class _FakeResp:
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code


class _FakeClient:
    """HTTP client that reflects ?html= into a sink and serves page scripts."""

    def __init__(self, *, property_name: str = "vendorConfig", with_sink: bool = True):
        self.property_name = property_name
        self.with_sink = with_sink
        self.gets: List[str] = []

    async def get(self, url: str):
        self.gets.append(url)
        from urllib.parse import parse_qs, urlparse

        qs = parse_qs(urlparse(url).query)
        html_param = (qs.get("html") or [""])[0]
        if html_param:
            sink = html_param
        else:
            sink = f'<a id="{self.property_name}" href="/x.js">x</a>'
        script = ""
        if self.with_sink:
            script = f"""
            <script>
              var cfg = window.{self.property_name} || {{ href: '/safe' }};
              var s = document.createElement('script');
              s.src = cfg.href;
              document.body.appendChild(s);
            </script>
            """
        else:
            script = f"""
            <script>
              var cfg = window.{self.property_name} || {{ href: '/safe' }};
              /* no sink */
            </script>
            """
        body = f"<html><body><div id='sink'>{sink}</div>{script}<a href='?html=x'>seed</a></body></html>"
        return _FakeResp(body)


class _FakeBrowser:
    def __init__(self, *, clobber: bool = True, exec_ok: bool = False, sink: bool = True, net: bool = False):
        self.driver = MagicMock()
        self._clobber = clobber
        self._exec = exec_ok
        self._sink = sink
        self._net = net
        self.analyzed: List[Dict[str, Any]] = []

    def analyze(self, **kwargs):
        # Not used — verify calls analyze_clobber_page(driver, ...)
        return {}


@pytest.fixture
def patch_analyze(monkeypatch):
    def _install(*, clobber=True, exec_ok=False, sink=True, net=False, csp=False):
        def _analyze(driver, **kwargs):
            proof = kwargs.get("proof_url") or ""
            nonce = kwargs.get("nonce") or ""
            prop = kwargs.get("property_path") or ""
            page_url = str(kwargs.get("page_url") or "")
            # Negative controls / empty payloads must not look like positive proof
            has_payload = (
                "id=" in page_url
                or "id%3D" in page_url
                or "%3Cid" in page_url.lower()
                or "<a" in page_url
                or "%3Ca" in page_url
            )
            real_proof = bool(proof) and proof not in ("", "about:blank") and (
                "proof.js" in proof or (nonce and nonce in proof)
            )
            pos = has_payload and real_proof
            return {
                "browser_session_id": "bs_test",
                "final_url": kwargs.get("page_url"),
                "console_errors": [],
                "csp_blocked": ["csp"] if csp and pos else [],
                "inventory": {"namedWindow": [prop.split(".")[0]], "elements": []},
                "property": {
                    "ok": True,
                    "isElement": clobber and has_payload,
                    "type": "object",
                    "tagName": "A" if clobber and has_payload else None,
                    "href": proof if clobber and has_payload else None,
                    "id": prop.split(".")[0] if clobber and has_payload else None,
                },
                "root_property": {
                    "ok": True,
                    "isElement": clobber and has_payload,
                    "type": "object",
                    "href": proof if clobber and has_payload else None,
                },
                "hooks": {
                    "sinks": [{"kind": "script.src", "detail": proof}] if sink and pos else [],
                    "scriptsCreated": [{"src": proof, "by": "appendChild"}] if sink and pos else [],
                },
                "network": [{"url": proof, "initiatorType": "script"}] if net and pos else [],
                "named_property_clobbered": bool(clobber and has_payload),
                "proof_in_sink": bool(sink and pos),
                "sink_name": "script.src" if sink and pos else "",
                "sink_argument": proof if sink and pos else "",
                "app_network_proof": bool(net and pos),
                "execution_marker": bool(exec_ok and pos),
                "consumed_hint": bool((sink or clobber) and has_payload),
            }

        monkeypatch.setattr("dom_clobber.browser.analyze_clobber_page", _analyze)
        monkeypatch.setattr(
            "dom_clobber.browser.open_probe_url",
            lambda driver, url, wait_seconds=0.8: {
                "browser_session_id": "bs_inv",
                "final_url": url,
                "console_errors": [],
                "csp_blocked": [],
            },
        )
        monkeypatch.setattr(
            "dom_clobber.browser.inventory_page",
            lambda driver: {"namedWindow": ["vendorConfig"], "elements": [{"id": "vendorConfig", "name": ""}]},
        )
        monkeypatch.setattr(
            "dom_clobber.browser.resolve_property",
            lambda driver, path: {"ok": True, "isElement": False, "id": None},
        )
        return _analyze

    return _install


def test_lab_confirms_when_app_sink_executes(patch_analyze):
    patch_analyze(clobber=True, exec_ok=True, sink=True, net=True)
    client = _FakeClient(property_name="vendorConfig", with_sink=True)

    async def _run():
        return await verify_dom_clobber_on_url(
            client,
            "https://app.example/page?html=test",
            mode="lab",
            callback_base="https://cb.example/oob",
            scan_id="scan-1",
            browser_session_factory=lambda: _FakeBrowser(),
            max_params=2,
            max_candidates=4,
        )

    findings = asyncio.run(_run())
    states = [
        (f[4].get("proof") or {}).get("validation_state")
        for f in findings
        if len(f) > 4
    ]
    assert STATE_BROWSER_EXECUTION_CONFIRMED in states or STATE_SINK_CONTEXT_CANDIDATE in states
    # Property must be discovered dynamically
    assert any("vendorConfig" in str(f[2]) for f in findings)


def test_clobber_without_sink_not_high_confirmed(patch_analyze):
    patch_analyze(clobber=True, exec_ok=False, sink=False, net=False)
    client = _FakeClient(property_name="vendorConfig", with_sink=False)

    async def _run():
        return await verify_dom_clobber_on_url(
            client,
            "https://app.example/page?html=test",
            mode="lab",
            callback_base="https://cb.example/oob",
            scan_id="scan-1",
            browser_session_factory=lambda: _FakeBrowser(),
        )

    findings = asyncio.run(_run())
    for f in findings:
        state = (f[4].get("proof") or {}).get("validation_state")
        assert state != STATE_BROWSER_EXECUTION_CONFIRMED
        assert f[1] != "high" or state == STATE_SINK_CONTEXT_CANDIDATE


def test_safe_mode_never_returns_execution_confirmed(patch_analyze):
    patch_analyze(clobber=True, exec_ok=True, sink=True, net=True)
    client = _FakeClient(property_name="vendorConfig")

    async def _run():
        return await verify_dom_clobber_on_url(
            client,
            "https://app.example/page?html=test",
            mode="safe",
            callback_base="https://cb.example/oob",
            scan_id="scan-1",
            browser_session_factory=lambda: _FakeBrowser(),
        )

    findings = asyncio.run(_run())
    for f in findings:
        state = (f[4].get("proof") or {}).get("validation_state")
        assert state != STATE_BROWSER_EXECUTION_CONFIRMED


def test_unknown_param_name_discovered(patch_analyze):
    """Param is 'markup' — not in classic XSS allowlists — still discovered."""
    patch_analyze(clobber=True, exec_ok=False, sink=True, net=False)

    class _Client(_FakeClient):
        async def get(self, url: str):
            self.gets.append(url)
            from urllib.parse import parse_qs, urlparse

            qs = parse_qs(urlparse(url).query)
            # Accept any param reflecting as live HTML
            injected = ""
            for k, vals in qs.items():
                if k in ("markup", "html") and vals:
                    injected = vals[0]
            sink = injected or '<a id="vendorConfig" href="/x.js">x</a>'
            body = (
                f"<html><body><div id='sink'>{sink}</div>"
                "<script>var cfg=window.vendorConfig||{href:'/s'};"
                "var s=document.createElement('script');s.src=cfg.href;"
                "document.body.appendChild(s);</script>"
                "<a href='?markup=x'>seed</a></body></html>"
            )
            return _FakeResp(body)

    async def _run():
        return await verify_dom_clobber_on_url(
            _Client(),
            "https://app.example/page?markup=test",
            mode="lab",
            callback_base="https://cb.example/oob",
            browser_session_factory=lambda: _FakeBrowser(),
        )

    findings = asyncio.run(_run())
    assert findings
    assert any("markup" in str(f[2]) for f in findings)


def test_browser_execution_requires_application_sink(patch_analyze):
    # Clobber yes, but sink not attributed → not execution confirmed
    patch_analyze(clobber=True, exec_ok=True, sink=False, net=False)
    state = decide_state(
        mode="lab",
        injection_class="live_dom",
        named_clobber=True,
        consumed=True,
        proof_in_sink=False,
        app_network_proof=False,
        execution_marker=True,
        csp_blocked=False,
        browser_available=True,
        proof_available=True,
        negative_cleared=True,
        replay_ok=True,
    )
    # execution_marker without proof_in_sink should not be E-tier
    assert state != STATE_BROWSER_EXECUTION_CONFIRMED
