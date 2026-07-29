"""Phase-1 XSS browser-evidence binding + encoded-control isolation regressions.

No Horizon path hardcodes in production packages under assertion — fixtures use
lab.example hosts with randomized paths where required.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any, Dict, List
from urllib.parse import parse_qs, urlparse

import pytest

from active_probe_kit import (
    STATE_BROWSER_EXEC,
    ProbeModeSettings,
    classify_xss,
    run_active_probe_kit,
)
from crawl_stats import CrawlStats


class _XssClient:
    """HTTP stub: reflected executes raw HTML; encoded entity-escapes markup."""

    def __init__(self, mode: str = "reflected"):
        self.mode = mode

    async def get(self, url, params=None, timeout=8, follow_redirects=True):
        from urllib.parse import urlencode

        q = dict(params or {})
        full = url
        if q:
            sep = "&" if "?" in url else "?"
            full = f"{url}{sep}{urlencode(q)}"
        val = ""
        if q:
            val = next(iter(q.values()))
        elif "?" in url:
            qs = parse_qs(urlparse(url).query)
            val = (qs.get("q") or qs.get("html") or [""])[0]
        if self.mode == "encoded":
            import html as _html

            body = f"<html><body><p>Results for: {_html.escape(str(val))}</p></body></html>"
        else:
            body = f"<html><body><p>Results for: {val}</p></body></html>"
        return SimpleNamespace(
            status_code=200,
            text=body,
            headers={"content-type": "text/html"},
            url=full,
        )

    async def post(self, *a, **k):
        return await self.get("https://lab.example/x", params={})


def test_classify_xss_encoded_markup_is_negative_not_attr_breakout():
    token = "VCXSS_dead"
    payload = f"\"><svg onload=\"document.body.dataset.vc='{token}'\">"
    encoded_body = (
        f"<p>Results for: &lt;svg onload=\"document.body.dataset.vc='{token}'\"&gt;</p>"
    )
    assert classify_xss(encoded_body, token, "base", payload=payload) is None

    live_body = f"<p>Results for: \"><svg onload=\"document.body.dataset.vc='{token}'\"></p>"
    disp = classify_xss(live_body, token, "base", payload=payload)
    assert disp is not None
    assert disp["validation_state"] in ("attribute_breakout", "sink_context_candidate")


def test_patch_last_probe_result_is_url_bound():
    """Browser confirm for candidate A must not stamp candidate B's ledger row."""
    stats = CrawlStats()

    async def _eval(page_url, js_expr, **kwargs):
        # Honest: only confirm when the navigated URL is the reflected fixture.
        executed = "/a/reflected" in page_url
        tok = kwargs.get("expected_token") or ""
        return {
            "executed": executed,
            "reproduced": True,
            "correlation_ok": True,
            "value": tok if executed else None,
            "final_url": page_url,
            "generated_url": page_url,
            "console_errors": [],
            "csp_blocked": [],
            "marker_before": "",
            "marker_after": tok if executed else "",
            "probe_id": kwargs.get("probe_id"),
            "nonce": kwargs.get("nonce") or tok,
            "correlation_decision": {"confirmed": executed},
        }

    asyncio.run(
        run_active_probe_kit(
            _XssClient("reflected"),
            "https://lab.example/a/reflected?q=hello",
            settings=ProbeModeSettings(
                mode="safe",
                browser_evaluate=_eval,
                stats=stats,
                max_params=2,
                max_forms=0,
                scan_id="scan-bind",
            ),
        )
    )
    asyncio.run(
        run_active_probe_kit(
            _XssClient("encoded"),
            "https://lab.example/b/encoded?q=hello",
            settings=ProbeModeSettings(
                mode="safe",
                browser_evaluate=_eval,
                stats=stats,
                max_params=2,
                max_forms=0,
                scan_id="scan-bind",
            ),
        )
    )
    enc_onload = [
        r
        for r in stats.request_ledger
        if r.get("probe_role") == "probe"
        and "/b/encoded" in str(r.get("url") or "")
        and r.get("probe_name") == "xss_event_onload"
    ]
    assert enc_onload, "encoded onload probe must exist"
    assert all(r.get("result_state") != STATE_BROWSER_EXEC for r in enc_onload)

    ref_onload = [
        r
        for r in stats.request_ledger
        if r.get("probe_role") == "probe"
        and "/a/reflected" in str(r.get("url") or "")
        and r.get("probe_name") == "xss_event_onload"
        and r.get("result_state") == STATE_BROWSER_EXEC
    ]
    assert ref_onload, "reflected onload must reach browser_execution_confirmed"


def test_xss_cross_contaminate_order_and_reverse():
    """Vulnerable then control, and reverse — only vulnerable confirms."""

    async def _eval(page_url, js_expr, **kwargs):
        executed = "vuln-xss" in page_url and "onload" in page_url
        tok = kwargs.get("expected_token") or ""
        return {
            "executed": executed,
            "reproduced": True,
            "correlation_ok": True,
            "value": tok if executed else None,
            "final_url": page_url,
            "generated_url": page_url,
            "console_errors": [],
            "csp_blocked": [],
            "marker_before": "",
            "marker_after": tok if executed else "",
            "probe_id": kwargs.get("probe_id"),
            "nonce": tok,
            "correlation_decision": {"confirmed": executed},
        }

    def _run(url: str, mode: str, stats: CrawlStats):
        return asyncio.run(
            run_active_probe_kit(
                _XssClient(mode),
                url,
                settings=ProbeModeSettings(
                    mode="lab",
                    browser_evaluate=_eval,
                    stats=stats,
                    max_params=3,
                    max_forms=0,
                    scan_id="scan-order",
                ),
            )
        )

    def _confirmed(findings) -> bool:
        return any(
            len(f) > 4
            and f[0] == "xss"
            and f[4].get("proof", {}).get("validation_state") == STATE_BROWSER_EXEC
            for f in findings
        )

    stats = CrawlStats()
    f_ref = _run("https://lab.example/rand/vuln-xss?q=1", "reflected", stats)
    f_enc = _run("https://lab.example/rand/safe-xss?q=1", "encoded", stats)
    assert _confirmed(f_ref)
    assert not _confirmed(f_enc)

    stats2 = CrawlStats()
    f_enc2 = _run("https://lab.example/rand/safe-xss2?q=1", "encoded", stats2)
    f_ref2 = _run("https://lab.example/rand/vuln-xss2?q=1", "reflected", stats2)
    assert not _confirmed(f_enc2)
    assert _confirmed(f_ref2)


def test_xss_concurrent_scans_isolated_context_ids():
    """Two scan_ids sharing a mock browser worker must not cross-confirm."""

    seen: List[Dict[str, Any]] = []

    async def _eval(page_url, js_expr, **kwargs):
        seen.append(
            {
                "scan_id": kwargs.get("scan_id"),
                "candidate_id": kwargs.get("candidate_id"),
                "probe_id": kwargs.get("probe_id"),
                "nonce": kwargs.get("nonce") or kwargs.get("expected_token"),
                "url": page_url,
            }
        )
        tok = kwargs.get("expected_token") or ""
        # Confirm only for scan-A reflected
        executed = kwargs.get("scan_id") == "scan-A" and "reflected" in page_url
        return {
            "executed": executed,
            "reproduced": True,
            "correlation_ok": True,
            "value": tok if executed else None,
            "final_url": page_url,
            "generated_url": page_url,
            "console_errors": [],
            "csp_blocked": [],
            "marker_before": "",
            "marker_after": tok if executed else "",
            "scan_id": kwargs.get("scan_id"),
            "candidate_id": kwargs.get("candidate_id"),
            "probe_id": kwargs.get("probe_id"),
            "nonce": tok,
            "correlation_decision": {"confirmed": executed, "scan_id": kwargs.get("scan_id")},
        }

    stats_a = CrawlStats()
    stats_b = CrawlStats()
    fa = asyncio.run(
        run_active_probe_kit(
            _XssClient("reflected"),
            "https://lab.example/reflected?q=1",
            settings=ProbeModeSettings(
                mode="safe",
                browser_evaluate=_eval,
                stats=stats_a,
                max_params=2,
                max_forms=0,
                scan_id="scan-A",
            ),
        )
    )
    fb = asyncio.run(
        run_active_probe_kit(
            _XssClient("encoded"),
            "https://lab.example/encoded?q=1",
            settings=ProbeModeSettings(
                mode="safe",
                browser_evaluate=_eval,
                stats=stats_b,
                max_params=2,
                max_forms=0,
                scan_id="scan-B",
            ),
        )
    )
    assert any(
        len(f) > 4 and f[4].get("proof", {}).get("validation_state") == STATE_BROWSER_EXEC
        for f in fa
        if f[0] == "xss"
    )
    assert not any(
        len(f) > 4 and f[4].get("proof", {}).get("validation_state") == STATE_BROWSER_EXEC
        for f in fb
        if f[0] == "xss"
    )
    assert any(s.get("scan_id") == "scan-A" for s in seen)
    # Encoded/inert control must not invoke browser confirmation (no live markup).
    assert not any(s.get("scan_id") == "scan-B" for s in seen)
    nonces = [s.get("nonce") for s in seen if s.get("nonce")]
    assert len(nonces) == len(set(nonces))


def test_candidate_vs_inventory_metrics_not_interchangeable():
    from verifiers.runtime.lifecycle import (
        OUTCOME_TERMINAL_CONFIRMED,
        OUTCOME_TERMINAL_NEGATIVE,
        compute_published_metrics,
        empty_lifecycle_row,
        apply_probe_outcome,
    )

    def _row(path, family, cls, state, sched="attempted", must_not=False):
        row = empty_lifecycle_row(
            plan_item={
                "fixture_id": f"c:{path}:{family}",
                "path": path,
                "family": family,
                "support_classification": "supported_active",
                "schedule_status": sched,
                "classification": cls,
                "must_not_confirm": must_not,
                "capability_maturity_before": "executable_unvalidated",
                "deps_available_for_live_recall": True,
            },
            mode="lab",
            discovered_url=f"https://t{path}",
        )
        if sched == "attempted":
            apply_probe_outcome(
                row,
                probe_sent=True,
                result_state=state,
                finding_emitted=state == "browser_execution_confirmed",
                evidence={},
            )
        else:
            row["schedule_status"] = sched
            row["lifecycle_outcome"] = "nonterminal"
        return row

    # Two candidate rows for same inventory path + one other
    rows = [
        _row("/xss/reflected", "xss", "vulnerable", "browser_execution_confirmed"),
        _row("/xss/reflected", "xss", "vulnerable", "reflected_only"),  # variant
        _row("/xss/encoded", "xss", "control", "negative", must_not=True),
        _row("/other", "xss", "vulnerable", "", sched="discovery_missing"),
    ]
    # Force second reflected row path-same by tweaking fixture only — both path=/xss/reflected
    rows[1]["fixture_id"] = "c:/xss/reflected:xss:q2"
    inv = [
        {"path": "/xss/reflected", "family": "xss", "classification": "vulnerable"},
        {"path": "/xss/encoded", "family": "xss", "classification": "control", "must_not_confirm": True},
        {"path": "/other", "family": "xss", "classification": "vulnerable"},
    ]
    pub = compute_published_metrics(
        rows,
        mode="lab",
        catalog_support_counts={"supported_active": 3},
        inventory_identities=inv,
    )
    assert pub["metric_universes"]["candidate_count"] == 4
    assert pub["metric_universes"]["inventory_count"] == 3
    assert pub["candidate_metrics"]["universe_size"] == 4
    assert pub["inventory_metrics"]["universe_size"] == 3
    # discovery_missing must not be labelled legitimate exclusion
    gaps = pub["inventory_metrics"]["discovery_gaps"]
    assert any(g["path"] == "/other" for g in gaps)
    assert all(g.get("legitimate_exclusion") is False for g in gaps)
    assert pub["inventory_metrics"]["negative_control_fp_rate"]["numerator"] == 0


def test_no_horizon_paths_in_production_runtime_packages():
    """Hardcode sweep: production packages must not embed Horizon fixture paths."""
    from pathlib import Path

    banned = (
        "/xss/reflected",
        "/xss/encoded",
        "/xss/dom-clobber-safe",
        "horizon-catalog.onrender.com",
    )
    roots = [
        Path("verifiers/runtime"),
        Path("active_probe_kit.py"),
        Path("active_probe_browser.py"),
        Path("dom_clobber"),
    ]
    hits = []
    for root in roots:
        files = [root] if root.is_file() else list(root.rglob("*.py"))
        for f in files:
            text = f.read_text(encoding="utf-8")
            for b in banned:
                if b in text:
                    hits.append(f"{f}:{b}")
    assert hits == [], f"Horizon hardcodes in production packages: {hits}"
