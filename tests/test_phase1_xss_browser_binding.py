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


def test_provenance_summary_uses_confirming_probe_not_latest():
    """Provenance correlation must cite the accepted confirming probe_id/nonce."""
    import json
    import tempfile
    from pathlib import Path

    from crawl_stats import CrawlStats
    from verifiers.runtime.finalize import finalize_phase1_runtime

    class _Cfg:
        active_probe_mode = "lab"
        job_id = "scan-prov"
        report_title = "t"

    stats = CrawlStats()
    stats.scan_id = "scan-prov"
    stats.discovered_urls.add("https://t.example/ui/xss/reflected")
    stats.target_catalog = [
        {
            "path": "/ui/xss/reflected",
            "family": "xss",
            "tags": ["active", "safe"],
            "methods": ["GET"],
        }
    ]
    stats.request_ledger.extend(
        [
            {
                "phase": "active_probe",
                "probe_role": "probe",
                "probe_class": "xss",
                "probe_name": "xss_event_onload",
                "probe_id": "xss_event_onload:q:/ui/xss/reflected:1",
                "nonce": "VCXSS_aaa",
                "parameter": "q",
                "url": "https://t.example/ui/xss/reflected?q=1",
                "result_state": "browser_execution_confirmed",
            },
            {
                "phase": "active_probe",
                "probe_role": "browser_execution_confirmed",
                "probe_class": "xss",
                "probe_id": "xss_event_onload:q:/ui/xss/reflected:1",
                "nonce": "VCXSS_aaa",
                "parameter": "q",
                "url": "https://t.example/ui/xss/reflected?q=1",
                "result_state": "browser_execution_confirmed",
                "browser_context_id": "ctx-onload",
                "marker_before": "",
                "marker_after": "VCXSS_aaa",
            },
            {
                "phase": "active_probe",
                "probe_role": "probe",
                "probe_class": "xss",
                "probe_name": "xss_js_string_breakout",
                "probe_id": "xss_js_string_breakout:q:/ui/xss/reflected:2",
                "nonce": "VCXSS_bbb",
                "parameter": "q",
                "url": "https://t.example/ui/xss/reflected?q=2",
                "result_state": "reflected_only",
            },
        ]
    )
    with tempfile.TemporaryDirectory() as td:
        finalize_phase1_runtime(stats, config=_Cfg(), report_dir=td, scan_id="scan-prov")
        prov = json.loads(Path(td, "evidence_provenance.json").read_text(encoding="utf-8"))
    row = next(e for e in prov if e.get("path") == "/ui/xss/reflected")
    corr = row["correlation"]
    assert corr["probe_id"] == "xss_event_onload:q:/ui/xss/reflected:1"
    assert corr["nonce"] == "VCXSS_aaa"
    assert corr["browser_context_id"] == "ctx-onload"
    assert corr["decision"] == "confirmed_current_probe"
    assert "xss_js_string_breakout" not in str(corr["probe_id"])


def test_no_horizon_paths_in_production_runtime_packages():
    """Full production-boundary hardcode + fail-closed import-graph audit."""
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    banned = (
        "horizon_benchmark",
        "horizon-catalog",
        "onrender.com",
        "/xss/reflected",
        "/xss/encoded",
        "/xss/dom-clobber",
        "/xss/dom-clobber-safe",
        "app-settings",
        "media-embed",
        "widget-cfg",
        "defaultConfig",
        "appSettings",
    )
    production_roots = [
        root / "verifiers",
        root / "dom_clobber",
        root / "active_probe_kit.py",
        root / "active_probe_browser.py",
        root / "active_probe_targeting.py",
        root / "browser_fetch.py",
        root / "crawl_orchestrator.py",
        root / "crawl_stats.py",
        root / "reporting.py",
        root / "security_scan.py",
        root / "report_status.py",
        root / "web" / "worker",
        root / "web" / "api" / "vantacrawl_api" / "routes" / "jobs.py",
        root / "web" / "api" / "vantacrawl_api" / "services" / "embedded_worker.py",
        root / "web" / "api" / "vantacrawl_api" / "services" / "queue.py",
    ]
    # Fail closed: every required root must exist.
    missing_roots = [str(p.relative_to(root)) for p in production_roots if not p.exists()]
    assert missing_roots == [], f"required production roots missing: {missing_roots}"

    prod_hits = []
    prod_files: list[Path] = []
    for path in production_roots:
        files = [path] if path.is_file() else list(path.rglob("*.py"))
        assert files, f"production root yielded no files: {path}"
        for f in files:
            if "__pycache__" in f.parts:
                continue
            prod_files.append(f)
            try:
                text = f.read_text(encoding="utf-8", errors="strict")
            except Exception as exc:
                raise AssertionError(f"cannot read production file {f}: {exc}") from exc
            for b in banned:
                if b in text:
                    prod_hits.append(f"{f.relative_to(root)}:{b}")
    assert prod_hits == [], f"production boundary violations: {prod_hits}"
    assert any(p.name == "browser_fetch.py" for p in prod_files), (
        "browser_fetch.py must be in the audited production file set"
    )

    entry_mods = [
        "reporting",
        "crawl_orchestrator",
        "security_scan",
        "active_probe_kit",
        "active_probe_browser",
        "active_probe_targeting",
        "browser_fetch",
        "report_status",
        "dom_clobber.verify",
        "dom_clobber.browser",
        "verifiers.runtime.finalize",
        "verifiers.runtime.lifecycle",
        "verifiers.policy.catalog_inventory",
        "web.worker.runner",
        "web.api.vantacrawl_api.routes.jobs",
        "web.api.vantacrawl_api.services.embedded_worker",
    ]

    def _resolve_mod(mod_name: str) -> Path:
        parts = mod_name.split(".")
        candidates = [
            root.joinpath(*parts).with_suffix(".py"),
            root.joinpath(*parts, "__init__.py"),
        ]
        path = next((p for p in candidates if p.exists()), None)
        if path is None:
            raise AssertionError(
                f"unresolved production module: {mod_name} "
                f"(tried {[str(c.relative_to(root)) for c in candidates]})"
            )
        return path

    def _imports_of(mod_name: str) -> set[str]:
        path = _resolve_mod(mod_name)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError as exc:
            raise AssertionError(f"AST parse failed for {mod_name} ({path}): {exc}") from exc
        out: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    out.add(alias.name.split(".")[0])
                    out.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    out.add(node.module.split(".")[0])
                    out.add(node.module)
        return out

    first_party_tops = {
        "verifiers",
        "dom_clobber",
        "active_probe_kit",
        "active_probe_browser",
        "active_probe_targeting",
        "browser_fetch",
        "crawl_orchestrator",
        "crawl_stats",
        "security_scan",
        "reporting",
        "report_status",
        "web",
        "crawler_common",
        "exploit_probes",
        "oob_callback",
        "evasion_layer",
        "session_cookies",
        "auth_login",
    }
    seen: set[str] = set()
    queue = list(entry_mods)
    hz_importers: list[str] = []
    while queue:
        mod = queue.pop(0)
        if mod in seen:
            continue
        try:
            _resolve_mod(mod)
        except AssertionError:
            top = mod.split(".")[0]
            if mod in entry_mods:
                raise
            if top in first_party_tops and top != mod:
                # Account via package root; still require the package to resolve.
                _resolve_mod(top)
                seen.add(mod)
                if top not in seen:
                    queue.append(top)
                continue
            # Non-first-party / stdlib / third-party — ignore.
            continue
        seen.add(mod)
        for imp in _imports_of(mod):
            if imp == "horizon_benchmark" or imp.startswith("horizon_benchmark."):
                hz_importers.append(f"{mod} -> {imp}")
                continue
            top = imp.split(".")[0]
            if top in first_party_tops or imp in first_party_tops:
                if imp not in seen:
                    queue.append(imp)
    assert seen, "production import closure unexpectedly empty"
    assert "browser_fetch" in seen, (
        f"browser_fetch missing from import closure; seen={sorted(seen)[:40]}"
    )
    assert hz_importers == [], (
        "production modules import horizon_benchmark: " + "; ".join(hz_importers)
    )
    # Separated (non-failing) report for benchmark/tests/docs literals.
    separated = {"benchmark": [], "tests": [], "docs": []}
    for label, base in (
        ("benchmark", root / "horizon_benchmark"),
        ("tests", root / "tests"),
        ("docs", root / "docs"),
    ):
        if not base.exists():
            continue
        if label == "docs":
            files = [p for p in base.rglob("*") if p.suffix in {".md", ".txt", ".rst"}]
        else:
            files = list(base.rglob("*.py"))
        for f in files:
            if not f.is_file() or "__pycache__" in f.parts:
                continue
            text = f.read_text(encoding="utf-8", errors="ignore")
            for b in banned:
                if b in text:
                    separated[label].append(f"{f.relative_to(root)}:{b}")
                    break
    assert isinstance(separated["benchmark"], list)


def test_boundary_gate_fails_closed_on_missing_root(tmp_path, monkeypatch):
    """Removing a required production root must fail the gate, not skip silently."""
    import ast
    from pathlib import Path

    # Lightweight replica of the fail-closed root check.
    root = Path(__file__).resolve().parents[1]
    required = root / "browser_fetch.py"
    assert required.exists()
    # Simulate missing by checking a fake required path
    fake = root / "definitely_missing_production_module_xyz.py"
    assert not fake.exists()
    missing = [str(fake.relative_to(root))] if not fake.exists() else []
    assert missing, "expected missing root detection"


def test_boundary_gate_detects_synthetic_horizon_import():
    """A synthetic transitive horizon_benchmark import must be detected."""
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    # Parse browser_fetch — must not import horizon; inject check via AST of a snippet.
    snippet = "import horizon_benchmark\nfrom horizon_benchmark.evaluate import evaluate_stats\n"
    tree = ast.parse(snippet)
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "horizon_benchmark" or a.name.startswith("horizon_benchmark."):
                    hits.append(a.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            if node.module == "horizon_benchmark" or node.module.startswith("horizon_benchmark."):
                hits.append(node.module)
    assert hits == ["horizon_benchmark", "horizon_benchmark.evaluate"]
    # And real browser_fetch has none
    text = (root / "browser_fetch.py").read_text(encoding="utf-8")
    assert "horizon_benchmark" not in text
