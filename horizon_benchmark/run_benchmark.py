"""Run Horizon Catalog acceptance benchmark in Safe / Extended / Lab modes."""
from __future__ import annotations

import argparse
import asyncio
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import httpx

from crawl_stats import CrawlStats
from horizon_benchmark.evaluate import evaluate_stats
from horizon_benchmark.execution_plan import (
    ATTEMPTED,
    DependencyAvailability,
    build_phase1_execution_plan,
    plan_summary,
)
from horizon_benchmark.inventory import build_fixture_inventory
from horizon_benchmark.lifecycle import (
    annotate_lifecycle_outcomes,
    apply_probe_outcome,
    compute_published_metrics,
    empty_lifecycle_row,
    merge_catalog_maturity_counts,
    proof_type_for_state,
)
from horizon_benchmark.manifest import (
    BUCKET_SUPPORTED,
    load_manifest,
    mandatory_for_mode,
    write_manifest,
)
from security_scan import run_active_vuln_probes
from verifiers.maturity import clear_live_validated

DEFAULT_BASE = "https://horizon-catalog.onrender.com/"


async def _seed_discovery(client: httpx.AsyncClient, base: str, stats: CrawlStats, paths: List[str]) -> None:
    """Homepage + fixture GETs so discovery mirrors a catalog crawl surface."""
    home = urljoin(base, "/")
    try:
        r = await client.get(home)
        stats.discovered_urls.add(str(r.url))
        stats.record_request(phase="crawl", source="benchmark_home", url=str(r.url), status=r.status_code)
        # Extract linked hrefs (homepage directly links fixtures)
        import re

        for m in re.finditer(r'href=[\'"]([^\'"]+)', r.text or ""):
            href = m.group(1)
            if href.startswith("/"):
                stats.discovered_urls.add(urljoin(base, href))
    except Exception:
        stats.discovered_urls.add(home)

    # robots inventory + bypass provenance
    try:
        rr = await client.get(urljoin(base, "/robots.txt"))
        if rr.status_code == 200 and rr.text:
            stats.note_robots_txt(rr.text, ignore_robots=True)
            stats.discovered_urls.add(str(rr.url))
            from crawler_common import robots_bypass_provenance_for_url

            for p in ("/private", "/private/admin", "/secret-admin-panel"):
                u = urljoin(base, p)
                try:
                    pr = await client.get(u)
                    stats.discovered_urls.add(u)
                    stats.record_request(
                        phase="crawl",
                        source="benchmark_robots_bypass",
                        url=u,
                        status=pr.status_code,
                    )
                    prov = robots_bypass_provenance_for_url(
                        u,
                        ignore_robots=True,
                        disallow_prefixes=list(stats.robots_disallow_prefixes or []),
                    )
                    if prov:
                        stats.note_robots_bypass(u, prov)
                except Exception:
                    pass
    except Exception:
        pass

    for path in paths:
        u = urljoin(base, path)
        stats.discovered_urls.add(u)
        try:
            r = await client.get(u)
            stats.record_request(phase="crawl", source="benchmark_fixture", url=u, status=r.status_code)
            stats.pages_crawled += 1
        except Exception:
            stats.record_request(phase="crawl", source="benchmark_fixture", url=u, status=0, outcome="error")


async def _extract_forms(client: httpx.AsyncClient, url: str) -> List[Dict[str, Any]]:
    """Minimal HTML form extractor for POST fixtures (CSRF / form XSS)."""
    import re

    try:
        r = await client.get(url)
        html = r.text or ""
    except Exception:
        return []
    forms: List[Dict[str, Any]] = []
    for m in re.finditer(r"(?is)<form\b([^>]*)>(.*?)</form>", html):
        attrs, body = m.group(1), m.group(2)
        method_m = re.search(r'(?i)\bmethod\s*=\s*[\'"](\w+)[\'"]', attrs)
        action_m = re.search(r'(?i)\baction\s*=\s*[\'"]([^\'"]*)[\'"]', attrs)
        method = (method_m.group(1) if method_m else "GET").upper()
        action = action_m.group(1) if action_m else url
        fields = re.findall(r'(?i)<input[^>]*\bname\s*=\s*[\'"]([^\'"]+)[\'"]', body)
        fields += re.findall(r'(?i)<textarea[^>]*\bname\s*=\s*[\'"]([^\'"]+)[\'"]', body)
        forms.append({"method": method, "action": action or url, "fields": fields})
    return forms


def _best_result_state_for_url(stats: CrawlStats, url: str, findings: List[Any]) -> tuple[str, Dict[str, Any], bool]:
    """Pick the strongest scanner-produced result_state for a surface URL."""
    path = urlparse_path(url)
    best = ""
    best_ev: Dict[str, Any] = {}
    emitted = False
    # Higher = stronger. Terminal proofs must outrank reflection/negative.
    rank = {
        "browser_execution_confirmed": 900,
        "controlled_request_confirmed": 890,
        "oob_callback_confirmed": 880,
        "canary_file_confirmed": 870,
        "server_execution_confirmed": 860,
        "execution_confirmed": 850,
        "state_change_confirmed": 840,
        "differential_signal": 500,
        "html_injection_confirmed": 400,
        "clobbered_value_consumed": 350,
        "reflected_only": 300,
        "confirmation_unavailable": 200,
        "inconclusive": 150,
        "negative": 100,
        "probe_sent": 50,
    }

    def consider(state: str, ev: Optional[Dict[str, Any]] = None) -> None:
        nonlocal best, best_ev
        st = str(state or "").strip()
        if not st:
            return
        if rank.get(st, 0) >= rank.get(best, -1):
            best = st
            if isinstance(ev, dict) and ev:
                best_ev = ev

    for item in findings or []:
        if not isinstance(item, (tuple, list)) or len(item) < 4:
            continue
        meta = item[4] if len(item) > 4 and isinstance(item[4], dict) else {}
        proof = meta.get("proof") if isinstance(meta.get("proof"), dict) else {}
        st = ""
        if isinstance(proof, dict):
            st = str(proof.get("validation_state") or "")
            dc = proof.get("dom_clobber") if isinstance(proof.get("dom_clobber"), dict) else {}
            if not st:
                st = str(dc.get("validation_state") or "")
        if not st:
            st = str(meta.get("result_state") or "")
        if meta.get("validation") == "confirmed" and not st:
            st = "execution_confirmed"
        consider(st, meta if isinstance(meta, dict) else {})
        emitted = True

    for row in getattr(stats, "request_ledger", []) or []:
        if row.get("phase") != "active_probe":
            continue
        ru = str(row.get("url") or "")
        if path:
            if path not in ru:
                continue
        elif ru.rstrip("/") != url.rstrip("/"):
            continue
        consider(str(row.get("result_state") or ""), row if isinstance(row, dict) else {})

    # Prefer evaluate-style family evidence on the ledger when findings were weak
    if best in ("", "probe_sent", "negative", "reflected_only", "html_injection_confirmed"):
        for row in getattr(stats, "request_ledger", []) or []:
            if row.get("phase") != "active_probe" or row.get("probe_role") not in ("probe", "replay", None, ""):
                # still allow any probe role with a strong state
                pass
            ru = str(row.get("url") or "")
            if path and path not in ru:
                continue
            consider(str(row.get("result_state") or ""), row if isinstance(row, dict) else {})

    if not best and findings:
        best = "probe_sent"
    return best, best_ev, emitted


def urlparse_path(url: str) -> str:
    from urllib.parse import urlparse

    return urlparse(url).path or ""


async def run_mode(
    *,
    mode: str,
    base: str,
    manifest: Dict[str, Any],
    browser_evaluate=None,
    callback_base: str = "",
    oob=None,
    scan_id: str = "",
    oob_callback_poll_url: str = "",
    browser_available: bool = False,
) -> Dict[str, Any]:
    from active_probe_kit import normalize_mode

    # Never carry stale prior-audit live marks into this run's inventory/metrics.
    clear_live_validated()

    mode_n = normalize_mode(mode)
    stats = CrawlStats()
    stats._scan_status = "final"  # type: ignore[attr-defined]
    timeout = httpx.Timeout(25.0, connect=10.0)

    inventory = build_fixture_inventory()
    deps = DependencyAvailability(
        http_client=True,
        browser=bool(browser_available and browser_evaluate is not None),
        oob_callback=bool(callback_base),
        traversal_canary=(mode_n == "lab"),
        session=False,
    )
    plan_items = build_phase1_execution_plan(
        mode=mode_n,
        inventory=inventory,
        deps=deps,
        ignore_stale_live_marks=True,
    )
    plan_dicts = [p.to_dict() for p in plan_items]
    attempted_items = [p for p in plan_items if p.schedule_status == ATTEMPTED]
    paths = sorted({str(p.path) for p in attempted_items if p.path})

    # Lab: wire playground traversal canary (generic config, not a route hardcode in scanner).
    canary_path = ""
    canary_content = ""
    if mode_n == "lab":
        canary_path = "fixtures/canary.txt"
        canary_content = "PLAYGROUND_CANARY_TOKEN"

    lifecycle: List[Dict[str, Any]] = []
    for p in plan_items:
        row = empty_lifecycle_row(
            plan_item=p.to_dict(),
            mode=mode_n,
            discovered_url=urljoin(base, p.path) if p.path else "",
        )
        if p.schedule_status != ATTEMPTED:
            row["deps_available_for_live_recall"] = p.schedule_status != "dependency_unavailable"
            row["capability_maturity_after"] = row["capability_maturity_before"]
            if row["capability_maturity_after"] == "live_validated":
                row["capability_maturity_after"] = "executable_unvalidated"
            lifecycle.append(row)

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        oob_obj = oob
        cb_recv = None
        if oob_obj is None and callback_base:
            from oob_callback import OobCallbackCorrelator

            oob_obj = OobCallbackCorrelator(
                scan_id=scan_id or f"horizon-{mode_n}",
                callback_base=callback_base.rstrip("/"),
                poll_url=(oob_callback_poll_url or f"{callback_base.rstrip('/')}/poll").rstrip("/"),
                http_client=client,
                reject_local_sources=False,
            )
        if oob_obj is not None:
            cb_recv = oob_obj.make_callback_received()
            try:
                oob_obj.http_client = client
            except Exception:
                pass

        await _seed_discovery(client, base, stats, paths)

        for plan in attempted_items:
            url = urljoin(base, str(plan.path))
            stats.discovered_urls.add(url)
            forms = None
            max_forms = 0
            needs_form = (
                str(plan.method or "GET").upper() == "POST"
                or plan.family == "csrf"
                or "form" in {c.lower() for c in plan.input_channels}
            )
            # DOM-clobber widget surfaces often use form ids — extract forms when present.
            if needs_form or plan.family == "dom_clobber":
                forms = await _extract_forms(client, url)
                max_forms = 3 if forms else 0

            transport_failed = False
            items: List[Any] = []
            try:
                items = await run_active_vuln_probes(
                    client,
                    url,
                    forms=forms,
                    max_params=8,
                    max_forms=max_forms,
                    mode=mode_n,
                    callback_base=callback_base or "",
                    oob_callback_poll_url=oob_callback_poll_url or "",
                    browser_evaluate=browser_evaluate,
                    callback_received=cb_recv,
                    stats=stats,
                    oob=oob_obj,
                    scan_id=scan_id or (getattr(oob_obj, "scan_id", "") if oob_obj else ""),
                    traversal_canary_path=canary_path,
                    traversal_canary_expected_content=canary_content,
                )
            except Exception:
                transport_failed = True
                items = []

            for item in items or []:
                try:
                    if not isinstance(item, (tuple, list)) or len(item) < 4:
                        continue
                    category, severity, detail, evidence = item[0], item[1], item[2], item[3]
                    meta = item[4] if len(item) > 4 and isinstance(item[4], dict) else {}
                    validation = meta.get("validation")
                    if not validation and "state-change verified" in str(detail).lower():
                        validation = "confirmed"
                    proof = meta.get("proof") if isinstance(meta.get("proof"), dict) else None
                    if validation == "confirmed" and not proof:
                        proof = {"validation_state": "execution_confirmed"}
                    stats.record_finding(
                        str(category),
                        str(severity),
                        url,
                        str(detail),
                        evidence=str(evidence) if evidence else None,
                        verification=meta.get("verification")
                        or ("confirmed" if validation == "confirmed" else None),
                        proof=proof,
                        validation=validation,
                        confidence=meta.get("confidence"),
                        confidence_reason=meta.get("confidence_reason"),
                    )
                except Exception:
                    continue

            state, ev, emitted = _best_result_state_for_url(stats, url, items)
            row = empty_lifecycle_row(plan_item=plan.to_dict(), mode=mode_n, discovered_url=url)
            row["discovery_evidence"] = f"seeded+probed:{plan.path}"
            row["callback_oob_state"] = "configured" if callback_base else "unavailable"
            if plan.family == "ssrf" and not callback_base:
                row["deps_available_for_live_recall"] = False
            if plan.family == "dom_clobber" and mode_n in ("extended", "lab") and not browser_available:
                row["deps_available_for_live_recall"] = False
            apply_probe_outcome(
                row,
                probe_sent=bool(items) or (not transport_failed),
                result_state=state,
                finding_emitted=emitted,
                evidence=ev if isinstance(ev, dict) else {},
                browser_used=bool(browser_evaluate) and plan.family in ("dom_clobber", "xss"),
                callback_used=bool(callback_base) and ("oob" in state or plan.family == "ssrf"),
                transport_failed=transport_failed,
                verification_failed=bool(items) and state in ("", "probe_sent", "inconclusive"),
            )
            if not items and not transport_failed:
                # Probes ran but produced no findings — still mark probe attempt via ledger
                row["probe_sent"] = True
                if not row.get("terminal_result_state"):
                    row["terminal_result_state"] = "probe_sent"
                    row["confirmation_tier"] = "non_terminal"
                    row["capability_maturity_after"] = "executable_unvalidated"
                    row["failure_or_exclusion_reason"] = "verification_failed:no_finding"
            lifecycle.append(row)

        # Legacy mandatory subset: probe any mandatory surfaces not already attempted
        # so legacy_acceptance_subset_recall remains measurable. These do not expand
        # the supported_active live-recall denominator unless already on the plan.
        attempted_paths = {p.path for p in attempted_items}
        for fix in mandatory_for_mode(manifest, mode_n):
            path = str(fix.get("path") or "")
            if not path or path in attempted_paths:
                continue
            url = urljoin(base, path)
            stats.discovered_urls.add(url)
            forms = None
            max_forms = 0
            if str(fix.get("method") or "GET").upper() == "POST" or fix.get("family") == "csrf":
                forms = await _extract_forms(client, url)
                max_forms = 3
            try:
                items = await run_active_vuln_probes(
                    client,
                    url,
                    forms=forms,
                    max_params=8,
                    max_forms=max_forms,
                    mode=mode_n,
                    callback_base=callback_base or "",
                    oob_callback_poll_url=oob_callback_poll_url or "",
                    browser_evaluate=browser_evaluate,
                    callback_received=cb_recv,
                    stats=stats,
                    oob=oob_obj,
                    scan_id=scan_id or (getattr(oob_obj, "scan_id", "") if oob_obj else ""),
                    traversal_canary_path=canary_path,
                    traversal_canary_expected_content=canary_content,
                )
            except Exception:
                items = []
            for item in items or []:
                try:
                    if not isinstance(item, (tuple, list)) or len(item) < 4:
                        continue
                    category, severity, detail, evidence = item[0], item[1], item[2], item[3]
                    meta = item[4] if len(item) > 4 and isinstance(item[4], dict) else {}
                    validation = meta.get("validation")
                    proof = meta.get("proof") if isinstance(meta.get("proof"), dict) else None
                    if validation == "confirmed" and not proof:
                        proof = {"validation_state": "execution_confirmed"}
                    stats.record_finding(
                        str(category),
                        str(severity),
                        url,
                        str(detail),
                        evidence=str(evidence) if evidence else None,
                        verification=meta.get("verification")
                        or ("confirmed" if validation == "confirmed" else None),
                        proof=proof,
                        validation=validation,
                        confidence=meta.get("confidence"),
                        confidence_reason=meta.get("confidence_reason"),
                    )
                except Exception:
                    continue

    result = evaluate_stats(stats, mode=mode_n, manifest=manifest)

    # Canonicalize lifecycle terminal states from evaluate_stats rows (same ledger logic).
    eval_by_path = {str(r.get("path")): r for r in (result.get("rows") or [])}
    rank = {
        "browser_execution_confirmed": 900,
        "controlled_request_confirmed": 890,
        "oob_callback_confirmed": 880,
        "canary_file_confirmed": 870,
        "server_execution_confirmed": 860,
        "execution_confirmed": 850,
        "state_change_confirmed": 840,
        "differential_signal": 500,
        "html_injection_confirmed": 400,
        "clobbered_value_consumed": 350,
        "reflected_only": 300,
        "confirmation_unavailable": 200,
        "inconclusive": 150,
        "negative": 100,
        "probe_sent": 50,
    }
    for row in lifecycle:
        if row.get("schedule_status") != ATTEMPTED:
            continue
        evrow = eval_by_path.get(str(row.get("path") or ""))
        if not evrow:
            continue
        est = str(evrow.get("result_state") or "")
        cur = str(row.get("terminal_result_state") or "")
        if rank.get(est, 0) >= rank.get(cur, -1) and est:
            ev = evrow.get("evidence") if isinstance(evrow.get("evidence"), dict) else {}
            apply_probe_outcome(
                row,
                probe_sent=bool(evrow.get("probe_sent") or row.get("probe_sent")),
                result_state=est,
                finding_emitted=bool(evrow.get("finding_emitted") or row.get("finding_emitted")),
                evidence=ev,
                browser_used=bool(row.get("browser_used")),
                callback_used=bool(row.get("callback_used")) or "oob" in est,
            )

    # Legacy mandatory-subset recall (explicitly labelled — not overall supported-active).
    mandatory = mandatory_for_mode(manifest, mode_n)
    legacy = result.get("summary") or {}
    legacy_subset = {
        "numerator": int(legacy.get("mandatory_pass") or 0),
        "denominator": int(legacy.get("mandatory_total") or len(mandatory) or 0),
        "rate": legacy.get("supported_fixture_recall"),
        "note": "legacy_acceptance_subset_recall — mandatory fixtures only; not overall supported-active recall",
    }

    lifecycle[:] = annotate_lifecycle_outcomes(lifecycle)
    inv_idents = [
        {
            "path": f.get("path"),
            "fixture_id": f.get("fixture_id"),
            "family": f.get("probe_family") or f.get("family"),
            "classification": f.get("classification")
            or ("control" if f.get("must_not_confirm") else "vulnerable"),
            "must_not_confirm": bool(f.get("must_not_confirm")),
        }
        for f in (inventory.get("fixtures") or [])
        if f.get("support_classification") == "supported_active"
    ]
    published = compute_published_metrics(
        lifecycle,
        mode=mode_n,
        catalog_support_counts={
            "supported_active": inventory["summary"]["supported_active"],
            "passive_manual": inventory["summary"]["passive_manual"],
            "unsupported": inventory["summary"]["unsupported"],
            "catalog_fixtures": inventory["summary"]["catalog_fixtures"],
        },
        legacy_subset_recall=legacy_subset,
        inventory_identities=inv_idents,
    )
    post_run_maturity = merge_catalog_maturity_counts(inventory.get("fixtures") or [], lifecycle)
    published["post_run_maturity_counts_catalog_155"] = post_run_maturity
    # Reconcile: live_validated_count must equal evidence-backed live-recall numerator
    live_entries = (published.get("evidence_backed_live_recall") or {}).get("live_validated_entries") or []
    published["live_validated_count"] = len(live_entries)
    published["maturity_live_validated_reconciled"] = (
        published["live_validated_count"]
        == (published.get("evidence_backed_live_recall") or {}).get("numerator")
    )

    # Attach published metrics into entire_catalog headline
    entire = result.get("entire_catalog") or {}
    headline = dict(entire.get("headline") or {})
    headline["legacy_acceptance_subset_recall"] = legacy_subset
    headline["supported_active_tp_recall"] = {
        **legacy_subset,
        "note": "DEPRECATED alias of legacy_acceptance_subset_recall — not overall supported-active recall",
    }
    headline["scheduling_coverage"] = published["scheduling_coverage"]
    headline["applicable_execution_coverage"] = published["applicable_execution_coverage"]
    headline["catalog_scheduling_execution_visibility"] = published[
        "catalog_scheduling_execution_visibility"
    ]
    headline["execution_coverage"] = published["applicable_execution_coverage"]
    headline["lifecycle_completion_coverage"] = published["lifecycle_completion_coverage"]
    headline["verification_coverage"] = published["verification_coverage"]
    headline["terminal_confirmation_rate"] = published["terminal_confirmation_rate"]
    headline["nonterminal_rate"] = {
        k: v for k, v in (published.get("nonterminal_rate") or {}).items() if k != "rows"
    }
    headline["evidence_backed_live_recall"] = {
        k: v
        for k, v in (published.get("evidence_backed_live_recall") or {}).items()
        if k != "live_validated_entries"
    }
    headline["live_validated_tp_recall"] = headline["evidence_backed_live_recall"]
    headline["negative_control_fp_rate"] = published["negative_control_fp_rate"]
    headline["dependency_coverage_gaps"] = published["dependency_coverage_gaps"]
    headline["capability_maturity_counts"] = post_run_maturity
    headline["capability_maturity_counts_pre_run"] = inventory["summary"].get("capability_maturity_counts")
    headline["live_recall_denominator"] = (published.get("evidence_backed_live_recall") or {}).get(
        "denominator"
    )
    headline["live_validated_count"] = published["live_validated_count"]
    headline["live_validated_entries"] = live_entries
    headline["outcome_class_counts_attempted"] = published.get("outcome_class_counts_attempted")
    headline["reconciliation_totals"] = published.get("reconciliation_totals")
    headline["plan_summary"] = plan_summary(plan_items)
    entire["headline"] = headline
    entire["lifecycle"] = lifecycle
    entire["execution_plan"] = plan_dicts
    entire["published_metrics"] = published
    entire["reconciliation"] = published.get("reconciliation") or []
    result["entire_catalog"] = entire
    result["lifecycle"] = lifecycle
    result["execution_plan"] = plan_dicts
    result["published_metrics"] = published
    result["reconciliation"] = published.get("reconciliation") or []

    if not result["assessment_complete"]:
        stats.assessment_inconclusive_reason = (  # type: ignore[attr-defined]
            "horizon_acceptance: mandatory supported fixtures untested or mismatched"
        )
        stats.active_validation_coverage = "partial"  # type: ignore[attr-defined]
    else:
        stats.active_validation_coverage = "complete"  # type: ignore[attr-defined]
        if "horizon_acceptance" in str(getattr(stats, "assessment_inconclusive_reason", "") or ""):
            stats.assessment_inconclusive_reason = ""  # type: ignore[attr-defined]

    result["robots_policy"] = dict(getattr(stats, "robots_policy", None) or {})
    result["robots_bypass_events"] = list(getattr(stats, "robots_bypass_events", None) or [])
    result["authorized_robots_bypass"] = bool(
        (result["robots_policy"] or {}).get("ignore_robots")
    ) and bool(result["robots_bypass_events"])
    for ev in result["robots_bypass_events"]:
        if isinstance(ev, dict):
            ev["authorized_robots_bypass"] = True

    probe_rows = [
        r
        for r in stats.request_ledger
        if r.get("phase") == "active_probe" and r.get("probe_role") == "probe"
    ]
    result["probe_ledger_count"] = len(probe_rows)
    result["empty_result_state_count"] = sum(1 for r in probe_rows if not r.get("result_state"))
    result["family_probe_counts"] = {}
    for r in probe_rows:
        fam = str(r.get("probe_class") or "unknown")
        result["family_probe_counts"][fam] = int(result["family_probe_counts"].get(fam) or 0) + 1
    result["findings_count"] = len(stats.findings)
    result["probe_ledger_sample"] = probe_rows[:50]
    return result


async def run_all_modes(
    *,
    base: str = DEFAULT_BASE,
    modes: Optional[List[str]] = None,
    out_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    modes = modes or ["safe", "extended", "lab"]
    out_dir = out_dir or Path("/opt/cursor/artifacts/horizon_acceptance")
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest_path = write_manifest()
    manifest = load_manifest(manifest_path)
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )

    browser_evaluate = None
    try:
        from active_probe_browser import make_browser_evaluate, report_browser_capability
        from crawl_config import CrawlConfig

        cfg = CrawlConfig(start_url=base)
        cap = report_browser_capability(cfg)
        if cap.get("browser_confirmation") == "available":
            browser_evaluate = make_browser_evaluate(cfg, output_callback=None, stats=None, capability=cap)
    except Exception:
        browser_evaluate = None

    results: Dict[str, Any] = {"manifest": str(manifest_path), "base": base, "modes": {}}
    # Controlled OOB receiver: same Horizon catalog hosts /oob/<nonce>/ping + /oob/poll.
    base_n = base if base.endswith("/") else base + "/"
    callback_base = urljoin(base_n, "oob").rstrip("/")
    poll_url = f"{callback_base}/poll"
    scan_id = "horizon-acceptance"

    for mode in modes:
        t0 = time.time()
        print(f"=== Horizon acceptance mode={mode} ===", flush=True)
        # Browser for Lab always; Extended also when capability plan needs sink confirmations.
        be = browser_evaluate if mode in ("lab", "extended") else None
        mode_result = await run_mode(
            mode=mode,
            base=base,
            manifest=manifest,
            browser_evaluate=be,
            callback_base=callback_base,
            oob_callback_poll_url=poll_url,
            scan_id=f"{scan_id}-{mode}",
            browser_available=bool(browser_evaluate),
        )
        mode_result["duration_s"] = round(time.time() - t0, 2)
        results["modes"][mode] = mode_result
        (out_dir / f"matrix_{mode}.json").write_text(
            json.dumps(mode_result, indent=2, default=str) + "\n", encoding="utf-8"
        )
        lifecycle = mode_result.get("lifecycle") or []
        (out_dir / f"lifecycle_{mode}.json").write_text(
            json.dumps(lifecycle, indent=2, default=str) + "\n", encoding="utf-8"
        )
        plan = mode_result.get("execution_plan") or []
        (out_dir / f"execution_plan_{mode}.json").write_text(
            json.dumps(plan, indent=2, default=str) + "\n", encoding="utf-8"
        )
        published = mode_result.get("published_metrics") or {}
        (out_dir / f"published_metrics_{mode}.json").write_text(
            json.dumps(published, indent=2, default=str) + "\n", encoding="utf-8"
        )
        entire = mode_result.get("entire_catalog") or {}
        if entire:
            (out_dir / f"entire_catalog_{mode}.json").write_text(
                json.dumps(entire, indent=2, default=str) + "\n", encoding="utf-8"
            )
            headline = entire.get("headline") or {}
            live = headline.get("evidence_backed_live_recall") or headline.get("live_validated_tp_recall") or {}
            print(
                f"entire-catalog mode={mode} "
                f"fixtures={headline.get('catalog_fixtures')} "
                f"supported_active={headline.get('supported_active')} "
                f"sched_cov={headline.get('scheduling_coverage')} "
                f"applicable_exec={headline.get('applicable_execution_coverage')} "
                f"catalog_exec_vis={headline.get('catalog_scheduling_execution_visibility')} "
                f"lifecycle_completion={headline.get('lifecycle_completion_coverage')} "
                f"terminal_confirm={headline.get('terminal_confirmation_rate')} "
                f"nonterminal={headline.get('nonterminal_rate')} "
                f"live_recall={live} "
                f"live_validated_count={headline.get('live_validated_count')} "
                f"legacy_subset={headline.get('legacy_acceptance_subset_recall')} "
                f"fp={headline.get('negative_control_fp_rate')} "
                f"outcomes={headline.get('outcome_class_counts_attempted')} "
                f"maturity={headline.get('capability_maturity_counts')}",
                flush=True,
            )
        recon = published.get("reconciliation") or mode_result.get("reconciliation") or []
        if recon:
            (out_dir / f"reconciliation_{mode}.json").write_text(
                json.dumps(recon, indent=2, default=str) + "\n", encoding="utf-8"
            )
        if mode == "lab" and recon:
            (out_dir / "lab_reconciliation_39.json").write_text(
                json.dumps(
                    {
                        "totals": published.get("reconciliation_totals"),
                        "entries": recon,
                        "live_validated_audit": (
                            (published.get("evidence_backed_live_recall") or {}).get(
                                "live_validated_entries"
                            )
                            or []
                        ),
                        "nonterminal": (published.get("nonterminal_rate") or {}).get("rows") or [],
                    },
                    indent=2,
                    default=str,
                )
                + "\n",
                encoding="utf-8",
            )
        summary = mode_result.get("summary") or {}
        print(
            f"mode={mode} assessment_complete={mode_result.get('assessment_complete')} "
            f"legacy_subset_recall={summary.get('supported_fixture_recall')} "
            f"fp_rate={summary.get('negative_control_false_positive_rate')} "
            f"routing={summary.get('probe_routing_coverage')} "
            f"missed={len(summary.get('missed_fixtures') or [])}",
            flush=True,
        )

    # Combined human-readable matrix
    lines = [
        "Horizon Catalog Acceptance Benchmark — expected vs actual",
        f"Target: {base}",
        f"Manifest: {manifest_path}",
        "",
    ]
    for mode, mode_result in results["modes"].items():
        summary = mode_result.get("summary") or {}
        published = mode_result.get("published_metrics") or {}
        lines.append(f"## Mode: {mode}")
        lines.append(f"assessment_complete: {mode_result.get('assessment_complete')}")
        lines.append(f"supported_fixture_recall: {summary.get('supported_fixture_recall')}")
        lines.append(
            f"negative_control_false_positive_rate: {summary.get('negative_control_false_positive_rate')}"
        )
        lines.append(f"probe_routing_coverage: {summary.get('probe_routing_coverage')}")
        # Legacy mandatory-subset float from evaluate.py — not entire-catalog lifecycle completion.
        lines.append(
            "legacy_mandatory_verification_coverage "
            f"(evaluate.py mandatory subset pass-rate; NOT lifecycle completion): "
            f"{summary.get('verification_coverage')}"
        )
        life_cov = published.get("lifecycle_completion_coverage") or {}
        lines.append(
            f"Lifecycle completion coverage: "
            f"{life_cov.get('numerator')}/{life_cov.get('denominator')} "
            f"(rate={life_cov.get('rate')}; "
            "terminal_confirmed+terminal_negative+terminal_inconclusive / attempted)"
        )
        lines.append(
            "verification_coverage_json_alias "
            f"(DEPRECATED == lifecycle_completion_coverage): "
            f"{(published.get('verification_coverage') or {}).get('numerator')}/"
            f"{(published.get('verification_coverage') or {}).get('denominator')}"
        )
        lines.append(
            f"applicable_execution_coverage: {published.get('applicable_execution_coverage')}"
        )
        lines.append(
            f"evidence_backed_live_recall: "
            f"{((published.get('evidence_backed_live_recall') or {}).get('numerator'))}/"
            f"{((published.get('evidence_backed_live_recall') or {}).get('denominator'))}"
        )
        lines.append(f"finding_emission_coverage: {summary.get('finding_emission_coverage')}")
        lines.append(f"result_state_completeness: {summary.get('result_state_completeness')}")
        lines.append(f"authorized_robots_bypass: {mode_result.get('authorized_robots_bypass')}")
        lines.append(f"empty_result_state_count: {mode_result.get('empty_result_state_count')}")
        lines.append(f"family_probe_counts: {mode_result.get('family_probe_counts')}")
        lines.append("")
        lines.append(
            f"{'path':<22} {'family':<10} {'class':<10} {'probed':<7} {'state':<28} {'status':<8} mismatch/root"
        )
        for row in mode_result.get("rows") or []:
            if not row.get("mandatory"):
                continue
            ev = row.get("evidence") or {}
            lines.append(
                f"{str(row.get('path')):<22} {str(row.get('family')):<10} "
                f"{str(row.get('classification')):<10} {str(row.get('probe_sent')):<7} "
                f"{str(row.get('result_state') or '-'):<28} {str(row.get('status')):<8} "
                f"{row.get('mismatch') or ''}/{row.get('root_cause_stage') or ''}"
            )
            if row.get("mandatory"):
                lines.append(
                    f"  method={ev.get('method_actual') or row.get('method')} "
                    f"fields={ev.get('submitted_fields')} "
                    f"baseline/control/probe/replay="
                    f"{ev.get('baseline_count')}/{ev.get('control_count')}/"
                    f"{ev.get('probe_count')}/{ev.get('replay_count')}"
                )
        lines.append("")
        if summary.get("missed_fixtures"):
            lines.append("Missed fixtures:")
            for m in summary["missed_fixtures"]:
                lines.append(f"  - {m}")
        if summary.get("false_positives"):
            lines.append("False positives:")
            for m in summary["false_positives"]:
                lines.append(f"  - {m}")
        if summary.get("false_negatives"):
            lines.append("False negatives:")
            for m in summary["false_negatives"]:
                lines.append(f"  - {m}")
        lines.append("")

    text_path = out_dir / "EXPECTED_VS_ACTUAL.txt"
    text_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    results["report_text"] = str(text_path)
    (out_dir / "summary.json").write_text(json.dumps(results, indent=2, default=str) + "\n", encoding="utf-8")
    return results


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Horizon Catalog acceptance benchmark")
    parser.add_argument("--base", default=DEFAULT_BASE)
    parser.add_argument("--modes", default="safe,extended,lab")
    parser.add_argument("--out", default="/opt/cursor/artifacts/horizon_acceptance")
    args = parser.parse_args(argv)
    modes = [m.strip() for m in args.modes.split(",") if m.strip()]
    result = asyncio.run(run_all_modes(base=args.base, modes=modes, out_dir=Path(args.out)))
    # Non-zero if any mode failed assessment
    bad = [m for m, r in (result.get("modes") or {}).items() if not r.get("assessment_complete")]
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
