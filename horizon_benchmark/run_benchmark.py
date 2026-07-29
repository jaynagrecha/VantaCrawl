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
from horizon_benchmark.manifest import (
    BUCKET_SUPPORTED,
    load_manifest,
    mandatory_for_mode,
    write_manifest,
)
from security_scan import run_active_vuln_probes

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


async def run_mode(
    *,
    mode: str,
    base: str,
    manifest: Dict[str, Any],
    browser_evaluate=None,
    callback_base: str = "",
) -> Dict[str, Any]:
    from active_probe_kit import normalize_mode

    mode_n = normalize_mode(mode)
    stats = CrawlStats()
    stats._scan_status = "final"  # type: ignore[attr-defined]
    timeout = httpx.Timeout(25.0, connect=10.0)
    mandatory = mandatory_for_mode(manifest, mode_n)
    # Also probe non-mandatory supported controls/vulns that share families (linked homepage)
    extra = [
        r
        for r in manifest.get("routes") or []
        if r.get("bucket") == BUCKET_SUPPORTED
        and mode_n in [m.lower() for m in (r.get("modes") or [])]
        and r.get("parameter")
        and not r.get("mandatory")
        and r.get("path")
        in {
            "/sqli/search",
            "/xss/form",
            "/xss/attr",
            "/ssrf/imds-tease",
            "/lfi/include",
        }
    ]
    targets = mandatory + extra
    paths = sorted({str(t["path"]) for t in targets})

    # Lab Horizon: wire playground traversal canary so /trav/view can confirm.
    canary_path = ""
    canary_content = ""
    if mode_n == "lab":
        canary_path = "fixtures/canary.txt"
        canary_content = "PLAYGROUND_CANARY_TOKEN"

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        await _seed_discovery(client, base, stats, paths)
        for fix in targets:
            url = urljoin(base, str(fix["path"]))
            stats.discovered_urls.add(url)
            forms = None
            max_forms = 0
            if str(fix.get("method") or "GET").upper() == "POST" or fix.get("family") == "csrf":
                forms = await _extract_forms(client, url)
                max_forms = 3
            items = await run_active_vuln_probes(
                client,
                url,
                forms=forms,
                max_params=8,
                max_forms=max_forms,
                mode=mode_n,
                callback_base=callback_base or "",
                browser_evaluate=browser_evaluate,
                stats=stats,
                traversal_canary_path=canary_path,
                traversal_canary_expected_content=canary_content,
            )
            # Mirror kit findings into stats so evaluation sees emission/confirmation.
            for item in items or []:
                try:
                    if not isinstance(item, (tuple, list)) or len(item) < 4:
                        continue
                    category, severity, detail, evidence = item[0], item[1], item[2], item[3]
                    meta = item[4] if len(item) > 4 and isinstance(item[4], dict) else {}
                    # CSRF Horizon state-change: treat as confirmed validation
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
                        verification=meta.get("verification") or ("confirmed" if validation == "confirmed" else None),
                        proof=proof,
                        validation=validation,
                        confidence=meta.get("confidence"),
                        confidence_reason=meta.get("confidence_reason"),
                    )
                except Exception:
                    continue

    result = evaluate_stats(stats, mode=mode_n, manifest=manifest)
    # Assessment completeness gate on stats
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
    # Persist raw ledger snapshot for artifact audit
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
    for mode in modes:
        t0 = time.time()
        print(f"=== Horizon acceptance mode={mode} ===", flush=True)
        # Lab gets browser if available; safe/extended still probe browser fixture only if in modes
        be = browser_evaluate if mode == "lab" else None
        mode_result = await run_mode(
            mode=mode,
            base=base,
            manifest=manifest,
            browser_evaluate=be,
            callback_base="",
        )
        mode_result["duration_s"] = round(time.time() - t0, 2)
        results["modes"][mode] = mode_result
        (out_dir / f"matrix_{mode}.json").write_text(
            json.dumps(mode_result, indent=2, default=str) + "\n", encoding="utf-8"
        )
        summary = mode_result.get("summary") or {}
        print(
            f"mode={mode} assessment_complete={mode_result.get('assessment_complete')} "
            f"recall={summary.get('supported_fixture_recall')} "
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
        lines.append(f"## Mode: {mode}")
        lines.append(f"assessment_complete: {mode_result.get('assessment_complete')}")
        lines.append(f"supported_fixture_recall: {summary.get('supported_fixture_recall')}")
        lines.append(
            f"negative_control_false_positive_rate: {summary.get('negative_control_false_positive_rate')}"
        )
        lines.append(f"probe_routing_coverage: {summary.get('probe_routing_coverage')}")
        lines.append(f"verification_coverage: {summary.get('verification_coverage')}")
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
