#!/usr/bin/env python3
"""Run Passive/Safe/Extended/Lab acceptance scans against the local lab app.

Does not modify scanner logic — only configures CrawlConfig and collects reports.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sqlite3
import sys
import time
import traceback
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from crawl_config import CrawlConfig
from crawl_orchestrator import run_full_crawl_async
from crawler_common import DownloadManager

LAB_BASE = os.environ.get("ACCEPTANCE_LAB_URL", "http://127.0.0.1:8765").rstrip("/")
ARTIFACT_ROOT = Path(os.environ.get("ACCEPTANCE_ARTIFACT_ROOT", "/opt/cursor/artifacts/acceptance_runs"))
WORDLIST = ROOT / "acceptance_lab" / "wordlists" / "acceptance.txt"
CANARY_PATH = str(ROOT / "acceptance_lab" / "fixtures" / "canary.txt")
CANARY_CONTENT = "CANARY_OK_ACCEPTANCE_TOKEN"

MODES = ("passive", "safe", "extended", "lab", "breaker")


def _build_config(mode: str, run_dir: Path) -> CrawlConfig:
    report_title = f"acceptance-{mode}"
    start = f"{LAB_BASE}/breaker-zone" if mode == "breaker" else f"{LAB_BASE}/"
    probe_mode = "safe" if mode == "breaker" else mode
    cfg = CrawlConfig(
        start_url=start,
        wordlist_file=str(WORDLIST),
        report_title=report_title,
        profile="full",
        max_depth=1 if mode == "breaker" else 2,
        crawl_concurrency=2,
        enum_concurrency=4,
        download_concurrency=2,
        directory_enum=(mode != "breaker"),
        use_wordlist=(mode != "breaker"),
        mutation_enum=False,
        enum_word_limit=20,
        enum_parallel_with_crawl=True,
        enum_start_after_pages=1,
        enum_start_timeout_s=15.0,
        security_scan=True,
        vuln_scan=True,
        vuln_active_probe=(mode != "passive"),
        active_probe_mode=probe_mode,
        active_probe_max_params=6,
        active_probe_max_forms=2,
        ssrf_callback_base="" if mode in ("passive", "breaker") else f"{LAB_BASE}/oob",
        oob_callback_poll_url="" if mode in ("passive", "breaker") else f"{LAB_BASE}/oob/poll",
        redirect_proof_host="redirect-proof.vantacrawl-lab.example",
        traversal_canary_path=(f"../../../../{CANARY_PATH.lstrip('/')}" if mode == "lab" else ""),
        traversal_canary_expected_content=(CANARY_CONTENT if mode == "lab" else ""),
        traversal_fixture_installed=(mode == "lab"),
        selenium_fallback=False,
        browser_primary=False,
        browser_on_challenge=False,
        screenshot_capture=False,
        wayback_seeds=False,
        common_crawl_seeds=False,
        subdomain_enum=False,
        api_recon=False,
        api_recon_active=False,
        js_bundle_analysis=False,
        form_discovery=True,
        rss_feeds=False,
        openapi_parse=False,
        vhost_enum=False,
        s3_enum=False,
        gcs_enum=False,
        nuclei_scan=False,
        defense_verify=True,
        evasion_enabled=True,
        evasion_level="basic",
        download_files=False,
        mirror_page_assets=False,
        html_report=True,
        json_report=True,
        sqlite_export=True,
        csv_export=True,
        assessment_report=True,
        search_conclusion_report=True,
        broken_link_sample_size=5,
        crawl_page_timeout=20.0,
    )
    return cfg


def _copy_reports(mode: str, run_dir: Path, *, since: float) -> Dict[str, str]:
    reports_src = ROOT / "Reports"
    dest = run_dir / "reports"
    dest.mkdir(parents=True, exist_ok=True)
    copied: Dict[str, str] = {}
    if not reports_src.exists():
        return copied
    # Only copy artifacts produced for this mode during this run window.
    for path in reports_src.rglob("*"):
        if not path.is_file():
            continue
        name = path.name.lower()
        if f"acceptance-{mode}" not in name:
            continue
        if path.stat().st_mtime < since - 2:
            continue
        target = dest / path.relative_to(reports_src)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        copied[str(path.relative_to(reports_src))] = str(target)
    return copied


def _load_json_reports(run_dir: Path) -> List[Dict[str, Any]]:
    out = []
    for path in (run_dir / "reports").rglob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                data["_path"] = str(path)
                out.append(data)
        except Exception:
            continue
    return out


def _extract_findings(payloads: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings = []
    for p in payloads:
        for row in p.get("findings") or []:
            if isinstance(row, dict):
                findings.append(row)
            elif isinstance(row, (list, tuple)) and len(row) >= 3:
                findings.append(
                    {
                        "category": row[0],
                        "severity": row[1],
                        "detail": row[2],
                        "evidence": row[3] if len(row) > 3 else "",
                        "meta": row[4] if len(row) > 4 else {},
                    }
                )
    return findings


def _ledger_summary(payloads: List[Dict[str, Any]], run_dir: Path) -> Dict[str, Any]:
    rows = []
    for p in payloads:
        for r in p.get("request_ledger") or []:
            if isinstance(r, dict):
                rows.append(r)
    # Also sqlite
    sqlite_rows = []
    for db in (run_dir / "reports").rglob("*.sqlite"):
        try:
            conn = sqlite3.connect(db)
            cols = [c[1] for c in conn.execute("PRAGMA table_info(request)").fetchall()]
            if "phase" in cols:
                cur = conn.execute(
                    "SELECT phase, probe_role, classification, result_state, payload_redacted "
                    "FROM request WHERE phase = 'active_probe' LIMIT 500"
                )
                for rec in cur.fetchall():
                    sqlite_rows.append(
                        {
                            "phase": rec[0],
                            "probe_role": rec[1],
                            "classification": rec[2],
                            "result_state": rec[3],
                            "payload_redacted": rec[4],
                        }
                    )
            conn.close()
        except Exception:
            continue
    probe = [r for r in rows if r.get("phase") == "active_probe"]
    return {
        "json_ledger_total": len(rows),
        "json_active_probe_rows": len(probe),
        "sqlite_active_probe_rows": len(sqlite_rows),
        "probe_roles": sorted({r.get("probe_role") for r in probe if r.get("probe_role")}),
        "classifications": sorted({r.get("classification") for r in probe if r.get("classification")}),
        "sample_probe_rows": probe[:20],
        "sqlite_sample": sqlite_rows[:20],
    }


EXPECTED = [
    {
        "id": "sqli_vuln",
        "expect": {"passive": "absent_or_passive_only", "safe": "sql_injection_signal", "extended": "sql_injection_signal", "lab": "sql_injection_signal"},
        "match": lambda f: f.get("category") in ("sql_injection", "sqli") or "sql" in str(f.get("category", "")).lower(),
    },
    {
        "id": "sqli_safe_no_fp",
        "expect": {"passive": "no_sqli", "safe": "no_sqli", "extended": "no_sqli", "lab": "no_sqli"},
        "match": None,  # evaluated specially
    },
    {
        "id": "xss_reflected_or_html_injection",
        "expect": {"passive": "maybe_passive", "safe": "xss_or_html_injection_unconfirmed", "extended": "xss_or_html_injection_unconfirmed", "lab": "xss_or_html_injection_unconfirmed"},
        "match": lambda f: f.get("category") in ("xss", "html_injection", "reflected_xss"),
    },
    {
        "id": "xss_encoded_not_confirmed",
        "expect": {"passive": "no_xss_confirmed", "safe": "no_xss_confirmed", "extended": "no_xss_confirmed", "lab": "no_xss_confirmed"},
        "match": None,
    },
    {
        "id": "ssrf_callback_or_inconclusive",
        "expect": {"passive": "absent", "safe": "ssrf_confirmed_or_inconclusive", "extended": "ssrf_confirmed_or_inconclusive", "lab": "ssrf_confirmed_or_inconclusive"},
        "match": lambda f: f.get("category") == "ssrf",
    },
    {
        "id": "rce_arith_or_marker",
        "expect": {"passive": "absent", "safe": "rce_probable_or_confirmed", "extended": "rce_probable_or_confirmed", "lab": "rce_probable_or_confirmed"},
        "match": lambda f: f.get("category") == "rce",
    },
    {
        "id": "ssti",
        "expect": {"passive": "absent", "safe": "ssti_signal", "extended": "ssti_signal", "lab": "ssti_signal"},
        "match": lambda f: f.get("category") == "ssti",
    },
    {
        "id": "traversal",
        "expect": {"passive": "absent", "safe": "diff_or_coverage_skip", "extended": "diff_or_coverage_skip", "lab": "canary_or_diff"},
        "match": lambda f: f.get("category") in ("directory_traversal", "active_probe_coverage") or "traversal" in str(f.get("category", "")),
    },
    {
        "id": "crlf_or_redirect",
        "expect": {"passive": "maybe", "safe": "crlf_or_open_redirect", "extended": "crlf_or_open_redirect", "lab": "crlf_or_open_redirect"},
        "match": lambda f: f.get("category") in ("crlf", "crlf_injection", "open_redirect", "header_injection"),
    },
    {
        "id": "hidden_dir",
        "expect": {"passive": "enum_if_enabled", "safe": "enum_hit", "extended": "enum_hit", "lab": "enum_hit"},
        "match": None,
    },
]


async def _run_one(mode: str, run_dir: Path) -> Dict[str, Any]:
    run_dir.mkdir(parents=True, exist_ok=True)
    log_path = run_dir / "scan.log"
    logs: List[str] = []

    def output_callback(msg: str) -> None:
        line = str(msg)
        logs.append(line)
        print(f"[{mode}] {line}", flush=True)

    cfg = _build_config(mode, run_dir)
    t0 = time.time()
    result_meta: Dict[str, Any] = {"mode": mode, "ok": False}
    try:
        result = await run_full_crawl_async(
            cfg,
            output_callback,
            lambda: True,
            DownloadManager(),
            None,
            None,
        )
        result_meta["ok"] = True
        result_meta["result_type"] = type(result).__name__
        if isinstance(result, tuple):
            result_meta["tuple_len"] = len(result)
            # stats often index 0 or similar — try to snapshot
            for item in result:
                if hasattr(item, "snapshot"):
                    try:
                        snap = item.snapshot()
                        (run_dir / "stats_snapshot.json").write_text(
                            json.dumps(snap, indent=2, default=str), encoding="utf-8"
                        )
                        result_meta["browser_confirmation"] = getattr(item, "browser_confirmation", None)
                        result_meta["active_probe_coverage"] = getattr(item, "active_probe_coverage", None)
                        result_meta["active_probe_breaker"] = getattr(item, "active_probe_breaker", None)
                        result_meta["vuln_active_probe_paused"] = getattr(item, "vuln_active_probe_paused", None)
                    except Exception as exc:
                        result_meta["snapshot_error"] = str(exc)
                if isinstance(item, dict) and item.get("json"):
                    result_meta["report_paths"] = item
    except Exception as exc:
        result_meta["ok"] = False
        result_meta["error"] = str(exc)
        result_meta["traceback"] = traceback.format_exc()
        output_callback(f"SCAN ERROR: {exc}")

    result_meta["duration_s"] = round(time.time() - t0, 2)
    log_path.write_text("\n".join(logs), encoding="utf-8")
    copied = _copy_reports(mode, run_dir, since=t0)
    result_meta["copied_reports"] = copied

    payloads = _load_json_reports(run_dir)
    # Prefer the primary scan JSON (exclude zap/defense side-cars for finding counts)
    primary = [
        p
        for p in payloads
        if not str(p.get("_path") or "").endswith(("_zap.json", "_defense.json"))
    ]
    findings = _extract_findings(primary or payloads)
    # Normalize category key
    for f in findings:
        if "category" not in f and "type" in f:
            f["category"] = f.get("type")
        if "category" not in f and "kind" in f:
            f["category"] = f.get("kind")

    # Pull browser/breaker from JSON payloads if present
    for p in payloads:
        if p.get("browser_confirmation") and not result_meta.get("browser_confirmation"):
            result_meta["browser_confirmation"] = p.get("browser_confirmation")
        if p.get("active_probe_breaker") and not result_meta.get("active_probe_breaker"):
            result_meta["active_probe_breaker"] = p.get("active_probe_breaker")
        if p.get("active_probe_coverage") and not result_meta.get("active_probe_coverage"):
            result_meta["active_probe_coverage"] = p.get("active_probe_coverage")

    ledger = _ledger_summary(payloads, run_dir)
    (run_dir / "findings.json").write_text(json.dumps(findings, indent=2, default=str), encoding="utf-8")
    (run_dir / "ledger_summary.json").write_text(json.dumps(ledger, indent=2, default=str), encoding="utf-8")
    (run_dir / "result_meta.json").write_text(json.dumps(result_meta, indent=2, default=str), encoding="utf-8")

    # Callback / breaker evidence extracts
    oob_evidence = []
    for f in findings:
        proof = (f.get("meta") or {}).get("proof") or f.get("proof") or {}
        if isinstance(proof, dict) and proof.get("oob"):
            oob_evidence.append({"category": f.get("category"), "oob": proof.get("oob"), "validation_state": proof.get("validation_state")})
        detail = str(f.get("detail") or "")
        if "callback" in detail.lower() or f.get("category") == "ssrf":
            oob_evidence.append(
                {
                    "category": f.get("category"),
                    "detail": detail[:300],
                    "validation_state": (proof or {}).get("validation_state") if isinstance(proof, dict) else None,
                    "verification": (f.get("meta") or {}).get("verification") or f.get("verification"),
                }
            )
    (run_dir / "callback_evidence.json").write_text(json.dumps(oob_evidence, indent=2, default=str), encoding="utf-8")

    return {
        "meta": result_meta,
        "findings": findings,
        "ledger": ledger,
        "oob_evidence": oob_evidence,
        "logs_tail": logs[-80:],
    }


def _matrix_row(case_id: str, mode: str, expected: str, actual: str, status: str, notes: str = "") -> Dict[str, str]:
    return {
        "case": case_id,
        "mode": mode,
        "expected": expected,
        "actual": actual,
        "status": status,
        "notes": notes,
    }


def build_matrix(results: Dict[str, Dict[str, Any]]) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for mode, data in results.items():
        findings = data.get("findings") or []
        meta = data.get("meta") or {}
        ledger = data.get("ledger") or {}

        # SQLi vuln
        sqli = [f for f in findings if "sql" in str(f.get("category", "")).lower()]
        rows.append(
            _matrix_row(
                "sqli_vuln",
                mode,
                "signal in active modes" if mode != "passive" else "absent/passive-only",
                f"count={len(sqli)} states={[((f.get('meta') or {}).get('proof') or f.get('proof') or {}).get('validation_state') for f in sqli]}",
                "PASS" if (mode == "passive" and len(sqli) <= 2) or (mode != "passive" and len(sqli) >= 1) else "REVIEW",
            )
        )

        # XSS
        xss = [f for f in findings if f.get("category") in ("xss", "html_injection", "reflected_xss")]
        confirmed = [
            f
            for f in xss
            if ((f.get("meta") or {}).get("proof") or f.get("proof") or {}).get("validation_state")
            == "browser_execution_confirmed"
        ]
        rows.append(
            _matrix_row(
                "xss_family",
                mode,
                "unconfirmed xss/html_injection unless browser available",
                f"xssish={len(xss)} browser_confirmed={len(confirmed)} browser_cap={meta.get('browser_confirmation')}",
                "PASS" if len(confirmed) == 0 or (isinstance(meta.get("browser_confirmation"), dict) and meta["browser_confirmation"].get("browser_confirmation") == "available") else "REVIEW",
            )
        )

        # SSRF
        ssrf = [f for f in findings if f.get("category") == "ssrf"]
        oob_conf = [
            f
            for f in ssrf
            if ((f.get("meta") or {}).get("proof") or f.get("proof") or {}).get("validation_state")
            == "oob_callback_confirmed"
        ]
        rows.append(
            _matrix_row(
                "ssrf_callback",
                mode,
                "confirmed or inconclusive (never URL-echo confirm)" if mode != "passive" else "absent",
                f"ssrf={len(ssrf)} oob_confirmed={len(oob_conf)} evidence={len(data.get('oob_evidence') or [])}",
                "PASS"
                if (mode == "passive" and not ssrf)
                or (mode != "passive" and (oob_conf or any("inconclusive" in str(((f.get('meta') or {}).get('proof') or f.get('proof') or {}).get('validation_state')).lower()) or "unavailable" in str(f.get("detail","")).lower() for f in ssrf) or ssrf)
                else "REVIEW",
            )
        )

        # RCE / SSTI
        rce = [f for f in findings if f.get("category") == "rce"]
        ssti = [f for f in findings if f.get("category") == "ssti"]
        rows.append(_matrix_row("rce", mode, "probable/confirmed in active", f"count={len(rce)}", "PASS" if (mode == "passive") or rce else "REVIEW"))
        rows.append(_matrix_row("ssti", mode, "signal in active", f"count={len(ssti)}", "PASS" if (mode == "passive") or ssti else "REVIEW"))

        # Traversal
        trav = [f for f in findings if "traversal" in str(f.get("category", "")).lower() or f.get("category") == "active_probe_coverage"]
        rows.append(
            _matrix_row(
                "traversal",
                mode,
                "canary confirm only in lab with fixture; else skip/diff",
                f"count={len(trav)} details={[str(f.get('detail',''))[:80] for f in trav[:3]]}",
                "REVIEW",
            )
        )

        # CRLF / redirect
        inj = [f for f in findings if f.get("category") in ("crlf", "crlf_injection", "open_redirect", "header_injection")]
        rows.append(_matrix_row("crlf_redirect", mode, "signal in active", f"count={len(inj)}", "PASS" if (mode == "passive") or inj else "REVIEW"))

        # Ledger
        rows.append(
            _matrix_row(
                "active_probe_ledger",
                mode,
                "probe rows when active" if mode != "passive" else "none/minimal",
                f"json={ledger.get('json_active_probe_rows')} sqlite={ledger.get('sqlite_active_probe_rows')} roles={ledger.get('probe_roles')}",
                "PASS"
                if (mode == "passive" and int(ledger.get("json_active_probe_rows") or 0) == 0)
                or (mode != "passive" and int(ledger.get("json_active_probe_rows") or 0) > 0)
                else "REVIEW",
            )
        )

        # Browser capability
        cap = meta.get("browser_confirmation") or {}
        rows.append(
            _matrix_row(
                "browser_capability",
                mode,
                "available|unavailable surfaced",
                json.dumps(cap)[:240] if cap else "missing",
                "PASS" if (mode == "passive" or (isinstance(cap, dict) and cap.get("browser_confirmation") in ("available", "unavailable"))) else "REVIEW",
            )
        )

        # Breaker
        br = meta.get("active_probe_breaker") or {}
        rows.append(
            _matrix_row(
                "circuit_breaker",
                mode,
                "may trip on checkpoint/rate-limit storm",
                json.dumps(br)[:240] if br else f"paused={meta.get('vuln_active_probe_paused')}",
                "INFO",
            )
        )

        # Hidden dir presence in enum / discovered
        hidden_hit = False
        for p in _load_json_reports(Path(ARTIFACT_ROOT) / mode):
            blob = json.dumps(p)
            if "secret-admin-panel" in blob:
                hidden_hit = True
                break
        # also check findings/logs
        if not hidden_hit:
            hidden_hit = any("secret-admin-panel" in str(x) for x in (data.get("logs_tail") or []))
            if not hidden_hit:
                for f in findings:
                    if "secret-admin-panel" in json.dumps(f):
                        hidden_hit = True
                        break
        rows.append(
            _matrix_row(
                "hidden_directory",
                mode,
                "enum discovers /secret-admin-panel",
                f"found={hidden_hit}",
                "PASS" if hidden_hit else "REVIEW",
            )
        )

    return rows


def main() -> None:
    ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    session = ARTIFACT_ROOT / stamp
    session.mkdir(parents=True, exist_ok=True)
    print(f"Acceptance session: {session}", flush=True)

    results: Dict[str, Dict[str, Any]] = {}
    for mode in MODES:
        print(f"\n===== MODE {mode} =====", flush=True)
        run_dir = session / mode
        results[mode] = asyncio.run(_run_one(mode, run_dir))

    matrix = build_matrix(results)
    (session / "expected_vs_actual_matrix.json").write_text(json.dumps(matrix, indent=2), encoding="utf-8")

    # Markdown matrix
    lines = [
        "# Acceptance expected vs actual",
        "",
        f"Lab: `{LAB_BASE}`",
        f"Session: `{session}`",
        "",
        "| Case | Mode | Expected | Actual | Status | Notes |",
        "|---|---|---|---|---|---|",
    ]
    for r in matrix:
        lines.append(
            f"| {r['case']} | {r['mode']} | {r['expected']} | `{r['actual'][:120].replace('|','/')}` | {r['status']} | {r.get('notes','')} |"
        )
    (session / "expected_vs_actual_matrix.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    summary = {
        "session": str(session),
        "lab_base": LAB_BASE,
        "modes": {
            m: {
                "ok": results[m]["meta"].get("ok"),
                "duration_s": results[m]["meta"].get("duration_s"),
                "findings": len(results[m].get("findings") or []),
                "browser_confirmation": results[m]["meta"].get("browser_confirmation"),
                "active_probe_breaker": results[m]["meta"].get("active_probe_breaker"),
                "ledger_active_probe_rows": (results[m].get("ledger") or {}).get("json_active_probe_rows"),
                "error": results[m]["meta"].get("error"),
            }
            for m in MODES
        },
        "matrix_path": str(session / "expected_vs_actual_matrix.md"),
    }
    (session / "SUMMARY.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    print(json.dumps(summary, indent=2, default=str), flush=True)


if __name__ == "__main__":
    main()
