"""Coverage-gap records and expected-vs-actual evaluation for Horizon benchmark."""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

from horizon_benchmark.manifest import (
    BUCKET_SUPPORTED,
    BUCKET_UNSUPPORTED,
    load_manifest,
    mandatory_for_mode,
)

GAP_REASONS = (
    "no_parameter",
    "family_unsupported",
    "mode_excluded",
    "breaker_interruption",
    "probe_budget_exhausted",
    "applicability_score_below_threshold",
    "not_discovered",
    "not_scheduled",
    "browser_unavailable",
    "oob_unavailable",
    "baseline_failed",
)


def _norm_path(url_or_path: str) -> str:
    raw = (url_or_path or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        return (urlparse(raw).path or "/").rstrip("/") or "/"
    path = raw.split("?", 1)[0]
    if not path.startswith("/"):
        path = "/" + path
    return path.rstrip("/") or "/"


def discovered_paths_from_stats(stats: Any) -> set:
    paths = set()
    for u in list(getattr(stats, "discovered_urls", None) or []):
        paths.add(_norm_path(str(u)))
    for u in list(getattr(stats, "enum_hit_urls", None) or []):
        paths.add(_norm_path(str(u)))
    for row in list(getattr(stats, "request_ledger", None) or []):
        if not isinstance(row, dict):
            continue
        if row.get("phase") in ("crawl", "enumeration", "active_probe"):
            paths.add(_norm_path(str(row.get("url") or "")))
    return {p for p in paths if p}


def probe_rows_from_stats(stats: Any) -> List[Dict[str, Any]]:
    return [
        r
        for r in list(getattr(stats, "request_ledger", None) or [])
        if isinstance(r, dict)
        and r.get("phase") == "active_probe"
        and r.get("probe_role") == "probe"
    ]


def findings_from_stats(stats: Any) -> List[Dict[str, Any]]:
    return [f for f in list(getattr(stats, "findings", None) or []) if isinstance(f, dict)]


def _family_match(probe_class: str, family: str, probe_family: str) -> bool:
    pc = (probe_class or "").lower()
    fam = (probe_family or family or "").lower()
    aliases = {
        "sqli": ("sql_injection", "sqli"),
        "rce": ("rce", "command_injection"),
        "command_injection": ("rce", "command_injection"),
        "ssti": ("ssti",),
        "ssrf": ("ssrf",),
        "crlf": ("header_injection", "crlf"),
        "traversal": ("directory_traversal", "path_traversal", "traversal"),
        "xss": ("xss", "html_injection"),
        "redirect": ("open_redirect", "redirect"),
    }
    tokens = aliases.get(fam, (fam,))
    return any(t in pc for t in tokens) or pc == fam


def evaluate_fixture_against_stats(
    fixture: Dict[str, Any],
    *,
    stats: Any,
    mode: str,
) -> Dict[str, Any]:
    """Produce one expected-versus-actual row for a fixture."""
    path = _norm_path(fixture["path"])
    family = str(fixture.get("family") or "")
    probe_family = str(fixture.get("probe_family") or family)
    param = str(fixture.get("parameter") or "")
    discovered = path in discovered_paths_from_stats(stats)
    probes = [
        r
        for r in probe_rows_from_stats(stats)
        if _norm_path(str(r.get("url") or "")) == path
        and _family_match(str(r.get("probe_class") or ""), family, probe_family)
    ]
    if param:
        param_probes = [r for r in probes if str(r.get("parameter") or "") == param]
        if param_probes:
            probes = param_probes

    reasons = {str(r.get("target_selection_reason") or "") for r in probes if r.get("target_selection_reason")}
    states = [str(r.get("result_state") or "") for r in probes]
    probe_sent = bool(probes)
    result_state = next((s for s in states if s), "")
    response_classified = any(r.get("classification") or r.get("result_state") for r in probes)

    findings = [
        f
        for f in findings_from_stats(stats)
        if _norm_path(str(f.get("url") or "")) == path
        or path in str(f.get("detail") or "")
    ]
    # Prefer family-matching findings
    fam_findings = [
        f
        for f in findings
        if family.lower() in str(f.get("category") or "").lower()
        or probe_family.lower() in str(f.get("category") or "").lower()
        or (
            family == "crlf"
            and "header" in str(f.get("category") or "").lower()
        )
        or (
            family == "redirect"
            and "redirect" in str(f.get("category") or "").lower()
        )
        or (
            family == "command_injection"
            and str(f.get("category") or "").lower() == "rce"
        )
    ]
    if fam_findings:
        findings = fam_findings

    finding_emitted = bool(findings)
    confirmed = any(
        str(f.get("validation") or "").lower() == "confirmed"
        or str(f.get("impact") or "").lower() == "confirmed"
        or str((f.get("proof") or {}).get("validation_state") or "").endswith("confirmed")
        for f in findings
    )

    expected_state = str(fixture.get("expected_result_state") or "")
    must_not = bool(fixture.get("must_not_confirm"))
    mode_ok = (mode or "safe").lower() in [m.lower() for m in (fixture.get("modes") or [])]

    mismatch = None
    root_cause_stage = None
    status = "pass"

    # Ledger-level confirmation on a negative control is a false positive even when
    # findings were not mirrored into stats.findings.
    ledger_confirmed = any(
        s
        in (
            "execution_confirmed",
            "browser_execution_confirmed",
            "server_execution_confirmed",
            "oob_callback_confirmed",
            "canary_file_confirmed",
        )
        for s in states
    )
    if must_not and (confirmed or ledger_confirmed):
        status = "fail"
        mismatch = "false_positive_confirmed_on_control"
        root_cause_stage = "response_classification"
        confirmed = True

    if fixture.get("bucket") == BUCKET_UNSUPPORTED:
        # Unsupported fixtures must produce an explicit gap when discovered — not silent.
        gaps = list(getattr(stats, "benchmark_coverage_gaps", None) or [])
        explicit = any(_norm_path(str(g.get("path") or "")) == path for g in gaps if isinstance(g, dict))
        if discovered and not explicit:
            status = "fail"
            mismatch = "unsupported_fixture_silently_skipped"
            root_cause_stage = "reporting"
        return _row(
            fixture,
            mode=mode,
            discovered=discovered,
            parameter_extracted=bool(param),
            probe_family_selected=False,
            target_selection_reason="",
            probe_sent=False,
            response_classified=False,
            result_state="",
            finding_emitted=False,
            confirmed=False,
            status=status,
            mismatch=mismatch,
            root_cause_stage=root_cause_stage,
        )

    if not mode_ok:
        return _row(
            fixture,
            mode=mode,
            discovered=discovered,
            parameter_extracted=bool(param),
            probe_family_selected=False,
            target_selection_reason="",
            probe_sent=False,
            response_classified=False,
            result_state="",
            finding_emitted=False,
            confirmed=False,
            status="skipped_mode",
            mismatch=None,
            root_cause_stage="mode_excluded",
        )

    if must_not and confirmed:
        status = "fail"
        mismatch = "false_positive_confirmed_on_control"
        root_cause_stage = "finding_emission"
    elif not discovered and fixture.get("mandatory") and fixture.get("linked"):
        status = "fail"
        mismatch = "false_negative_not_discovered"
        root_cause_stage = "crawl_discovery"
    elif discovered and not probe_sent and fixture.get("classification") == "vulnerable":
        status = "fail"
        mismatch = "false_negative_not_probed"
        root_cause_stage = "probe_scheduling"
    elif discovered and probe_sent and must_not:
        # Control probed — ok if not confirmed; result_state should be negative/reflected_only
        if confirmed or ledger_confirmed:
            status = "fail"
            mismatch = "false_positive_confirmed_on_control"
            root_cause_stage = "response_classification"
            confirmed = True
        else:
            status = "pass"
    elif discovered and probe_sent and not must_not:
        # Vulnerable — probe routing success; confirmation may depend on OOB/browser/canary
        if expected_state in (
            "execution_confirmed",
            "browser_execution_confirmed",
            "canary_file_confirmed",
            "oob_callback_confirmed",
        ):
            # Soften: if probe sent but confirmation unavailable, treat as gap not hard FP/FN
            if confirmed or result_state in (
                expected_state,
                "execution_confirmed",
                "differential_signal",
                "server_execution_confirmed",
            ):
                status = "pass"
            elif result_state in ("inconclusive", "reflected_only", "negative", "differential_signal"):
                status = "partial"
                mismatch = f"expected_{expected_state}_got_{result_state or 'empty'}"
                root_cause_stage = "response_classification"
            else:
                status = "partial"
                mismatch = f"expected_{expected_state}_got_{result_state or 'empty'}"
                root_cause_stage = "response_classification"
        else:
            status = "pass"

    if probe_sent and not all(states):
        # result-state incompleteness is always a fail for probed rows
        if any(not s for s in states):
            status = "fail" if status == "pass" else status
            mismatch = mismatch or "empty_result_state"
            root_cause_stage = root_cause_stage or "response_classification"

    return _row(
        fixture,
        mode=mode,
        discovered=discovered,
        parameter_extracted=bool(param) and (not probes or any(str(r.get("parameter") or "") == param for r in probes) or probe_sent),
        probe_family_selected=probe_sent,
        target_selection_reason=(sorted(reasons)[0] if reasons else ""),
        probe_sent=probe_sent,
        response_classified=response_classified,
        result_state=result_state,
        finding_emitted=finding_emitted,
        confirmed=confirmed,
        status=status,
        mismatch=mismatch,
        root_cause_stage=root_cause_stage,
    )


def _row(fixture: Dict[str, Any], **kwargs) -> Dict[str, Any]:
    return {
        "path": fixture.get("path"),
        "method": fixture.get("method"),
        "parameter": fixture.get("parameter"),
        "family": fixture.get("family"),
        "probe_family": fixture.get("probe_family") or fixture.get("family"),
        "classification": fixture.get("classification"),
        "bucket": fixture.get("bucket"),
        "mandatory": bool(fixture.get("mandatory")),
        "must_not_confirm": bool(fixture.get("must_not_confirm")),
        "expected_result_state": fixture.get("expected_result_state"),
        "expected_severity": fixture.get("expected_severity"),
        "expected_validation": fixture.get("expected_validation"),
        **kwargs,
    }


def build_coverage_gaps(
    *,
    stats: Any,
    mode: str,
    manifest: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Every discovered supported fixture that was not tested gets an explicit gap."""
    manifest = manifest or load_manifest()
    mode_n = (mode or "safe").lower()
    discovered = discovered_paths_from_stats(stats)
    probes = probe_rows_from_stats(stats)
    probed_paths = {_norm_path(str(r.get("url") or "")) for r in probes}
    breaker = bool(getattr(stats, "vuln_active_probe_paused", False))
    gaps: List[Dict[str, Any]] = []

    for fix in manifest.get("routes") or []:
        path = _norm_path(str(fix.get("path") or ""))
        bucket = fix.get("bucket")
        if bucket == BUCKET_UNSUPPORTED and path in discovered:
            gaps.append(
                {
                    "path": path,
                    "family": fix.get("family"),
                    "reason": "family_unsupported",
                    "detail": "Fixture discovered but no compatible active detector exists.",
                    "mode": mode_n,
                }
            )
            continue
        if bucket != BUCKET_SUPPORTED:
            continue
        if mode_n not in [m.lower() for m in (fix.get("modes") or [])]:
            if path in discovered and fix.get("mandatory"):
                gaps.append(
                    {
                        "path": path,
                        "family": fix.get("family"),
                        "reason": "mode_excluded",
                        "detail": f"Fixture not in scope for mode={mode_n}",
                        "mode": mode_n,
                    }
                )
            continue
        if path not in discovered:
            if fix.get("mandatory") and fix.get("linked"):
                gaps.append(
                    {
                        "path": path,
                        "family": fix.get("family"),
                        "reason": "not_discovered",
                        "detail": "Mandatory linked fixture not present in crawl/enum discovery set.",
                        "mode": mode_n,
                    }
                )
            continue
        # Discovered + in mode
        fam = str(fix.get("probe_family") or fix.get("family") or "")
        family_probes = [
            r
            for r in probes
            if _norm_path(str(r.get("url") or "")) == path
            and _family_match(str(r.get("probe_class") or ""), str(fix.get("family") or ""), fam)
        ]
        if family_probes:
            continue
        reason = "not_scheduled"
        detail = "Supported fixture discovered but matching probe family was not scheduled."
        if breaker:
            reason = "breaker_interruption"
            detail = "Active-probe circuit breaker paused remaining probes."
        elif not fix.get("parameter"):
            reason = "no_parameter"
            detail = "No injectable parameter/form field known for fixture."
        elif path not in probed_paths:
            # Path never received any active probe
            ts = getattr(stats, "target_selection_coverage", None) or {}
            if isinstance(ts, dict) and ts.get("status") == "insufficient":
                reason = "applicability_score_below_threshold"
                detail = "Target-selection did not apply this family to the fixture."
        gaps.append(
            {
                "path": path,
                "family": fix.get("family"),
                "parameter": fix.get("parameter"),
                "reason": reason,
                "detail": detail,
                "mode": mode_n,
                "mandatory": bool(fix.get("mandatory")),
            }
        )
    return gaps


def summarize_matrix(rows: List[Dict[str, Any]], gaps: List[Dict[str, Any]]) -> Dict[str, Any]:
    supported = [r for r in rows if r.get("bucket") == BUCKET_SUPPORTED and r.get("status") != "skipped_mode"]
    mandatory = [r for r in supported if r.get("mandatory")]
    controls = [r for r in supported if r.get("must_not_confirm")]
    vulnerables = [r for r in supported if r.get("classification") == "vulnerable"]

    def _recall(group: List[Dict[str, Any]]) -> float:
        if not group:
            return 1.0
        ok = sum(1 for r in group if r.get("status") in ("pass", "partial") and r.get("probe_sent"))
        # For controls, probe_sent + not confirmed is enough
        ok_ctrl = sum(
            1
            for r in group
            if r.get("must_not_confirm") and r.get("status") == "pass"
        )
        # Mix: vulnerables need probe_sent; controls need pass
        numer = 0
        for r in group:
            if r.get("must_not_confirm"):
                numer += 1 if r.get("status") == "pass" else 0
            else:
                numer += 1 if r.get("probe_sent") and r.get("status") in ("pass", "partial") else 0
        return round(numer / max(len(group), 1), 4)

    fp = sum(1 for r in controls if r.get("confirmed") or r.get("mismatch") == "false_positive_confirmed_on_control")
    fp_rate = round(fp / max(len(controls), 1), 4)

    routing_ok = sum(1 for r in vulnerables if r.get("probe_sent"))
    routing_cov = round(routing_ok / max(len(vulnerables), 1), 4)

    emission_ok = sum(
        1
        for r in vulnerables
        if r.get("finding_emitted") or r.get("result_state") in ("inconclusive", "reflected_only", "differential_signal", "execution_confirmed", "negative")
    )
    # Finding emission: for OOB/browser soft cases, probe+state counts
    emission_cov = round(emission_ok / max(len(vulnerables), 1), 4)

    probed = [r for r in supported if r.get("probe_sent")]
    state_complete = sum(1 for r in probed if r.get("result_state"))
    state_completeness = round(state_complete / max(len(probed), 1), 4) if probed else 1.0

    fails = [r for r in supported if r.get("status") == "fail"]
    return {
        "supported_fixture_recall": _recall(mandatory or supported),
        "negative_control_false_positive_rate": fp_rate,
        "probe_routing_coverage": routing_cov,
        "finding_emission_coverage": emission_cov,
        "result_state_completeness": state_completeness,
        "mandatory_total": len(mandatory),
        "mandatory_pass": sum(1 for r in mandatory if r.get("status") in ("pass", "partial")),
        "mandatory_fail": sum(1 for r in mandatory if r.get("status") == "fail"),
        "false_positives": [
            {"path": r["path"], "family": r["family"], "root_cause_stage": r.get("root_cause_stage"), "mismatch": r.get("mismatch")}
            for r in controls
            if r.get("status") == "fail"
        ],
        "false_negatives": [
            {"path": r["path"], "family": r["family"], "root_cause_stage": r.get("root_cause_stage"), "mismatch": r.get("mismatch")}
            for r in vulnerables
            if r.get("status") == "fail"
        ],
        "missed_fixtures": [
            {"path": r["path"], "family": r["family"], "root_cause_stage": r.get("root_cause_stage"), "mismatch": r.get("mismatch")}
            for r in fails
        ],
        "coverage_gaps": gaps,
        "all_mismatches": [
            {
                "path": r["path"],
                "family": r["family"],
                "classification": r.get("classification"),
                "mismatch": r.get("mismatch"),
                "root_cause_stage": r.get("root_cause_stage"),
                "status": r.get("status"),
            }
            for r in supported
            if r.get("mismatch")
        ],
    }


def evaluate_stats(
    stats: Any,
    *,
    mode: str,
    manifest: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    manifest = manifest or load_manifest()
    gaps = build_coverage_gaps(stats=stats, mode=mode, manifest=manifest)
    # Persist onto stats for report export
    try:
        stats.benchmark_coverage_gaps = list(gaps)
    except Exception:
        pass
    rows = [
        evaluate_fixture_against_stats(fix, stats=stats, mode=mode)
        for fix in (manifest.get("routes") or [])
        if fix.get("bucket") in (BUCKET_SUPPORTED, BUCKET_UNSUPPORTED)
        and (fix.get("mandatory") or fix.get("bucket") == BUCKET_UNSUPPORTED or fix.get("classification") == "control")
    ]
    # Always include all mandatory + all controls in supported set
    summary = summarize_matrix(rows, gaps)
    mandatory = mandatory_for_mode(manifest, mode)
    untested_mandatory = [
        g for g in gaps if g.get("mandatory") and g.get("reason") not in ("mode_excluded",)
    ]
    assessment_complete = (
        len(untested_mandatory) == 0
        and summary["mandatory_fail"] == 0
        and not bool(getattr(stats, "vuln_active_probe_paused", False))
    )
    # Allow complete when all mandatory were tested (probe sent) even if soft-partial confirmation
    if untested_mandatory:
        assessment_complete = False
    elif any(
        r.get("mandatory") and r.get("classification") == "vulnerable" and not r.get("probe_sent") and r.get("status") != "skipped_mode"
        for r in rows
    ):
        assessment_complete = False
    else:
        # All mandatory vulnerables probed; controls not confirmed
        assessment_complete = summary["negative_control_false_positive_rate"] == 0.0 and not untested_mandatory

    return {
        "mode": mode,
        "rows": rows,
        "summary": summary,
        "assessment_complete": assessment_complete,
        "coverage_gaps": gaps,
    }
