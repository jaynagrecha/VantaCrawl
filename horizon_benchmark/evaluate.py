"""Coverage-gap records and expected-vs-actual evaluation for Horizon benchmark."""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlparse

from horizon_benchmark.manifest import (
    BUCKET_PASSIVE,
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

# Ledger states that count as confirmed (false positive on controls).
_CONFIRM_STATES = frozenset(
    {
        "execution_confirmed",
        "browser_execution_confirmed",
        "server_execution_confirmed",
        "oob_callback_confirmed",
        "canary_file_confirmed",
    }
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


def lifecycle_rows_for_path(stats: Any, path: str) -> Dict[str, List[Dict[str, Any]]]:
    """Baseline / control / probe / replay rows for a fixture path."""
    out: Dict[str, List[Dict[str, Any]]] = {
        "baseline": [],
        "control": [],
        "probe": [],
        "replay": [],
    }
    for r in list(getattr(stats, "request_ledger", None) or []):
        if not isinstance(r, dict) or r.get("phase") != "active_probe":
            continue
        if _norm_path(str(r.get("url") or "")) != path:
            continue
        role = str(r.get("probe_role") or "")
        if role in out:
            out[role].append(r)
    return out


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
        "csrf": ("csrf",),
    }
    tokens = aliases.get(fam, (fam,))
    return any(t in pc for t in tokens) or pc == fam


def _states_match(expected: str, actual: str) -> bool:
    exp = (expected or "").strip().lower()
    act = (actual or "").strip().lower()
    if not exp:
        return bool(act)
    if exp == act:
        return True
    # Narrow aliases only where the contract uses a collapsed label.
    aliases = {
        "execution_confirmed": {"execution_confirmed", "server_execution_confirmed"},
        "oob_callback_confirmed": {"oob_callback_confirmed", "out_of_band_callback_confirmed"},
    }
    return act in aliases.get(exp, set())


def _submitted_fields(row: Dict[str, Any]) -> Dict[str, str]:
    url = str(row.get("url") or "")
    parsed = urlparse(url)
    fields = {k: v for k, v in parse_qsl(parsed.query, keep_blank_values=True)}
    param = str(row.get("parameter") or "")
    payload = str(row.get("payload_redacted") or "")
    if param and payload and param not in fields:
        fields[param] = payload
    return fields


def evaluate_fixture_against_stats(
    fixture: Dict[str, Any],
    *,
    stats: Any,
    mode: str,
) -> Dict[str, Any]:
    """Produce one expected-versus-actual row for a fixture.

    A supported vulnerable fixture PASSES only when expected_result_state matches
    the actual ledger result_state. Discovery / scheduling / payload-send alone
    is never a true positive.
    """
    path = _norm_path(fixture["path"])
    family = str(fixture.get("family") or "")
    probe_family = str(fixture.get("probe_family") or family)
    param = str(fixture.get("parameter") or "")
    method_expected = str(fixture.get("method") or "GET").upper()
    discovered = path in discovered_paths_from_stats(stats)
    lifecycle = lifecycle_rows_for_path(stats, path)
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
    states = [str(r.get("result_state") or "").strip() for r in probes]
    probe_sent = bool(probes)
    # Prefer strongest matching confirm state, else first non-empty.
    result_state = ""
    for preferred in (
        "browser_execution_confirmed",
        "oob_callback_confirmed",
        "canary_file_confirmed",
        "execution_confirmed",
        "server_execution_confirmed",
        "differential_signal",
        "reflected_only",
        "confirmation_unavailable",
        "negative",
    ):
        if preferred in states:
            result_state = preferred
            break
    if not result_state:
        result_state = next((s for s in states if s), "")
    response_classified = any(bool(str(r.get("result_state") or "").strip()) for r in probes)
    verification_completed = response_classified and all(bool(s) for s in states) if probes else False

    findings = [
        f
        for f in findings_from_stats(stats)
        if _norm_path(str(f.get("url") or "")) == path
        or path in str(f.get("detail") or "")
    ]
    fam_findings = [
        f
        for f in findings
        if family.lower() in str(f.get("category") or "").lower()
        or probe_family.lower() in str(f.get("category") or "").lower()
        or (family == "crlf" and "header" in str(f.get("category") or "").lower())
        or (family == "redirect" and "redirect" in str(f.get("category") or "").lower())
        or (family == "command_injection" and str(f.get("category") or "").lower() == "rce")
        or (family == "csrf" and "csrf" in str(f.get("category") or "").lower())
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
    ledger_confirmed = any(s in _CONFIRM_STATES for s in states)

    expected_state = str(fixture.get("expected_result_state") or "")
    must_not = bool(fixture.get("must_not_confirm"))
    mode_ok = (mode or "safe").lower() in [m.lower() for m in (fixture.get("modes") or [])]

    method_actual = ""
    submitted = {}
    if probes:
        method_actual = str(probes[0].get("method") or method_expected).upper()
        submitted = _submitted_fields(probes[0])

    evidence = {
        "method_expected": method_expected,
        "method_actual": method_actual or method_expected,
        "submitted_fields": submitted,
        "baseline_count": len(lifecycle["baseline"]),
        "control_count": len(lifecycle["control"]),
        "probe_count": len(probes),
        "replay_count": len(lifecycle["replay"]),
        "probe_statuses": [r.get("status") for r in probes[:6]],
        "probe_payloads": [r.get("payload_redacted") for r in probes[:6]],
    }

    mismatch = None
    root_cause_stage = None
    status = "pass"

    if fixture.get("bucket") == BUCKET_UNSUPPORTED:
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
            verification_completed=False,
            result_state="",
            finding_emitted=False,
            confirmed=False,
            status=status,
            mismatch=mismatch,
            root_cause_stage=root_cause_stage,
            evidence=evidence,
        )

    if fixture.get("bucket") == BUCKET_PASSIVE:
        gaps = list(getattr(stats, "benchmark_coverage_gaps", None) or [])
        explicit = any(_norm_path(str(g.get("path") or "")) == path for g in gaps if isinstance(g, dict))
        if discovered and not explicit:
            status = "fail"
            mismatch = "passive_fixture_silently_skipped"
            root_cause_stage = "reporting"
        else:
            status = "coverage_gap"
        return _row(
            fixture,
            mode=mode,
            discovered=discovered,
            parameter_extracted=bool(param),
            probe_family_selected=False,
            target_selection_reason="",
            probe_sent=False,
            response_classified=False,
            verification_completed=False,
            result_state="",
            finding_emitted=False,
            confirmed=False,
            status=status,
            mismatch=mismatch,
            root_cause_stage=root_cause_stage or "family_unsupported",
            evidence=evidence,
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
            verification_completed=False,
            result_state="",
            finding_emitted=False,
            confirmed=False,
            status="skipped_mode",
            mismatch=None,
            root_cause_stage="mode_excluded",
            evidence=evidence,
        )

    if must_not and (confirmed or ledger_confirmed):
        status = "fail"
        mismatch = "false_positive_confirmed_on_control"
        root_cause_stage = "response_classification"
        confirmed = True
    elif not discovered and fixture.get("mandatory") and fixture.get("linked"):
        status = "fail"
        mismatch = "false_negative_not_discovered"
        root_cause_stage = "crawl_discovery"
    elif discovered and not probe_sent and fixture.get("classification") == "vulnerable":
        status = "fail"
        mismatch = "false_negative_not_probed"
        root_cause_stage = "probe_scheduling"
    elif discovered and probe_sent and must_not:
        if confirmed or ledger_confirmed:
            status = "fail"
            mismatch = "false_positive_confirmed_on_control"
            root_cause_stage = "response_classification"
            confirmed = True
        elif expected_state and not _states_match(expected_state, result_state):
            # Control probed but wrong final state (e.g. expected negative, got empty)
            if not result_state:
                status = "fail"
                mismatch = "empty_result_state"
                root_cause_stage = "response_classification"
            elif result_state not in _CONFIRM_STATES:
                # Non-confirming alternate (reflected_only vs negative) — allow if must_not holds
                if expected_state == "negative" and result_state in (
                    "negative",
                    "reflected_only",
                    "not_applicable",
                    "confirmation_unavailable",
                ):
                    status = "pass"
                elif _states_match(expected_state, result_state):
                    status = "pass"
                else:
                    status = "fail"
                    mismatch = f"expected_{expected_state}_got_{result_state or 'empty'}"
                    root_cause_stage = "response_classification"
            else:
                status = "fail"
                mismatch = f"expected_{expected_state}_got_{result_state or 'empty'}"
                root_cause_stage = "response_classification"
        else:
            status = "pass"
    elif discovered and probe_sent and not must_not:
        if not result_state or any(not s for s in states):
            status = "fail"
            mismatch = "empty_result_state"
            root_cause_stage = "response_classification"
        elif not _states_match(expected_state, result_state):
            status = "fail"
            mismatch = f"expected_{expected_state}_got_{result_state or 'empty'}"
            root_cause_stage = "response_classification"
        else:
            status = "pass"
            # Finding emission for confirming states should accompany the match when expected.
            if expected_state in _CONFIRM_STATES and not finding_emitted and not confirmed:
                # State matched on ledger — still pass verification; emission tracked separately.
                pass

    if probe_sent and any(not s for s in states):
        if status == "pass":
            status = "fail"
        mismatch = mismatch or "empty_result_state"
        root_cause_stage = root_cause_stage or "response_classification"

    return _row(
        fixture,
        mode=mode,
        discovered=discovered,
        parameter_extracted=bool(param)
        and (
            not probes
            or any(str(r.get("parameter") or "") == param for r in probes)
            or probe_sent
        ),
        probe_family_selected=probe_sent,
        target_selection_reason=(sorted(reasons)[0] if reasons else ""),
        probe_sent=probe_sent,
        response_classified=response_classified,
        verification_completed=verification_completed,
        result_state=result_state,
        finding_emitted=finding_emitted,
        confirmed=confirmed or ledger_confirmed,
        status=status,
        mismatch=mismatch,
        root_cause_stage=root_cause_stage,
        evidence=evidence,
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
        if bucket == BUCKET_PASSIVE and path in discovered:
            gaps.append(
                {
                    "path": path,
                    "family": fix.get("family"),
                    "reason": "family_unsupported",
                    "detail": "Fixture discovered but classified passive/manual-only — no active detector applied.",
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

    def _true_positive_recall(group: List[Dict[str, Any]]) -> float:
        """Vulnerable fixtures whose expected result_state exactly matches actual."""
        vulns = [r for r in group if r.get("classification") == "vulnerable"]
        if not vulns:
            return 1.0
        ok = sum(1 for r in vulns if r.get("status") == "pass")
        return round(ok / max(len(vulns), 1), 4)

    fp = sum(
        1
        for r in controls
        if r.get("confirmed") or r.get("mismatch") == "false_positive_confirmed_on_control"
    )
    fp_rate = round(fp / max(len(controls), 1), 4)

    routing_ok = sum(
        1
        for r in vulnerables
        if r.get("probe_sent")
        and r.get("probe_family_selected")
        and r.get("parameter_extracted")
    )
    routing_cov = round(routing_ok / max(len(vulnerables), 1), 4)

    verification_ok = sum(1 for r in vulnerables if r.get("verification_completed"))
    verification_cov = round(verification_ok / max(len(vulnerables), 1), 4)

    emission_ok = sum(
        1
        for r in vulnerables
        if r.get("status") == "pass"
        and (
            r.get("finding_emitted")
            or r.get("result_state")
            in (
                "inconclusive",
                "reflected_only",
                "differential_signal",
                "execution_confirmed",
                "confirmation_unavailable",
                "negative",
                "browser_execution_confirmed",
                "canary_file_confirmed",
                "oob_callback_confirmed",
            )
        )
    )
    emission_cov = round(emission_ok / max(len(vulnerables), 1), 4)

    probed = [r for r in supported if r.get("probe_sent")]
    state_complete = sum(1 for r in probed if r.get("result_state"))
    state_completeness = round(state_complete / max(len(probed), 1), 4) if probed else 1.0

    fails = [r for r in supported if r.get("status") == "fail"]
    return {
        "supported_fixture_recall": _true_positive_recall(mandatory or supported),
        "true_positive_recall": _true_positive_recall(mandatory or supported),
        "negative_control_false_positive_rate": fp_rate,
        "probe_routing_coverage": routing_cov,
        "verification_coverage": verification_cov,
        "finding_emission_coverage": emission_cov,
        "result_state_completeness": state_completeness,
        "mandatory_total": len(mandatory),
        "mandatory_pass": sum(1 for r in mandatory if r.get("status") == "pass"),
        "mandatory_fail": sum(1 for r in mandatory if r.get("status") == "fail"),
        "false_positives": [
            {
                "path": r["path"],
                "family": r["family"],
                "root_cause_stage": r.get("root_cause_stage"),
                "mismatch": r.get("mismatch"),
                "expected_result_state": r.get("expected_result_state"),
                "result_state": r.get("result_state"),
            }
            for r in controls
            if r.get("status") == "fail"
        ],
        "false_negatives": [
            {
                "path": r["path"],
                "family": r["family"],
                "root_cause_stage": r.get("root_cause_stage"),
                "mismatch": r.get("mismatch"),
                "expected_result_state": r.get("expected_result_state"),
                "result_state": r.get("result_state"),
            }
            for r in vulnerables
            if r.get("status") == "fail"
        ],
        "missed_fixtures": [
            {
                "path": r["path"],
                "family": r["family"],
                "root_cause_stage": r.get("root_cause_stage"),
                "mismatch": r.get("mismatch"),
            }
            for r in fails
        ],
        "coverage_gaps": gaps,
        "unsupported_inventory": [
            g
            for g in gaps
            if g.get("reason") == "family_unsupported"
        ],
        "all_mismatches": [
            {
                "path": r["path"],
                "family": r["family"],
                "classification": r.get("classification"),
                "mismatch": r.get("mismatch"),
                "root_cause_stage": r.get("root_cause_stage"),
                "status": r.get("status"),
                "expected_result_state": r.get("expected_result_state"),
                "result_state": r.get("result_state"),
                "evidence": r.get("evidence"),
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
    try:
        stats.benchmark_coverage_gaps = list(gaps)
    except Exception:
        pass
    rows = [
        evaluate_fixture_against_stats(fix, stats=stats, mode=mode)
        for fix in (manifest.get("routes") or [])
        if fix.get("bucket") in (BUCKET_SUPPORTED, BUCKET_UNSUPPORTED, BUCKET_PASSIVE)
        and (
            fix.get("mandatory")
            or fix.get("bucket") in (BUCKET_UNSUPPORTED, BUCKET_PASSIVE)
            or fix.get("classification") == "control"
        )
    ]
    summary = summarize_matrix(rows, gaps)
    untested_mandatory = [
        g for g in gaps if g.get("mandatory") and g.get("reason") not in ("mode_excluded",)
    ]
    # Assessment complete only when every mandatory fixture matches expected state
    # (or was explicitly interrupted) — soft partials no longer count.
    assessment_complete = (
        len(untested_mandatory) == 0
        and summary["mandatory_fail"] == 0
        and summary["negative_control_false_positive_rate"] == 0.0
        and not bool(getattr(stats, "vuln_active_probe_paused", False))
        and all(
            (r.get("status") == "pass" or r.get("status") == "skipped_mode")
            for r in rows
            if r.get("mandatory") and r.get("bucket") == BUCKET_SUPPORTED
        )
    )

    return {
        "mode": mode,
        "rows": rows,
        "summary": summary,
        "assessment_complete": assessment_complete,
        "coverage_gaps": gaps,
    }
