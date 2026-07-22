"""Scan report status helpers — partial vs final, enum messaging, assessment states."""

from __future__ import annotations

from typing import Any, Dict, Optional


ASSESSMENT_STATES = (
    "Confirmed vulnerability",
    "Likely vulnerability",
    "Needs manual validation",
    "Attack-surface observation",
    "Informational technology finding",
    "False positive / invalidated",
)


def scan_status_from_stats(stats: Any) -> Dict[str, Any]:
    """Derive report completeness metadata from CrawlStats (or attr-enriched rebuild)."""
    queue_size = int(getattr(stats, "queue_size", 0) or 0)
    remaining = int(getattr(stats, "_remaining_jobs", queue_size) or queue_size)
    pages = int(getattr(stats, "pages_crawled", 0) or 0)
    enum_total = int(getattr(stats, "enum_words_total", 0) or 0)
    enum_done = int(getattr(stats, "enum_words_tested", 0) or 0)

    enum_configured = bool(
        getattr(stats, "enum_configured", None)
        if getattr(stats, "enum_configured", None) is not None
        else getattr(stats, "_directory_enum_enabled", None)
        if getattr(stats, "_directory_enum_enabled", None) is not None
        else (enum_total > 0 or bool(getattr(stats, "enum_started_at", None)))
    )
    enum_started = bool(
        getattr(stats, "_directory_enum_started", None)
        if getattr(stats, "_directory_enum_started", None) is not None
        else getattr(stats, "enum_started_at", None)
    )
    enum_complete = bool(
        getattr(stats, "enum_complete", None)
        if getattr(stats, "enum_complete", None) is not None
        else (enum_started and enum_total > 0 and enum_done >= enum_total)
    )
    enum_skip_reason = getattr(stats, "enum_skip_reason", None)

    # Legacy alias — do NOT treat "enabled=false" as "configured but not started"
    enum_enabled = enum_configured

    finished = bool(getattr(stats, "finished_at", None))
    crawl_complete = remaining <= 0 and pages > 0

    explicit = str(getattr(stats, "_scan_status", "") or "").strip().lower()
    if explicit in ("partial", "final", "stopped"):
        status = explicit
    elif finished and crawl_complete and (enum_complete or not enum_configured):
        status = "final"
    elif finished:
        status = "stopped"
    else:
        status = "partial"

    crawl_pct = 100.0 if crawl_complete else max(0.0, min(95.0, 100.0 * pages / max(pages + remaining, 1)))
    if enum_configured and enum_total > 0:
        enum_pct = min(100.0, 100.0 * enum_done / enum_total)
        completion = round(0.7 * crawl_pct + 0.3 * enum_pct, 1)
    else:
        completion = round(crawl_pct, 1)

    if status == "final":
        phase = "complete"
    elif enum_started and not crawl_complete:
        phase = "crawl+enum"
    elif enum_started and crawl_complete and not enum_complete:
        phase = "enum"
    elif pages > 0:
        phase = "crawl"
    else:
        phase = "starting"

    if not enum_configured:
        enum_message = "Directory enumeration disabled for this scan."
    elif enum_skip_reason:
        enum_message = f"Directory enumeration did not complete ({enum_skip_reason})."
    elif not enum_started:
        enum_message = (
            "Directory enumeration configured but not started yet "
            "(runs in parallel after initial crawl pages)."
        )
    elif enum_total > 0 and enum_done < enum_total and not enum_complete:
        enum_message = (
            f"Directory enumeration in progress ({enum_done:,}/{enum_total:,} words)."
        )
    elif enum_complete and enum_total > 0:
        enum_message = f"Directory enumeration completed ({enum_done:,} words tested)."
    else:
        enum_message = "Directory enumeration status unavailable."

    return {
        "scan_status": status,
        "phase": phase,
        "completion_percent": completion if status != "final" else 100.0,
        "remaining_jobs": remaining,
        "report_generated_during_scan": status == "partial",
        # New explicit state model
        "enum_configured": enum_configured,
        "enum_started": enum_started,
        "enum_complete": enum_complete,
        "enum_skip_reason": enum_skip_reason,
        # Legacy aliases for older report templates
        "directory_enum_enabled": enum_enabled,
        "directory_enum_started": enum_started,
        "directory_enum_message": enum_message,
        "is_final": status == "final",
    }


def assessment_state_for_finding(
    *,
    category: str = "",
    severity: str = "",
    validation: str = "",
    impact: str = "",
    finding_kind: str = "",
    verification: str = "",
    detail: str = "",
) -> str:
    """Map a finding to a report confidence state (assessment language)."""
    cat = (category or "").lower()
    sev = (severity or "info").lower()
    val = (validation or "").lower()
    imp = (impact or "").lower()
    kind = (finding_kind or "").lower()
    ver = (verification or "").lower()
    detail_l = (detail or "").lower()

    if val in ("invalid", "skipped") or imp in ("no_impact", "invalid") or "false positive" in detail_l:
        return "False positive / invalidated"
    if cat in ("file_upload", "rate_limit", "well_known", "cloud_url", "js_intel", "websocket"):
        return "Attack-surface observation"
    if "deep-link flow" in detail_l or "password-reset deep-link" in detail_l:
        return "Attack-surface observation"
    if "source-to-sink flow not established" in detail_l or "potential dom execution sink" in detail_l:
        return "Needs manual validation"
    if kind == "hardening" or cat in ("header_audit", "bot_management", "http_methods"):
        return "Informational technology finding"
    if ver in ("exploitable", "confirmed") or val == "confirmed":
        if sev in ("critical", "high", "medium") and kind != "hardening":
            return "Confirmed vulnerability"
        return "Informational technology finding"
    if ver == "verified" or val == "active" or imp in ("possible", "stealable_credential", "confirmed"):
        if sev in ("critical", "high", "medium"):
            return "Likely vulnerability"
        return "Needs manual validation"
    if sev in ("info", "low") or kind == "hardening":
        return "Informational technology finding"
    return "Needs manual validation"


def demonstrated_severity_counts(findings: list) -> Dict[str, int]:
    """Count only findings that are demonstrated enough to drive overall risk."""
    from collections import Counter

    counts: Counter = Counter()
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        kind = str(f.get("finding_kind") or "").lower()
        if kind == "hardening":
            continue
        val = str(f.get("validation") or "").lower()
        ver = str(f.get("verification") or "").lower()
        imp = str(f.get("impact") or "").lower()
        sev = str(f.get("severity") or "info").lower()
        cat = str(f.get("category") or "").lower()
        if cat in ("file_upload", "rate_limit", "mass_assignment") and ver not in (
            "exploitable",
            "confirmed",
        ):
            if "persisted" not in str(f.get("detail") or "").lower():
                continue
        if val in ("unverified", "skipped", "n/a", "") and ver in ("", "detected") and sev in (
            "high",
            "critical",
        ):
            continue
        if ver in ("exploitable", "confirmed") or val == "confirmed" or imp in (
            "confirmed",
            "stealable_credential",
        ):
            counts[sev] += 1
        elif ver == "verified" or val == "active":
            counts[sev] += 1
    return dict(counts)


def partial_executive_summary(*, host: str = "", phase: str = "crawl") -> str:
    return (
        "The scan discovered several security-relevant surfaces and generated candidate findings "
        "requiring validation. No critical or high-severity vulnerability has yet been conclusively "
        f"demonstrated. The scan was exported during the {phase or 'crawl'} phase"
        + (", before directory enumeration began" if phase == "crawl" else "")
        + (f" on {host}" if host else "")
        + "."
    )


def merge_status_into_snapshot(snap: Dict[str, Any], status: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(snap or {})
    out.update({k: status[k] for k in status})
    return out


def include_in_remediation(finding: Dict[str, Any]) -> bool:
    """Remediation roadmap eligibility — never include invalidated / skipped / surface-only noise."""
    if not isinstance(finding, dict):
        return False
    val = str(finding.get("validation") or "").lower()
    ver = str(finding.get("verification") or "").lower()
    state = str(finding.get("assessment_state") or "").lower()
    if val in {"skipped", "unverified", "invalid"}:
        return False
    if state in {
        "false positive / invalidated",
        "attack-surface observation",
    }:
        return False
    if "false positive" in state or "invalidated" in state:
        return False
    return ver in {"confirmed", "verified", "exploitable"}


def is_suppressed_or_invalidated(finding: Dict[str, Any]) -> bool:
    if not isinstance(finding, dict):
        return False
    state = str(finding.get("assessment_state") or "").lower()
    val = str(finding.get("validation") or "").lower()
    impact = str(finding.get("impact") or "").lower()
    if state == "false positive / invalidated":
        return True
    if val in {"invalid", "skipped"} or impact in {"no_impact", "invalid"}:
        return True
    detail = str(finding.get("detail") or "").lower()
    return "false positive" in detail or "invalidated" in detail
