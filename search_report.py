"""Plain-language search conclusion and detailed multi-part report builder."""

from __future__ import annotations

import time
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from crawl_stats import CrawlStats
from detailed_report import build_report_model, render_detailed_text


def _risk_verdict(findings: List[dict]) -> Tuple[str, str]:
    counts = Counter(f.get("severity", "info") for f in findings)
    critical = counts.get("critical", 0)
    high = counts.get("high", 0)
    medium = counts.get("medium", 0)

    if critical > 0:
        return (
            "HIGH RISK — immediate review required",
            f"The scan found {critical} critical issue type(s), {high} high, and {medium} medium. "
            "Prioritize critical/high items in Part B. Each issue includes what it means, how it could be abused, "
            "and how to fix it.",
        )
    if high > 0:
        return (
            "ELEVATED RISK — review recommended",
            f"No critical issues were recorded, but {high} high-severity and {medium} medium issue(s) "
            "need a closer look. Read the “How an attacker could use this” notes before deciding what to patch first.",
        )
    if medium > 0:
        return (
            "MODERATE — harden when you can",
            f"{medium} medium-severity issue(s) were found (often missing security headers). "
            "These are common on real sites and usually quick to fix — details and fixes are listed in Part B.",
        )
    if findings:
        return (
            "LOW — informational findings only",
            f"{len(findings)} informational item(s) were recorded. No urgent exploit path is indicated, "
            "but skim Part B so nothing important was mis-labeled.",
        )
    return (
        "CLEAR — no security findings in this run",
        "No security issues were flagged. That does not prove the site is fully secure — only that this "
        "scan did not match known problem patterns. Re-scan after big changes.",
    )


def build_search_conclusion(
    stats: CrawlStats,
    start_url: str,
    *,
    profile: str = "full",
    download_enabled: bool = False,
    security_enabled: bool = True,
    output_file: str = "",
    download_dir: str = "",
    config_meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    verdict_title, verdict_body = _risk_verdict(stats.findings)
    meta = dict(config_meta or {})
    meta.setdefault("profile", profile)
    meta.setdefault("download_files", download_enabled)
    meta.setdefault("security_scan", security_enabled)
    meta.setdefault("output_file", output_file)
    meta.setdefault("download_dir", download_dir)

    model = build_report_model(
        stats,
        start_url,
        config_meta=meta,
        verdict_title=verdict_title,
        verdict_body=verdict_body,
    )
    text = render_detailed_text(model)
    if output_file:
        text += f"\nFull URL list:     {output_file}"
    if download_dir:
        text += f"\nDownloaded files:  {download_dir}"
    text += f"\nReport generated:  {time.strftime('%Y-%m-%d %H:%M:%S')}\n"

    finding_groups = model["finding_groups"]
    severity_counts = Counter(model["severity_counts"])
    recommendations: List[str] = []
    if severity_counts.get("critical") or severity_counts.get("high"):
        recommendations.append("Fix critical/high issues first — use the “How to fix it” steps in Part B6.")
    if any(g["category"] == "header_audit" for g in finding_groups):
        recommendations.append(
            "Add missing security headers once at the web server or CDN so every page inherits them."
        )
    if model["sensitive"]:
        recommendations.append("Lock down or remove sensitive paths; require strong login + MFA for admin panels.")
    if model["enum_hits"]:
        recommendations.append(
            f"Manually open the {len(model['enum_hits'])} hidden path(s) and confirm they are intentional."
        )
    if model["s3"] or model["gcs"]:
        recommendations.append("Review cloud bucket hits — public list/read access is often accidental.")
    if model["broken"]:
        recommendations.append("Clean up broken links for quality and reduced attack-surface confusion.")
    defense = model.get("defense") or {}
    if defense.get("gap_rate_percent", 0) > 50:
        recommendations.append(
            "Bot/WAF catch rate is low — enable bot fight mode, rate limits, and CAPTCHA on login/signup."
        )
    snap = model["snapshot"]
    if snap.get("enum_words_total") and snap.get("enum_words_tested", 0) < snap["enum_words_total"] * 0.05:
        recommendations.append(
            "Directory scan was stopped very early (under ~5% of the wordlist). Leave it running longer for deeper coverage."
        )
    if not recommendations:
        recommendations.append("No urgent actions. Re-scan after you change headers, auth, or deploy new apps.")
    recommendations.append("Keep this report with found_urls.txt and the Reports/ folder.")

    interesting: List[str] = []
    if model["enum_hits"]:
        interesting.append(
            "Hidden / interesting paths ("
            + str(len(model["enum_hits"]))
            + "): "
            + ", ".join(model["enum_hits"][:8])
            + ("…" if len(model["enum_hits"]) > 8 else "")
        )
    interesting.extend(model.get("key_findings_lines") or model["takeaways"])

    return {
        "text": text,
        "verdict_title": verdict_title,
        "verdict_body": verdict_body,
        "severity_counts": dict(model["severity_counts"]),
        "category_counts": dict(model["category_counts"]),
        "snapshot": snap,
        "finding_groups": finding_groups,
        "recommendations": recommendations,
        "interesting": interesting,
        "defense": defense,
        "scan_setup": model["scan_setup"],
        "report_model": model,
    }
