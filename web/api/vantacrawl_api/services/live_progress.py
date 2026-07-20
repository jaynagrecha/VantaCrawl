"""Build rich live progress payloads from CrawlStats + crawler progress callbacks."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

_PAGE_RE = re.compile(
    r"Page\s+(\d+)\s+of\s+~?(\d+)\s*·\s*queue\s+(\d+)",
    re.IGNORECASE,
)
_ENUM_RE = re.compile(
    r"\((\d[\d,]*)\s+of\s+(\d[\d,]*)\)",
    re.IGNORECASE,
)
_HITS_RE = re.compile(r"·\s*(\d+)\s+found so far", re.IGNORECASE)


def _findings_preview(stats) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    try:
        for item in list(getattr(stats, "findings", []) or [])[:40]:
            if not isinstance(item, dict):
                continue
            out.append(
                {
                    "severity": str(item.get("severity") or item.get("severity_label") or ""),
                    "title": str(item.get("title") or item.get("detail") or item.get("type") or "")[:160],
                    "url": str(item.get("url") or ""),
                }
            )
    except Exception:
        return []
    return out


def infer_phase(progress_text: str, *, enum_only: bool = False, previous: str = "") -> str:
    text = (progress_text or "").lower()
    if any(
        k in text
        for k in (
            "api recon",
            "api passive",
            "api docs",
            "api active",
            "api import",
            "graphql introspection",
        )
    ):
        return "api_recon"
    if any(
        k in text
        for k in (
            "trying folder/file",
            "folder/file names",
            "folder and file name",
            "advanced folder",
            "directory enum",
            "preparing directory enum",
            "building enum wordlist",
            "pro enum:",
            "brute force",
        )
    ):
        return "enum"
    if text.startswith("page ") or "· queue" in text or text.startswith("crawling:"):
        return "crawl"
    if "downloaded" in text and "total downloaded" in text:
        return "download"
    if any(k in text for k in ("security", "vuln", "finding", "defense verify")):
        return "security"
    if any(
        k in text
        for k in (
            "wayback",
            "common crawl",
            "historical seed",
            "request stealth",
            "protections spotted",
            "checking what protections",
            "looking up old urls",
        )
    ):
        return "recon"
    if previous in ("crawl", "enum", "api_recon", "download", "security", "recon", "starting"):
        return previous
    return "enum" if enum_only else "crawl"


def _num(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def build_live_progress(
    stats,
    *,
    progress_text: str = "",
    total: int = 0,
    done: int = 0,
    phase: Optional[str] = None,
    enum_only: bool = False,
    previous: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    prev = dict(previous or {})
    snap = stats.snapshot() if hasattr(stats, "snapshot") else {}
    text = (progress_text or prev.get("progress_text") or "")[:240]
    resolved_phase = phase or infer_phase(text, enum_only=enum_only, previous=str(prev.get("phase") or ""))

    pages = _num(snap.get("pages_crawled"), _num(prev.get("pages_crawled")))
    estimate = _num(getattr(stats, "session_total_estimate", 0), _num(prev.get("pages_estimate")))
    queue = _num(snap.get("queue_size"), _num(prev.get("queue_size")))
    page_match = _PAGE_RE.search(text)
    if page_match:
        pages = int(page_match.group(1))
        estimate = int(page_match.group(2))
        queue = int(page_match.group(3))
    if estimate < pages:
        estimate = pages

    enum_done = int(snap.get("enum_words_tested") or prev.get("enum_words_tested") or 0)
    enum_total = int(snap.get("enum_words_total") or prev.get("enum_words_total") or 0)
    enum_match = _ENUM_RE.search(text)
    if enum_match:
        enum_done = int(enum_match.group(1).replace(",", ""))
        enum_total = int(enum_match.group(2).replace(",", ""))

    enum_hits = int(snap.get("enum_hits") or prev.get("enum_hits") or 0)
    hits_match = _HITS_RE.search(text)
    if hits_match:
        enum_hits = max(enum_hits, int(hits_match.group(1)))

    findings = int(snap.get("findings_count") or prev.get("findings") or 0)
    elapsed = float(snap.get("elapsed_seconds") or prev.get("elapsed_seconds") or 0)
    upm = float(snap.get("urls_per_minute") or 0)

    progress_pct = 0
    if resolved_phase == "enum":
        # Do not keep crawl's 100% while wordlist/baseline is still preparing
        if enum_total > 0:
            progress_pct = min(100, int(enum_done * 100 / enum_total))
        else:
            progress_pct = 0
    elif resolved_phase in ("crawl", "download") and estimate > 0:
        progress_pct = min(99, int(pages * 100 / max(estimate, 1)))
    elif total > 0:
        progress_pct = min(100, int(done * 100 / total))
    elif prev.get("progress_pct") and resolved_phase not in ("enum", "security", "recon"):
        progress_pct = int(prev["progress_pct"])

    eta_seconds: Optional[int] = None
    if resolved_phase == "enum" and enum_total > enum_done > 0 and elapsed > 2:
        rate = enum_done / max(elapsed, 0.001)
        if rate > 0:
            eta_seconds = max(0, int((enum_total - enum_done) / rate))
    elif resolved_phase == "crawl" and estimate > pages and upm > 0:
        eta_seconds = max(0, int((estimate - pages) / (upm / 60.0)))

    enum_urls = list(snap.get("enum_hit_urls") or prev.get("enum_hit_urls") or [])[:80]
    preview = _findings_preview(stats) or list(prev.get("findings_preview") or [])[:40]

    errors = int(snap.get("errors") or prev.get("errors") or 0)
    defense = snap.get("defense") if isinstance(snap.get("defense"), dict) else {}
    protections = list(defense.get("protections_detected") or prev.get("protections") or [])
    blocks = int(
        defense.get("caught_by_protection")
        or prev.get("blocks")
        or 0
    )
    # Log-derived challenges (Cloudflare backoff lines) merge in from previous
    log_challenges = int(prev.get("challenge_events") or 0)
    challenge_events = max(blocks, log_challenges)
    block_journal = list(defense.get("block_journal") or prev.get("block_journal") or [])[-30:]
    block_status_counts = dict(
        defense.get("block_status_counts") or prev.get("block_status_counts") or {}
    )
    protection_block_counts = dict(
        defense.get("protection_block_counts") or prev.get("protection_block_counts") or {}
    )

    # Rate-based health: raw error counts panic users on secured sites mid-crawl.
    attempts = max(pages + errors, 1)
    error_rate = errors / attempts
    error_rate_pct = round(error_rate * 100, 1)
    # Pages/min naturally drops during enum — that is not a stalled crawl
    stalled = (
        resolved_phase in ("crawl", "download")
        and pages >= 25
        and upm < 1.5
        and errors >= 8
    )

    caught = int(defense.get("caught_by_protection") or blocks or 0)
    unchallenged = int(defense.get("completed_without_challenge") or 0)
    scored = max(caught + unchallenged, pages + errors, 1)
    block_rate = challenge_events / scored
    block_rate_pct = round(block_rate * 100, 1)
    # Big WAF sites trip a few 403s immediately — don't scream Challenged at 3.
    # Challenged when block *rate* is high with a meaningful sample, or absolute floor.
    is_challenged = (challenge_events >= 12 and block_rate >= 0.15) or challenge_events >= 25

    backoff_rem = float(snap.get("backoff_remaining_seconds") or prev.get("backoff_remaining_seconds") or 0)
    heartbeat = str(snap.get("heartbeat") or prev.get("heartbeat") or "")
    if backoff_rem > 0.4 and not heartbeat:
        heartbeat = f"Waiting on WAF backoff… {int(backoff_rem + 0.99)}s"

    health = "OK"
    health_detail = "Scan progressing normally"
    if is_challenged:
        health = "Challenged"
        health_detail = (
            f"{challenge_events} WAF/bot block(s) ({block_rate_pct}% of scored traffic)"
            + (f" · {', '.join(protections[:3])}" if protections else "")
            + " — separate from fetch Errors"
        )
    elif challenge_events > 0:
        health = "Slowing"
        health_detail = (
            f"{challenge_events} challenge/block event(s) ({block_rate_pct}% of scored) — "
            "normal on protected sites; journal has the detail"
        )
    elif stalled or (error_rate >= 0.25 and errors >= 10) or (pages < 8 and errors >= 15):
        health = "Degraded"
        health_detail = (
            f"Crawl struggling ({error_rate_pct}% fetch failures"
            + (", nearly stalled" if stalled else "")
            + ")"
        )
    elif error_rate >= 0.12 and errors >= 8:
        health = "Noisy"
        health_detail = (
            f"Some failed fetches ({errors} errors, {error_rate_pct}%) — "
            "common on locked-down sites; scan can still be useful"
        )
    elif errors > 0 and protections:
        health = "OK"
        health_detail = (
            f"Protections seen; {errors} failed fetch(es) "
            f"({error_rate_pct}%) — normal noise unless rate climbs"
        )
    elif protections:
        health = "OK"
        health_detail = "Protections seen, traffic still flowing"
    elif errors > 0:
        health = "OK"
        health_detail = f"{errors} failed fetch(es) ({error_rate_pct}%) — within normal range"

    if heartbeat:
        health_detail = f"{heartbeat} · {health_detail}"

    return {
        "phase": resolved_phase,
        "progress_pct": progress_pct,
        "progress_text": text,
        "pages_crawled": pages,
        "pages_estimate": estimate,
        "queue_size": queue,
        "enum_hits": enum_hits,
        "enum_words_tested": enum_done,
        "enum_words_total": enum_total,
        "findings": findings,
        "findings_preview": preview,
        "enum_hit_urls": enum_urls,
        "urls_per_minute": upm,
        "eta_seconds": eta_seconds,
        "elapsed_seconds": elapsed,
        "bytes_downloaded": int(snap.get("bytes_downloaded") or prev.get("bytes_downloaded") or 0),
        "bytes_total": int(total or prev.get("bytes_total") or 0),
        "bytes_done": int(done or prev.get("bytes_done") or 0),
        "errors": errors,
        "error_rate_pct": error_rate_pct,
        "blocks": blocks,
        "challenge_events": challenge_events,
        "block_rate_pct": block_rate_pct,
        "protections": protections[:8],
        "protections_label": ", ".join(protections[:4]) if protections else "none",
        "block_journal": block_journal,
        "block_status_counts": block_status_counts,
        "protection_block_counts": protection_block_counts,
        "backoff_remaining_seconds": round(backoff_rem, 1),
        "heartbeat": heartbeat,
        "health": health,
        "health_detail": health_detail,
    }
