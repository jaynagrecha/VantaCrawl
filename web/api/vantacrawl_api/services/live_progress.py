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
    if "trying folder/file" in text or "folder/file names" in text or "brute force" in text:
        return "enum"
    if text.startswith("page ") or "· queue" in text:
        return "crawl"
    if "downloaded" in text and "total downloaded" in text:
        return "download"
    if any(k in text for k in ("security", "vuln", "finding", "defense")):
        return "security"
    if previous in ("crawl", "enum", "download", "security", "starting"):
        return previous
    return "enum" if enum_only else "crawl"


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

    pages = int(snap.get("pages_crawled") or prev.get("pages_crawled") or 0)
    estimate = int(getattr(stats, "session_total_estimate", 0) or prev.get("pages_estimate") or 0)
    queue = int(snap.get("queue_size") or prev.get("queue_size") or 0)
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
    if resolved_phase == "enum" and enum_total > 0:
        progress_pct = min(100, int(enum_done * 100 / enum_total))
    elif resolved_phase in ("crawl", "download") and estimate > 0:
        progress_pct = min(99, int(pages * 100 / max(estimate, 1)))
    elif total > 0:
        progress_pct = min(100, int(done * 100 / total))
    elif prev.get("progress_pct"):
        progress_pct = int(prev["progress_pct"])

    eta_seconds: Optional[int] = None
    if resolved_phase == "enum" and enum_total > enum_done > 0 and elapsed > 2:
        rate = enum_done / elapsed
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

    health = "OK"
    health_detail = "No blocks detected"
    if challenge_events >= 8 or (protections and challenge_events >= 3):
        health = "Challenged"
        health_detail = "Target is blocking or challenging the scan"
    elif challenge_events > 0:
        health = "Slowing"
        health_detail = "Some challenges / rate limits seen"
    elif errors >= 15:
        health = "Degraded"
        health_detail = "Elevated request errors"
    elif protections:
        health = "OK"
        health_detail = "Protections seen, traffic still flowing"

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
        "blocks": blocks,
        "challenge_events": challenge_events,
        "protections": protections[:8],
        "protections_label": ", ".join(protections[:4]) if protections else "none",
        "health": health,
        "health_detail": health_detail,
    }
