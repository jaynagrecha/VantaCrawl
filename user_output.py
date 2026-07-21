"""Plain-language messages for live output, stats, and results."""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional

HTTP_STATUS_LABELS = {
    200: "page found",
    204: "page found (empty)",
    301: "moved permanently",
    302: "redirects elsewhere",
    401: "login required",
    403: "blocked but may exist",
    405: "method not allowed",
    500: "server error",
}

SEVERITY_LABELS = {
    "critical": "Critical",
    "high": "Important",
    "medium": "Moderate",
    "low": "Minor",
    "info": "Informational",
}

CATEGORY_LABELS = {
    "sql_injection": "Possible SQL injection",
    "xss": "Possible cross-site scripting (XSS)",
    "rce": "Possible remote code execution",
    "ssrf": "Possible server-side request forgery",
    "path_traversal": "Possible path traversal",
    "secrets_exposure": "Exposed secret or API key",
    "sensitive_path": "Sensitive file or folder",
    "header_audit": "Missing security header",
    "cors": "CORS misconfiguration",
    "auth": "Authentication weakness",
    "api_leak": "API information leak",
    "open_redirect": "Open redirect",
    "information_disclosure": "Information disclosure",
    "mixed_content": "Mixed content (HTTP on HTTPS)",
    "http_methods": "HTTP method surface",
    "authentication": "Authentication weakness",
    "directory_traversal": "Possible path traversal",
    "well_known": "Well-known endpoint",
    "cloud_url": "Cloud service URL",
    "file_metadata": "Embedded file metadata",
}

_STACK_FRAME_RE = re.compile(r"(?im)^\s*#\d+\s+0x[0-9a-fA-F]+\b.*$")
_STACKTRACE_SPLIT_RE = re.compile(r"(?i)\n\s*Stacktrace:\s*\n")


def sanitize_error_message(error: Any, *, max_len: int = 240) -> str:
    """Collapse driver/native stack dumps to a single human line.

    ChromeDriver embeds `#N 0xADDR <unknown>` frames in ``str(exc)``. Those must
    never flood Live Logs — keep the message, drop the native stack.
    """
    text = str(error or "").replace("\r\n", "\n").strip()
    if not text:
        return "unknown error"
    text = _STACKTRACE_SPLIT_RE.split(text, 1)[0]
    kept: List[str] = []
    for line in text.split("\n"):
        if _STACK_FRAME_RE.match(line):
            continue
        kept.append(line.strip())
    text = " ".join(part for part in kept if part)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > max_len:
        return text[: max_len - 1] + "…"
    return text


def _http_label(code: int) -> str:
    if code in HTTP_STATUS_LABELS:
        return HTTP_STATUS_LABELS[code]
    if 200 <= code < 300:
        return "page found"
    if 300 <= code < 400:
        return "redirect"
    if 400 <= code < 500:
        return "client error"
    if code >= 500:
        return "server error"
    return f"HTTP {code}"


def format_duration_friendly(seconds: float) -> str:
    """Short human duration for live stats (e.g. 45s, 3m 12s, 1h 05m)."""
    total = max(0, int(seconds))
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}h {minutes:02d}m"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def format_friendly_stats(stats) -> str:
    snap = stats.snapshot() if hasattr(stats, "snapshot") else stats
    pages = snap.get("pages_crawled", 0)
    links = snap.get("links_found", 0)
    enum_hits = snap.get("enum_hits", 0)
    tested = snap.get("enum_words_tested", 0)
    total = snap.get("enum_words_total", 0)
    queue = snap.get("queue_size", 0)
    speed = snap.get("urls_per_minute", 0)
    errors = snap.get("errors", 0)
    findings = snap.get("findings_count", 0)
    paused = snap.get("paused", False)
    elapsed = snap.get("elapsed_seconds", 0)

    parts = []
    if paused:
        parts.append("Paused")
    parts.append(f"{format_duration_friendly(elapsed)} elapsed")
    if pages:
        parts.append(f"{pages} page(s) checked")
    if links:
        parts.append(f"{links} link(s) discovered")
    if total:
        pct = min(100, int(tested * 100 / total)) if total else 0
        parts.append(f"folder scan {pct}% ({tested:,} of {total:,} names tried)")
    if enum_hits:
        parts.append(f"{enum_hits} hidden path(s) found")
    if queue:
        parts.append(f"{queue} page(s) waiting")
    if speed and pages:
        parts.append(f"~{speed:.0f} pages/min")
    if errors:
        parts.append(f"{errors} error(s)")
    if findings:
        parts.append(f"{findings} issue(s) flagged")

    return "Progress: " + " · ".join(parts)


def format_friendly_finding(item: Dict[str, Any]) -> str:
    severity = SEVERITY_LABELS.get(str(item.get("severity", "info")).lower(), "Note")
    category = str(item.get("category", "issue")).replace("_", " ")
    category = CATEGORY_LABELS.get(item.get("category", ""), category.title())
    url = item.get("url", "")
    detail = item.get("detail", "")
    if detail:
        return f"{severity} — {category} at {url}\n   {detail}"
    return f"{severity} — {category} at {url}"


def format_friendly_hits(hits: List[str], stats=None) -> str:
    if not hits:
        return "No hidden folders or files were discovered during directory scanning."
    count = len(hits)
    intro = (
        f"Found {count} hidden or interesting path(s). "
        "These pages or files responded differently from a normal “not found” page:\n"
    )
    lines = [intro]
    for url in hits:
        lines.append(f"  • {url}")
    if stats and getattr(stats, "enum_status_codes", None):
        codes = dict(stats.enum_status_codes)
        if codes:
            code_bits = [f"{_http_label(int(k))} ({k})" for k in sorted(codes.keys())]
            lines.append("\nResponse summary: " + ", ".join(code_bits))
    return "\n".join(lines)


def format_friendly_findings(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return "No security issues were flagged during this scan."
    intro = (
        f"The scan flagged {len(findings)} item(s) that may need a closer look. "
        "Only investigate on systems you are allowed to test:\n"
    )
    return intro + "\n\n".join(format_friendly_finding(item) for item in findings)


def format_enum_progress(words_done: int, total_words: int, hits: int) -> str:
    if not total_words:
        return "Scanning folders and file names…"
    pct = min(100, int(words_done * 100 / total_words))
    hit_part = f" · {hits} found so far" if hits else ""
    return f"Trying folder/file names: {pct}% done ({words_done:,} of {total_words:,}){hit_part}"


def simplify_log_line(message: str) -> str:
    raw = str(message)
    text = raw.strip()
    if not text:
        return text

    # ChromeDriver / native stacks arriving as one multiline blob
    if "Stacktrace:" in text or _STACK_FRAME_RE.search(text):
        first = text.split("\n", 1)[0].strip()
        if first.lower().startswith("error accessing "):
            m = re.match(r"(?i)^Error accessing (.+):\s*(.*)$", first)
            if m:
                url, err = m.groups()
                return f"Could not open {url} — {sanitize_error_message(err or first)}"
        return sanitize_error_message(text)

    if text.startswith("Progress:"):
        return text

    if text.startswith("WHAT THIS SCAN DID") or "OVERALL CONCLUSION" in text:
        return message

    if text.startswith("[Stats]"):
        return _translate_stats_line(text)

    m = re.match(r"^HIT \[(\d+)\] (\S+) \(size=(\d+)\)$", text)
    if m:
        code, url, size = m.groups()
        return f"Found hidden path ({_http_label(int(code))}): {url} ({_format_size(int(size))})"

    m = re.match(
        r"^FINDING \[(\w+)\] ([^:]+): (\S+) — (.+)$",
        text,
    )
    if m:
        severity, category, url, detail = m.groups()
        item = {"severity": severity, "category": category.strip(), "url": url, "detail": detail}
        return format_friendly_finding(item)

    # Multiline "Error accessing" (driver stacks) — match first line only
    m = re.match(r"(?is)^Error accessing (.+?):\s*(.+)$", text)
    if m and ("\n" in text or "Stacktrace:" in text):
        url, err = m.groups()
        return f"Could not open {url} — {sanitize_error_message(err)}"

    replacements = [
        (r"^=== Target (\d+)/(\d+): (.+) ===$", r"Starting target \1 of \2: \3"),
        (r"^Crawling: (.+)$", r"Checking page: \1"),
        (r"^Not modified \(304\): (.+)$", r"Already up to date (unchanged): \1"),
        (r"^Skipped duplicate content: (.+)$", r"Skipped duplicate page: \1"),
        (r"^Skipped download: (.+) \((.+)\)$", r"Skipped download: \1 (\2)"),
        (r"^Skipped: (.+) \(extension filter\)$", r"Skipped (file type filter): \1"),
        (r"^Skipped: (.+) \(exceeds size limit\)$", r"Skipped (file too large): \1"),
        (r"^Error accessing (.+): (.+)$", r"Could not open \1 — \2"),
        (
            r"^=== Enum-only mode \(Gobuster-beater\) — skipping crawl phase ===$",
            "Directory scan only — skipping regular page crawl.",
        ),
        (r"^=== Pro directory enumeration ===$", "Starting advanced folder and file name scan…"),
        (
            r"^Pro enum: ([\d,]+) words · (\d+) threads · flat$",
            r"Scanning \1 folder/file names using \2 parallel checks (single level).",
        ),
        (
            r"^Pro enum: ([\d,]+) words · (\d+) threads · depth (\d+)$",
            r"Scanning \1 folder/file names using \2 parallel checks (up to \3 levels deep).",
        ),
        (
            r"^Wildcard detected — filtering (\d+) response fingerprint\(s\)$",
            r"This site shows fake “found” pages for random URLs — filtering \1 false-match pattern(s).",
        ),
        (
            r"^Resumed enum checkpoint at word ([\d,]+)/([\d,]+)$",
            r"Resuming folder scan from name \1 of \2.",
        ),
        (
            r"^Directory enumeration finished — (\d+) hit\(s\)\.$",
            r"Folder scan complete — \1 hidden path(s) found.",
        ),
        (r"^Enum under (.+) \(depth (\d+)\)$", r"Scanning inside folder \1 (level \2)…"),
        (r"^Enum word limit reached \(([\d,]+)\)\.$", r"Folder scan stopped at the \1-name limit you set."),
        (r"^Fetching Wayback Machine seeds\.\.\.$", "Looking up old URLs from the Wayback Machine…"),
        (r"^Fetching Common Crawl seeds\.\.\.$", "Looking up old URLs from Common Crawl…"),
        (r"^Loaded (\d+) historical seed URLs\.$", r"Added \1 historical URL(s) to the scan list."),
        (r"^Resumed checkpoint: (\d+) queued, (\d+) visited\.$", r"Resumed previous scan — \1 waiting, \2 already checked."),
        (r"^Enumerating subdomains\.\.\.$", "Searching for related subdomains…"),
        (
            r"^Subdomain enum: ([\d,]+) host\(s\) · (\d+) threads$",
            r"Subdomain scan: \1 host(s) · \2 threads",
        ),
        (
            r"^Subdomain enum done: (\d+) live host\(s\) of ([\d,]+) probed$",
            r"Subdomain scan complete — \1 live host(s) of \2 probed.",
        ),
        (r"^Subdomain found: (.+)$", r"Related subdomain found: \1"),
        (r"^Distributed mode: Redis at (.+)$", r"Multi-machine mode enabled (Redis at \1)."),
        (r"^Pulled (\d+) URL\(s\) from Redis queue$", r"Picked up \1 URL(s) from the shared queue."),
        (
            r"^Request stealth enabled \((.+)\) — .+$",
            r"Request stealth is on (\1): using browser-like headers and pacing.",
        ),
        (
            r"^Chrome TLS impersonation on \((.+)\) — .+$",
            r"Chrome TLS impersonation on (\1): matching real-browser JA3/HTTP2.",
        ),
        (
            r"^Chrome TLS impersonation unavailable .+ falling back to httpx HTTP/2\.$",
            "Chrome TLS package missing — using httpx HTTP/2 fallback.",
        ),
        (
            r"^Real Chrome fetch path ready — (.+)\.$",
            r"Real Chrome fetch path ready — \1.",
        ),
        (
            r"^Synced (\d+) browser cookie\(s\) into HTTP jar for (.+)$",
            r"Synced \1 browser cookie(s) into HTTP jar for \2.",
        ),
        (
            r"^Warming up with a few ordinary-looking page requests…$",
            "Warming up with a few ordinary-looking page requests…",
        ),
        (
            r"^Protection / challenge signal detected \((.+)\) — slowing down for a moment\.$",
            r"The site looked like it blocked or challenged the scan (\1). Slowing down for a moment.",
        ),
        (
            r"^Checking what protections this server appears to use…$",
            "Checking what protections this server appears to use…",
        ),
        (
            r"^Protections spotted so far: (.+)$",
            r"Protections spotted so far: \1",
        ),
        (
            r"^No clear bot-management fingerprint yet — continuing scan measurement\.$",
            "No clear bot-management fingerprint yet — continuing to measure catch vs gaps.",
        ),
        (
            r"^Defense report \(web page\): (.+)$",
            r"Defense report (web page): \1",
        ),
        (
            r"^Defense report \(text\): (.+)$",
            r"Defense report (text file): \1",
        ),
        (r"^Generating reports\.\.\.$", "Creating your reports…"),
        (r"^All reports saved to: (.+)$", r"Reports saved to: \1"),
        (r"^Search report \(HTML\): (.+)$", r"Summary report (web page): \1"),
        (r"^Search report \(text\): (.+)$", r"Summary report (text file): \1"),
        (r"^Site map graph: (.+)$", r"Site map diagram saved: \1"),
        (r"^Burp export: (.+)$", r"Burp-compatible export saved: \1"),
        (r"^ZAP export: (.+)$", r"ZAP-compatible export saved: \1"),
        (r"^Downloaded: (.+) to (.+)$", r"Saved: \1"),
        (r"^Downloaded server file as text: (.+) to (.+)$", r"Saved server file as text: \1"),
        (
            r"^Downloading (\d+) supporting file\(s\) for offline view of (.+)$",
            r"Also downloading \1 supporting file(s) (CSS/JS/images) for offline view of \2",
        ),
        (
            r"^Saved (\d+) supporting file\(s\) for (.+)$",
            r"Saved \1 supporting file(s) for \2",
        ),
        (r"^Could not save asset (.+): (.+)$", r"Could not save supporting file \1 — \2"),
        (r"^VHOST hit: (.+) \[(\d+)\] size=(\d+)$", r"Found alternate site name: \1 (HTTP \2)"),
        (r"^S3 bucket: (.+) \[(\d+)\]$", r"Possible cloud storage bucket: \1"),
        (r"^GCS bucket: (.+) \[(\d+)\]$", r"Possible Google Cloud bucket: \1"),
        (r"^Hit follow-up scan failed: (.+) \((.+)\)$", r"Could not run extra checks on \1 — \2"),
        (r"^Form probe: (.+) -> (\d+)$", r"Tested form at \1 (response \2)"),
        (r"^Form probe failed: (.+) \((.+)\)$", r"Form test failed at \1 — \2"),
        (r"^Paused\.$", "Scan paused."),
        (r"^Resumed\.$", "Scan resumed."),
        (r"^Stopped by user\.$", "Scan stopped."),
        (r"^\nStopped by user\.$", "Scan stopped."),
    ]

    for pattern, repl in replacements:
        new_text = re.sub(pattern, repl, text)
        if new_text != text:
            return new_text

    m = re.match(
        r"^Brute force depth (\d+) \((\d+)% · batch (\d+)%\): "
        r"([\d,]+)/([\d,]+) words · batch ([\d,]+)/([\d,]+) under (.+?)"
        r"(?: · trying (\S+))?( · ETA ~.+)?$",
        text,
    )
    if m:
        depth, word_pct, _batch_pct, done, total, _bn, _tb, folder, trying, eta = m.groups()
        folder = folder or "/"
        eta_text = eta.replace(" · ETA ~", " · about ") if eta else ""
        trying_text = f" · now {trying}" if trying else ""
        return (
            f"Trying names inside {folder} (level {depth}): {word_pct}% complete "
            f"({done} of {total} names){trying_text}{eta_text or ''}"
        )

    if text.startswith("Page ") and "queue" in text:
        m = re.match(r"^Page (\d+) of ~(\d+) · queue (\d+)$", text)
        if m:
            return f"Checking page {m.group(1)} of about {m.group(2)} ({m.group(3)} still waiting)"

    if text.startswith("Total downloaded:"):
        return text.replace("Total downloaded:", "Downloaded so far:")
        m = re.match(r"^Enum: ([\d,]+)/([\d,]+) \((\d+)%\) · (\d+) hits$", text)
        if m:
            return format_enum_progress(int(m.group(1).replace(",", "")), int(m.group(2).replace(",", "")), int(m.group(4)))

    return text


def _translate_stats_line(line: str) -> str:
    nums = {}
    for key in (
        "crawled", "found", "enum", "tested", "queue", "errors", "findings",
    ):
        m = re.search(rf"{key}=([\d,]+)", line)
        if m:
            nums[key] = int(m.group(1).replace(",", ""))
    tested_total = re.search(r"tested=([\d,]+)/([\d,]+)", line)
    snap = {
        "pages_crawled": nums.get("crawled", 0),
        "links_found": nums.get("found", 0),
        "enum_hits": nums.get("enum", 0),
        "enum_words_tested": int(tested_total.group(1).replace(",", "")) if tested_total else 0,
        "enum_words_total": int(tested_total.group(2).replace(",", "")) if tested_total else 0,
        "queue_size": nums.get("queue", 0),
        "errors": nums.get("errors", 0),
        "findings_count": nums.get("findings", 0),
        "urls_per_minute": 0,
        "paused": False,
    }
    m = re.search(r"([\d.]+)/min", line)
    if m:
        snap["urls_per_minute"] = float(m.group(1))
    return format_friendly_stats(snap)


def _format_size(num: int) -> str:
    if num < 1024:
        return f"{num} bytes"
    if num < 1024 * 1024:
        return f"{round(num / 1024, 1)} KB"
    return f"{round(num / (1024 * 1024), 1)} MB"


def wrap_output_callback(callback: Optional[Callable[[str], None]]) -> Callable[[str], None]:
    if callback is None:
        return lambda _message: None

    def wrapped(message: str):
        raw = str(message)
        if raw.startswith("\n") and ("WHAT THIS SCAN DID" in raw or "OVERALL CONCLUSION" in raw):
            callback(raw)
            return
        callback(simplify_log_line(raw))

    return wrapped


def format_comparison_summary(summary: Dict[str, Any]) -> str:
    lines = ["Comparison complete:"]
    new_hits = summary.get("new_enum_hits", summary.get("enum_hits_added"))
    if new_hits is not None:
        lines.append(f"  • {new_hits} new hidden path(s) since the last scan")
    removed_hits = summary.get("removed_enum_hits")
    if removed_hits:
        lines.append(f"  • {removed_hits} hidden path(s) no longer detected")
    new_findings = summary.get("new_findings", summary.get("findings_added"))
    if new_findings is not None:
        lines.append(f"  • {new_findings} new possible security issue(s)")
    removed = summary.get("removed_urls")
    if removed is not None:
        lines.append(f"  • {removed} URL(s) no longer present")
    out_path = summary.get("output_path") or summary.get("report_path")
    if out_path:
        lines.append(f"  • Full comparison saved to: {out_path}")
    if len(lines) == 1:
        for key, value in summary.items():
            label = key.replace("_", " ").capitalize()
            lines.append(f"  • {label}: {value}")
    return "\n".join(lines)
