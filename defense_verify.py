"""Defense verification: fingerprint protections and score catch vs unchallenged traffic.

This measures how often the target's bot/WAF/CAPTCHA signals stopped the scanner,
and how often requests completed without a detected challenge (gaps to harden).
It does not solve CAPTCHAs or bypass bot management.
"""

from __future__ import annotations

import json
import os
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from evasion_layer import detect_challenge

# Header / body signals → protection family
PROTECTION_SIGNATURES = (
    ("cloudflare", ("cf-ray", "cf-mitigated", "cf-cache-status", "__cf_bm", "cloudflare")),
    ("cloudflare_turnstile", ("turnstile", "cf-turnstile", "challenges.cloudflare.com")),
    ("recaptcha", ("recaptcha", "g-recaptcha", "google.com/recaptcha")),
    ("hcaptcha", ("hcaptcha", "h-captcha")),
    ("datadome", ("datadome", "x-datadome", "dd_")),
    ("perimeterx", ("perimeterx", "_px", "px-cdn")),
    ("akamai", ("akamai", "akamai-origin-hop", "x-akamai", "edgesuite", "akamaighost")),
    ("imperva", ("imperva", "incapsula", "x-iinfo")),
    ("sucuri", ("sucuri", "x-sucuri")),
    ("aws_waf", ("x-amzn-waf", "awselb", "x-amz-cf", "x-amzn-requestid", "aws waf")),
    ("modsecurity", ("mod_security", "modsecurity")),
    ("rate_limit", ("retry-after",)),
)

SECURITY_HEADER_CHECKS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)

# Headers worth keeping in forensic capture (case-insensitive match / prefix)
FORENSIC_HEADER_KEYS = (
    "server",
    "date",
    "content-type",
    "content-length",
    "retry-after",
    "www-authenticate",
    "cf-ray",
    "cf-mitigated",
    "cf-cache-status",
    "x-amzn-waf",
    "x-amzn-requestid",
    "x-amz-cf-id",
    "x-amz-id-2",
    "x-akamai-request-id",
    "akamai-origin-hop",
    "x-iinfo",
    "x-cdn",
    "x-sucuri-id",
    "x-datadome",
    "x-blocked-by",
    "x-error",
    "x-cache",
    "via",
)

REASON_HINTS = {
    "rate_limit": "Rate limited (HTTP 429 / Retry-After) — scanner slowed or paused.",
    "cloudflare_block": "Cloudflare returned a hard block (typically HTTP 403).",
    "cloudflare": "Cloudflare challenge or bot-management page detected.",
    "cf-challenge": "Cloudflare JS/browser challenge interstitial.",
    "cloudflare_turnstile": "Cloudflare Turnstile CAPTCHA challenge.",
    "akamai": "Akamai bot/WAF fingerprint in headers or denial page.",
    "aws_waf": "AWS WAF / ALB protection fingerprint on the response.",
    "access denied": "Generic access-denied page body.",
    "request blocked": "Response body indicates the request was blocked.",
    "datadome": "DataDome bot protection signal.",
    "perimeterx": "PerimeterX / HUMAN bot protection signal.",
    "imperva": "Imperva / Incapsula protection signal.",
    "sucuri": "Sucuri WAF signal.",
    "captcha": "CAPTCHA challenge content detected.",
    "recaptcha": "reCAPTCHA challenge content detected.",
    "hcaptcha": "hCaptcha challenge content detected.",
}


@dataclass
class DefenseEvent:
    url: str
    status: int
    outcome: str  # caught | unchallenged | error
    signal: str
    protections: List[str] = field(default_factory=list)
    reason: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body_snippet: str = ""
    time: float = field(default_factory=time.time)

    def journal_dict(self) -> Dict[str, Any]:
        """Slim payload for live cockpit."""
        # Avoid duplicating the same label as both signal and protection chip
        signal = (self.signal or "").strip()
        protections = [p for p in self.protections if p and p.lower() != signal.lower()][:6]
        return {
            "url": self.url,
            "status": self.status,
            "signal": signal,
            "protections": protections,
            "reason": self.reason,
            # Explicit UTC clock — browsers must not treat this as local time
            "time": time.strftime("%H:%M:%S UTC", time.gmtime(self.time)),
            "time_unix": self.time,
        }

    def forensic_dict(self) -> Dict[str, Any]:
        """Full payload for defense report / JSON export."""
        return {
            "url": self.url,
            "status": self.status,
            "outcome": self.outcome,
            "signal": self.signal,
            "protections": list(self.protections),
            "reason": self.reason,
            "headers": dict(self.headers),
            "body_snippet": self.body_snippet,
            "time_unix": self.time,
            "time_utc": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(self.time)),
        }


def _fingerprint_protections(headers: Dict[str, str], body_preview: str = "") -> List[str]:
    combined = " ".join(f"{k}:{v}" for k, v in (headers or {}).items()).lower()
    combined += " " + (body_preview or "").lower()[:6000]
    header_keys = {k.lower() for k in (headers or {})}
    found: List[str] = []
    for name, tokens in PROTECTION_SIGNATURES:
        if any(token in combined or token in header_keys for token in tokens):
            found.append(name)
    return found


def _extract_forensic_headers(headers: Dict[str, str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for key, value in (headers or {}).items():
        lk = key.lower()
        if lk in FORENSIC_HEADER_KEYS or lk.startswith("x-amzn") or lk.startswith("x-akamai") or lk.startswith("cf-"):
            text = str(value)
            if len(text) > 240:
                text = text[:240] + "…"
            out[key] = text
    return out


def _body_snippet(body_preview: str, limit: int = 480) -> str:
    text = (body_preview or "").replace("\r", " ").replace("\n", " ").strip()
    if len(text) > limit:
        return text[:limit] + "…"
    return text


def _explain(status: int, signal: str, protections: List[str], headers: Dict[str, str]) -> str:
    parts: List[str] = []
    if status:
        parts.append(f"HTTP {status}")
    if signal and signal != "none":
        hint = REASON_HINTS.get(signal) or f"Challenge/block marker: {signal}"
        parts.append(hint)
    if protections:
        parts.append("Protections on this response: " + ", ".join(protections))
    retry = headers.get("Retry-After") or headers.get("retry-after")
    if retry:
        parts.append(f"Retry-After: {retry}")
    server = headers.get("Server") or headers.get("server")
    if server:
        parts.append(f"Server: {server}")
    if not parts:
        return "No challenge/block signal on this response."
    return " · ".join(parts)


@dataclass
class DefenseTracker:
    """Tracks protection fingerprint and catch / unchallenged counts during a scan."""

    start_url: str = ""
    protections_seen: Set[str] = field(default_factory=set)
    security_headers_present: Set[str] = field(default_factory=set)
    security_headers_missing: Set[str] = field(default_factory=set)
    signal_counts: Counter = field(default_factory=Counter)
    block_status_counts: Counter = field(default_factory=Counter)
    protection_block_counts: Counter = field(default_factory=Counter)
    caught_count: int = 0
    unchallenged_count: int = 0
    error_count: int = 0
    rate_limit_count: int = 0
    captcha_signal_count: int = 0
    bot_wall_count: int = 0
    sample_caught: List[DefenseEvent] = field(default_factory=list)
    sample_unchallenged: List[DefenseEvent] = field(default_factory=list)
    block_events: List[DefenseEvent] = field(default_factory=list)
    fingerprint_notes: List[str] = field(default_factory=list)
    _max_samples: int = 40
    _max_block_events: int = 120

    def observe_headers(self, headers: Dict[str, str], body_preview: str = ""):
        for name in _fingerprint_protections(headers, body_preview):
            self.protections_seen.add(name)

        header_keys = {k.lower() for k in (headers or {})}
        present = set()
        for h in SECURITY_HEADER_CHECKS:
            if h in header_keys:
                present.add(h)
        self.security_headers_present.update(present)
        if not self.security_headers_missing and headers:
            self.security_headers_missing = set(SECURITY_HEADER_CHECKS) - present

        server = (headers or {}).get("server") or (headers or {}).get("Server") or ""
        if server and server not in self.fingerprint_notes:
            self.fingerprint_notes.append(f"Server header: {server}")

    def record_response(
        self,
        url: str,
        status_code: int,
        headers: Optional[Dict[str, str]] = None,
        body_preview: str = "",
    ):
        headers = dict(headers or {})
        self.observe_headers(headers, body_preview)
        on_response = _fingerprint_protections(headers, body_preview)
        forensic_headers = _extract_forensic_headers(headers)
        snippet = _body_snippet(body_preview)

        # Enrich preview with header tokens for detect_challenge
        bits = [body_preview]
        server = (headers.get("server") or "").lower()
        if "cloudflare" in server:
            bits.append("cloudflare")
        if headers.get("cf-ray") or headers.get("cf-mitigated"):
            bits.append("cf-challenge")
        if headers.get("cf-mitigated"):
            bits.append("challenge-platform")
        for name in on_response:
            bits.append(name.replace("_", " "))
        preview = " ".join(bits)

        signal = detect_challenge(status_code, preview)
        preview_l = preview.lower()
        if not signal:
            for marker, label in (
                ("turnstile", "cloudflare_turnstile"),
                ("hcaptcha", "hcaptcha"),
                ("recaptcha", "recaptcha"),
                ("g-recaptcha", "recaptcha"),
                ("akamai", "akamai"),
                ("x-amzn-waf", "aws_waf"),
                ("access denied", "access denied"),
                ("request blocked", "request blocked"),
            ):
                if marker in preview_l:
                    signal = label
                    break

        # Hard deny statuses with a known WAF fingerprint still count as caught
        if not signal and status_code in (401, 403, 429, 503) and on_response:
            preferred = [p for p in on_response if p != "rate_limit"]
            signal = preferred[0] if preferred else on_response[0]
            if status_code == 429:
                signal = "rate_limit"

        if signal:
            self.caught_count += 1
            self.signal_counts[signal] += 1
            self.block_status_counts[str(status_code)] += 1
            for name in on_response or ([signal] if signal else []):
                self.protection_block_counts[name] += 1
            if signal == "rate_limit" or status_code == 429:
                self.rate_limit_count += 1
            if any(x in signal for x in ("captcha", "recaptcha", "hcaptcha", "turnstile")):
                self.captcha_signal_count += 1
            if any(x in signal for x in ("cloudflare", "challenge", "datadome", "akamai", "aws_waf", "bot", "blocked")):
                self.bot_wall_count += 1
            reason = _explain(status_code, signal, on_response, headers)
            event = DefenseEvent(
                url=url,
                status=status_code,
                outcome="caught",
                signal=signal,
                protections=on_response,
                reason=reason,
                headers=forensic_headers,
                body_snippet=snippet,
            )
            if len(self.sample_caught) < self._max_samples:
                self.sample_caught.append(event)
            if len(self.block_events) < self._max_block_events:
                self.block_events.append(event)
            elif self.block_events:
                # Keep a rolling window of the newest forensic events
                self.block_events.pop(0)
                self.block_events.append(event)
            return

        if status_code >= 500:
            self.error_count += 1
            return

        self.unchallenged_count += 1
        event = DefenseEvent(
            url=url,
            status=status_code,
            outcome="unchallenged",
            signal="none",
            protections=on_response,
            reason=_explain(status_code, "none", on_response, headers),
            headers=forensic_headers,
            body_snippet=snippet[:160],
        )
        if len(self.sample_unchallenged) < self._max_samples:
            self.sample_unchallenged.append(event)

    def total_scored(self) -> int:
        return self.caught_count + self.unchallenged_count

    def catch_rate_pct(self) -> float:
        total = self.total_scored()
        if not total:
            return 0.0
        return round(100.0 * self.caught_count / total, 1)

    def gap_rate_pct(self) -> float:
        total = self.total_scored()
        if not total:
            return 0.0
        return round(100.0 * self.unchallenged_count / total, 1)

    def posture_verdict(self) -> Tuple[str, str]:
        total = self.total_scored()
        if total == 0:
            return (
                "INCONCLUSIVE — not enough responses scored",
                "Run a longer scan so catch vs unchallenged rates are meaningful.",
            )
        catch = self.catch_rate_pct()
        if catch >= 70 and self.protections_seen:
            return (
                "STRONG CATCH RATE — protections are stopping most scanner traffic",
                f"{catch}% of scored requests showed a block, challenge, or rate-limit signal. "
                f"Still review the {self.unchallenged_count} unchallenged request(s) for gaps.",
            )
        if catch >= 30:
            return (
                "PARTIAL COVERAGE — some traffic is stopped, gaps remain",
                f"Only {catch}% of scored requests were challenged/blocked. "
                f"{self.unchallenged_count} completed without a detected bot wall — tighten rules before going public.",
            )
        if self.protections_seen:
            return (
                "WEAK CATCH RATE — protections detected but rarely triggered",
                f"Signals of {', '.join(sorted(self.protections_seen))} were seen, but only {catch}% of "
                f"requests were actually challenged/blocked. Treat unchallenged traffic as hardening work.",
            )
        return (
            "FEW PROTECTIONS OBSERVED — high risk if this host goes public",
            f"{self.unchallenged_count} request(s) completed without challenge signals and little/no "
            "bot-management fingerprint was detected. Add WAF/bot controls and CAPTCHA on sensitive forms.",
        )

    def to_dict(self) -> Dict[str, Any]:
        verdict_title, verdict_body = self.posture_verdict()
        journal = [e.journal_dict() for e in self.block_events[-30:]]
        forensic = [e.forensic_dict() for e in self.block_events]
        return {
            "start_url": self.start_url,
            "protections_detected": sorted(self.protections_seen),
            "security_headers_present": sorted(self.security_headers_present),
            "security_headers_missing": sorted(self.security_headers_missing),
            "caught_by_protection": self.caught_count,
            "completed_without_challenge": self.unchallenged_count,
            "catch_rate_percent": self.catch_rate_pct(),
            "gap_rate_percent": self.gap_rate_pct(),
            "rate_limit_events": self.rate_limit_count,
            "captcha_signals": self.captcha_signal_count,
            "bot_wall_signals": self.bot_wall_count,
            "signal_breakdown": dict(self.signal_counts),
            "block_status_counts": dict(self.block_status_counts),
            "protection_block_counts": dict(self.protection_block_counts),
            "fingerprint_notes": list(self.fingerprint_notes),
            "verdict_title": verdict_title,
            "verdict_body": verdict_body,
            "block_journal": journal,
            "block_events_forensic": forensic,
            "sample_caught": [
                {"url": e.url, "status": e.status, "signal": e.signal, "reason": e.reason} for e in self.sample_caught
            ],
            "sample_unchallenged": [
                {"url": e.url, "status": e.status} for e in self.sample_unchallenged
            ],
            "note": (
                "completed_without_challenge means no challenge/block signal was detected — "
                "not that a CAPTCHA or bot wall was cracked. "
                "block_events_forensic includes status, protections, headers, and body snippets."
            ),
        }

    def format_plain_report(self) -> str:
        data = self.to_dict()
        lines = [
            "=" * 70,
            "DEFENSE VERIFICATION REPORT",
            "=" * 70,
            "",
            f"Target:  {data['start_url']}",
            f"When:    {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "-" * 70,
            "PROTECTIONS DETECTED ON THIS SERVER",
            "-" * 70,
        ]
        if data["protections_detected"]:
            for name in data["protections_detected"]:
                count = data["protection_block_counts"].get(name, 0)
                suffix = f" ({count} block event(s))" if count else ""
                lines.append(f"  • {name.replace('_', ' ').title()}{suffix}")
        else:
            lines.append("  • None clearly identified from headers/body signals")
        lines.append("")
        lines.append("Security response headers present:")
        if data["security_headers_present"]:
            for h in data["security_headers_present"]:
                lines.append(f"  • {h}")
        else:
            lines.append("  • (none of the common set seen on first check)")
        if data["security_headers_missing"]:
            lines.append("Common security headers missing (from sample response):")
            for h in data["security_headers_missing"]:
                lines.append(f"  • {h}")
        lines.append("")
        lines.append("-" * 70)
        lines.append("DID YOUR DEFENSES CATCH THE SCANNER?")
        lines.append("-" * 70)
        lines.append(f"  Caught / challenged / blocked:     {data['caught_by_protection']}")
        lines.append(f"  Completed without challenge signal: {data['completed_without_challenge']}")
        lines.append(f"  Catch rate:                        {data['catch_rate_percent']}%")
        lines.append(f"  Gap rate (unchallenged):           {data['gap_rate_percent']}%")
        lines.append(f"  Rate-limit events (429 etc.):      {data['rate_limit_events']}")
        lines.append(f"  CAPTCHA-related signals:           {data['captcha_signals']}")
        lines.append(f"  Bot-wall / WAF-style signals:      {data['bot_wall_signals']}")
        lines.append("")
        if data["block_status_counts"]:
            lines.append("Block / challenge HTTP status codes:")
            for code, count in sorted(data["block_status_counts"].items(), key=lambda x: -int(x[1])):
                lines.append(f"  • HTTP {code}: {count}")
            lines.append("")
        lines.append(
            "  Important: “Completed without challenge” is a GAP to review — "
            "it does NOT mean a CAPTCHA or bot manager was bypassed or solved."
        )
        lines.append("")
        if data["signal_breakdown"]:
            lines.append("Why traffic was marked as caught:")
            for signal, count in sorted(data["signal_breakdown"].items(), key=lambda x: -x[1]):
                lines.append(f"  • {signal}: {count}")
            lines.append("")
        lines.append("-" * 70)
        lines.append("POSTURE VERDICT")
        lines.append("-" * 70)
        lines.append(f"  {data['verdict_title']}")
        lines.append("")
        lines.append(f"  {data['verdict_body']}")
        lines.append("")
        forensic = data.get("block_events_forensic") or []
        if forensic:
            lines.append("-" * 70)
            lines.append("FORENSIC BLOCK / CHALLENGE LOG (what was blocked and why)")
            lines.append("-" * 70)
            for item in forensic[:80]:
                lines.append(
                    f"  • [{item.get('time_utc')}] HTTP {item.get('status')} · "
                    f"{item.get('signal')} · {item.get('url')}"
                )
                if item.get("protections"):
                    lines.append(f"      Protections: {', '.join(item['protections'])}")
                if item.get("reason"):
                    lines.append(f"      Why: {item['reason']}")
                headers = item.get("headers") or {}
                if headers:
                    shown = ", ".join(f"{k}={v}" for k, v in list(headers.items())[:8])
                    lines.append(f"      Headers: {shown}")
                if item.get("body_snippet"):
                    lines.append(f"      Body: {item['body_snippet'][:200]}")
                lines.append("")
        elif data["sample_caught"]:
            lines.append("-" * 70)
            lines.append("SAMPLE URLS WHERE PROTECTION CAUGHT THE SCANNER")
            lines.append("-" * 70)
            for item in data["sample_caught"][:15]:
                lines.append(f"  • [{item['status']}] {item['signal']}: {item['url']}")
            lines.append("")
        if data["sample_unchallenged"]:
            lines.append("-" * 70)
            lines.append("SAMPLE URLS WITH NO CHALLENGE SIGNAL (REVIEW THESE GAPS)")
            lines.append("-" * 70)
            for item in data["sample_unchallenged"][:15]:
                lines.append(f"  • [{item['status']}] {item['url']}")
            lines.append("")
        lines.append("=" * 70)
        return "\n".join(lines)


async def probe_defense_fingerprint(client, start_url: str, tracker: DefenseTracker, output_callback=None):
    """One-shot probe of the home page / a few paths to fingerprint protections early."""
    tracker.start_url = start_url
    if output_callback:
        output_callback("Checking what protections this server appears to use…")
    parsed = urlparse(start_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    probes = [start_url, origin + "/", origin + "/robots.txt", origin + "/favicon.ico"]
    seen: Set[str] = set()
    for url in probes:
        if url in seen:
            continue
        seen.add(url)
        try:
            response = await client.get(url, timeout=10, follow_redirects=True)
            # Scoring is done by httpx response hooks; here we only enrich fingerprints from body.
            body = ""
            try:
                raw = response.content[:5000] if response.content else b""
                body = raw.decode("utf-8", errors="replace")
            except Exception:
                body = ""
            tracker.observe_headers(dict(response.headers), body)
        except Exception:
            tracker.error_count += 1
    if output_callback:
        if tracker.protections_seen:
            names = ", ".join(sorted(tracker.protections_seen))
            output_callback(f"Protections spotted so far: {names}")
        else:
            output_callback("No clear bot-management fingerprint yet — continuing scan measurement.")


def write_defense_reports(tracker: DefenseTracker, report_dir: str, base_name: str) -> Dict[str, str]:
    os.makedirs(report_dir, exist_ok=True)
    txt_path = os.path.join(report_dir, f"{base_name}_defense.txt")
    json_path = os.path.join(report_dir, f"{base_name}_defense.json")
    html_path = os.path.join(report_dir, f"{base_name}_defense.html")
    text = tracker.format_plain_report()
    data = tracker.to_dict()
    with open(txt_path, "w", encoding="utf-8") as handle:
        handle.write(text)
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
    html = _defense_html(data, text)
    with open(html_path, "w", encoding="utf-8") as handle:
        handle.write(html)
    return {"defense_txt": txt_path, "defense_json": json_path, "defense_html": html_path}


def _escape(text: str) -> str:
    return (
        str(text or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _defense_html(data: Dict[str, Any], plain: str) -> str:
    protections = "".join(
        f"<li>{_escape(p)} — {int((data.get('protection_block_counts') or {}).get(p, 0))} block(s)</li>"
        for p in (data.get("protections_detected") or ["(none clear)"])
    )
    status_rows = "".join(
        f"<tr><td>HTTP {_escape(code)}</td><td>{count}</td></tr>"
        for code, count in sorted((data.get("block_status_counts") or {}).items(), key=lambda x: -int(x[1]))
    ) or "<tr><td colspan='2'>None yet</td></tr>"

    forensic_cards = []
    for item in (data.get("block_events_forensic") or [])[:80]:
        headers = item.get("headers") or {}
        header_lis = "".join(f"<li><code>{_escape(k)}</code>: {_escape(v)}</li>" for k, v in list(headers.items())[:12])
        forensic_cards.append(
            f"""
            <article class="event">
              <div class="event-head">
                <span class="badge">{_escape(item.get('status'))}</span>
                <span class="badge signal">{_escape(item.get('signal'))}</span>
                <span class="muted">{_escape(item.get('time_utc'))}</span>
              </div>
              <div class="url">{_escape(item.get('url'))}</div>
              <p class="why">{_escape(item.get('reason'))}</p>
              <p class="muted">Protections: {_escape(', '.join(item.get('protections') or []) or '—')}</p>
              <details>
                <summary>Forensic headers / body</summary>
                <ul>{header_lis or '<li>(no interesting headers captured)</li>'}</ul>
                <pre>{_escape(item.get('body_snippet') or '(empty)')}</pre>
              </details>
            </article>
            """
        )

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Defense verification</title>
<style>
body{{font-family:Segoe UI,system-ui,sans-serif;margin:2rem;background:#0f1419;color:#e7ecf1;line-height:1.45}}
h1,h2{{color:#7dd3fc}} .card{{background:#1a2332;padding:1.2rem;border-radius:10px;margin:1rem 0}}
.stat{{font-size:1.6rem;font-weight:700}} .ok{{color:#4ade80}} .warn{{color:#fbbf24}} .bad{{color:#f87171}}
pre{{white-space:pre-wrap;background:#0b1016;padding:1rem;border-radius:8px;overflow:auto}}
table{{width:100%;border-collapse:collapse}} td,th{{border-bottom:1px solid #2a3648;padding:.45rem .3rem;text-align:left}}
.event{{border:1px solid #2a3648;border-radius:10px;padding:.85rem;margin:.7rem 0;background:#121a24}}
.event-head{{display:flex;gap:.5rem;flex-wrap:wrap;align-items:center;margin-bottom:.35rem}}
.badge{{background:#243246;padding:.15rem .5rem;border-radius:999px;font-size:.85rem}}
.badge.signal{{background:#3b1f2b;color:#fda4af}}
.url{{word-break:break-all;font-weight:600}} .why{{margin:.35rem 0}} .muted{{color:#9aa7b8}}
</style></head><body>
<h1>Defense verification</h1>
<p>Target: {_escape(data.get('start_url',''))}</p>
<div class="card"><h2>Verdict</h2>
<p class="stat">{_escape(data.get('verdict_title',''))}</p>
<p>{_escape(data.get('verdict_body',''))}</p></div>
<div class="card"><h2>Catch vs gaps</h2>
<p><span class="ok stat">{data.get('caught_by_protection',0)}</span> caught / challenged</p>
<p><span class="warn stat">{data.get('completed_without_challenge',0)}</span> completed without challenge signal (gaps)</p>
<p>Catch rate: {data.get('catch_rate_percent',0)}% · Gap rate: {data.get('gap_rate_percent',0)}%</p>
<p><em>{_escape(data.get('note',''))}</em></p></div>
<div class="card"><h2>Protections detected</h2><ul>{protections}</ul></div>
<div class="card"><h2>Block HTTP status codes</h2>
<table><thead><tr><th>Status</th><th>Count</th></tr></thead><tbody>{status_rows}</tbody></table>
</div>
<div class="card"><h2>Forensic block / challenge log</h2>
{''.join(forensic_cards) or '<p class="muted">No block events captured.</p>'}
</div>
<div class="card"><h2>Full plain-language report</h2><pre>{_escape(plain)}</pre></div>
</body></html>"""


def format_defense_for_ui(tracker: Optional[DefenseTracker]) -> str:
    if tracker is None:
        return "Defense verification was not run for this scan."
    return tracker.format_plain_report()
