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
from typing import Any, Dict, List, Optional, Set
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
    ("akamai", ("akamai", "akamai-origin-hop", "x-akamai")),
    ("imperva", ("imperva", "incapsula", "x-iinfo")),
    ("sucuri", ("sucuri", "x-sucuri")),
    ("aws_waf", ("x-amzn-waf", "awselb", "x-amz-cf")),
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


@dataclass
class DefenseEvent:
    url: str
    status: int
    outcome: str  # caught | unchallenged | error
    signal: str
    time: float = field(default_factory=time.time)


@dataclass
class DefenseTracker:
    """Tracks protection fingerprint and catch / unchallenged counts during a scan."""

    start_url: str = ""
    protections_seen: Set[str] = field(default_factory=set)
    security_headers_present: Set[str] = field(default_factory=set)
    security_headers_missing: Set[str] = field(default_factory=set)
    signal_counts: Counter = field(default_factory=Counter)
    caught_count: int = 0
    unchallenged_count: int = 0
    error_count: int = 0
    rate_limit_count: int = 0
    captcha_signal_count: int = 0
    bot_wall_count: int = 0
    sample_caught: List[DefenseEvent] = field(default_factory=list)
    sample_unchallenged: List[DefenseEvent] = field(default_factory=list)
    fingerprint_notes: List[str] = field(default_factory=list)
    _max_samples: int = 40

    def observe_headers(self, headers: Dict[str, str], body_preview: str = ""):
        combined = " ".join(
            f"{k}:{v}" for k, v in (headers or {}).items()
        ).lower() + " " + (body_preview or "").lower()[:6000]
        header_keys = {k.lower() for k in (headers or {})}

        for name, tokens in PROTECTION_SIGNATURES:
            if any(token in combined or token in header_keys for token in tokens):
                self.protections_seen.add(name)

        present = set()
        for h in SECURITY_HEADER_CHECKS:
            if h in header_keys:
                present.add(h)
        self.security_headers_present.update(present)
        missing = set(SECURITY_HEADER_CHECKS) - present
        # Only record missing from first substantial response if empty
        if not self.security_headers_missing and headers:
            self.security_headers_missing = missing

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

        # Enrich preview with header tokens for detect_challenge
        bits = [body_preview]
        server = (headers.get("server") or "").lower()
        if "cloudflare" in server:
            bits.append("cloudflare")
        if headers.get("cf-ray") or headers.get("cf-mitigated"):
            bits.append("cf-challenge")
        if headers.get("cf-mitigated"):
            bits.append("challenge-platform")
        preview = " ".join(bits)

        signal = detect_challenge(status_code, preview)
        # Extra CAPTCHA / turnstile body markers
        preview_l = preview.lower()
        if not signal:
            for marker, label in (
                ("turnstile", "cloudflare_turnstile"),
                ("hcaptcha", "hcaptcha"),
                ("recaptcha", "recaptcha"),
                ("g-recaptcha", "recaptcha"),
            ):
                if marker in preview_l:
                    signal = label
                    break

        if signal:
            self.caught_count += 1
            self.signal_counts[signal] += 1
            if signal == "rate_limit" or status_code == 429:
                self.rate_limit_count += 1
            if any(x in signal for x in ("captcha", "recaptcha", "hcaptcha", "turnstile")):
                self.captcha_signal_count += 1
            if any(x in signal for x in ("cloudflare", "challenge", "datadome", "akamai", "bot", "blocked")):
                self.bot_wall_count += 1
            event = DefenseEvent(url=url, status=status_code, outcome="caught", signal=signal)
            if len(self.sample_caught) < self._max_samples:
                self.sample_caught.append(event)
            return

        if status_code >= 500:
            self.error_count += 1
            return

        # Completed without a detected challenge/block signal
        self.unchallenged_count += 1
        event = DefenseEvent(url=url, status=status_code, outcome="unchallenged", signal="none")
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

    def posture_verdict(self) -> tuple[str, str]:
        """Plain-language verdict for lab hardening."""
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
            "fingerprint_notes": list(self.fingerprint_notes),
            "verdict_title": verdict_title,
            "verdict_body": verdict_body,
            "sample_caught": [
                {"url": e.url, "status": e.status, "signal": e.signal} for e in self.sample_caught
            ],
            "sample_unchallenged": [
                {"url": e.url, "status": e.status} for e in self.sample_unchallenged
            ],
            "note": (
                "completed_without_challenge means no challenge/block signal was detected — "
                "not that a CAPTCHA or bot wall was cracked."
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
                lines.append(f"  • {name.replace('_', ' ').title()}")
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
        if data["sample_caught"]:
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
    seen = set()
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


def _defense_html(data: Dict[str, Any], plain: str) -> str:
    protections = "".join(f"<li>{p}</li>" for p in data.get("protections_detected") or ["(none clear)"])
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Defense verification</title>
<style>
body{{font-family:Segoe UI,system-ui,sans-serif;margin:2rem;background:#0f1419;color:#e7ecf1}}
h1,h2{{color:#7dd3fc}} .card{{background:#1a2332;padding:1.2rem;border-radius:10px;margin:1rem 0}}
.stat{{font-size:1.6rem;font-weight:700}} .ok{{color:#4ade80}} .warn{{color:#fbbf24}} .bad{{color:#f87171}}
pre{{white-space:pre-wrap;background:#0b1016;padding:1rem;border-radius:8px}}
</style></head><body>
<h1>Defense verification</h1>
<p>Target: {data.get('start_url','')}</p>
<div class="card"><h2>Verdict</h2>
<p class="stat">{data.get('verdict_title','')}</p>
<p>{data.get('verdict_body','')}</p></div>
<div class="card"><h2>Catch vs gaps</h2>
<p><span class="ok stat">{data.get('caught_by_protection',0)}</span> caught / challenged</p>
<p><span class="warn stat">{data.get('completed_without_challenge',0)}</span> completed without challenge signal (gaps)</p>
<p>Catch rate: {data.get('catch_rate_percent',0)}% · Gap rate: {data.get('gap_rate_percent',0)}%</p>
<p><em>{data.get('note','')}</em></p></div>
<div class="card"><h2>Protections detected</h2><ul>{protections}</ul></div>
<div class="card"><h2>Full plain-language report</h2><pre>{plain.replace('<','&lt;')}</pre></div>
</body></html>"""


def format_defense_for_ui(tracker: Optional[DefenseTracker]) -> str:
    if tracker is None:
        return "Defense verification was not run for this scan."
    return tracker.format_plain_report()
