"""Detailed multi-part search report: executive summary, feature chapters, appendix."""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, Optional, Sequence

from crawl_stats import CrawlStats
from finding_explain import format_finding_group_lines, group_findings_for_report, summarize_finding_noise
from scan_setup_report import build_scan_setup
from user_output import format_duration_friendly


def _format_bytes(num: int) -> str:
    if num < 1024:
        return f"{num} bytes"
    if num < 1024 * 1024:
        return f"{num / 1024:.1f} KB"
    return f"{num / (1024 * 1024):.1f} MB"


def _format_duration(seconds: float) -> str:
    return format_duration_friendly(seconds) if seconds < 3600 * 48 else (
        f"{int(seconds) // 3600}h {(int(seconds) % 3600) // 60:02d}m"
    )


def _hrule(title: str = "", char: str = "-") -> List[str]:
    if title:
        return ["", char * 70, title, char * 70]
    return ["", char * 70]


def _list_urls(
    urls: Sequence[str],
    *,
    limit: int,
    indent: str = "  • ",
    empty: str = "  (none in this run)",
) -> List[str]:
    if not urls:
        return [empty]
    lines = [f"{indent}{u}" for u in urls[:limit]]
    if len(urls) > limit:
        lines.append(f"{indent}… and {len(urls) - limit:,} more (see appendix / found_urls.txt)")
    return lines


def _counter_lines(counter: Counter, *, indent: str = "  • ", limit: int = 20) -> List[str]:
    if not counter:
        return [f"{indent}(none recorded)"]
    lines = []
    for key, count in counter.most_common(limit):
        lines.append(f"{indent}{key}: {count:,}")
    if len(counter) > limit:
        lines.append(f"{indent}… {len(counter) - limit} more status codes")
    return lines


def _takeaways(stats: CrawlStats, finding_groups: List[dict], defense: Optional[dict]) -> List[str]:
    items: List[str] = []
    try:
        from report_status import scan_status_from_stats

        status = scan_status_from_stats(stats)
        if status.get("scan_status") == "partial":
            items.append(
                "Report exported mid-scan — treat risk conclusions as provisional until the crawl/enum finish."
            )
        if status.get("directory_enum_message") and not status.get("directory_enum_started"):
            items.append(str(status["directory_enum_message"]))
    except Exception:
        pass
    high = sum(
        1
        for g in finding_groups
        if g.get("severity") in ("critical", "high")
        and str(g.get("assessment_state") or "") == "Confirmed vulnerability"
    )
    if high:
        items.append(f"{high} confirmed high/critical issue type(s) need priority review.")
    if stats.enum_hit_urls:
        items.append(f"{len(stats.enum_hit_urls)} hidden path(s) discovered — verify they are intentional.")
    if stats.sensitive_urls:
        items.append(f"{len(stats.sensitive_urls)} sensitive-looking path(s) flagged (e.g. backups, .env, admin).")
    if stats.s3_buckets or stats.gcs_buckets:
        items.append(
            f"Possible cloud storage exposure: {len(stats.s3_buckets)} S3 + {len(stats.gcs_buckets)} GCS hit(s)."
        )
    if stats.subdomain_urls:
        items.append(f"{len(stats.subdomain_urls)} subdomain(s) responded — expand scope review if needed.")
    if defense and defense.get("gap_rate_percent", 0) > 50:
        items.append("Bot/WAF catch rate looks low — many requests completed without a challenge signal.")
    if stats.broken_links:
        summary = CrawlStats.summarize_broken_links(stats.broken_links)
        items.append(
            f"{summary.get('unique_urls', 0)} unique broken/denied URL(s) "
            f"({summary.get('unique_404', 0)}×404, "
            f"{summary.get('unique_access_denied', 0)}×access-denied, "
            f"{summary.get('unique_fetch_errors', 0)}×fetch-error; "
            f"{summary.get('rows_total', 0)} raw row(s))."
        )
    if not items:
        items.append("No urgent standout items; review the chapters below for coverage details.")
    return items[:8]


def build_report_model(
    stats: CrawlStats,
    start_url: str,
    *,
    config_meta: Optional[Dict[str, Any]] = None,
    verdict_title: str = "",
    verdict_body: str = "",
) -> Dict[str, Any]:
    """Structured model used by text + HTML renderers."""
    snap = stats.snapshot()
    meta = dict(config_meta or {})
    scan_setup = build_scan_setup(meta)
    finding_groups = group_findings_for_report(stats.findings)
    severity_counts = Counter(f.get("severity", "info") for f in stats.findings)
    category_counts = Counter(f.get("category", "other") for f in stats.findings)
    defense = stats.defense_tracker.to_dict() if stats.defense_tracker else None
    try:
        from report_status import scan_status_from_stats

        scan_status_meta = scan_status_from_stats(stats)
    except Exception:
        scan_status_meta = {}

    # Dedupe forms/parameters lightly for display
    form_rows = []
    seen_forms = set()
    for form in stats.forms:
        fields = form.get("fields") or form.get("inputs") or []
        key = (form.get("action"), form.get("method"), tuple(fields)[:8])
        if key in seen_forms:
            continue
        seen_forms.add(key)
        form_rows.append(form)
        if len(form_rows) >= 80:
            break

    param_rows = []
    seen_params = set()
    for param in stats.parameters:
        key = (param.get("url"), param.get("name"), param.get("source"))
        if key in seen_params:
            continue
        seen_params.add(key)
        param_rows.append(param)
        if len(param_rows) >= 120:
            break

    return {
        "start_url": start_url,
        "snapshot": snap,
        "scan_setup": scan_setup,
        "verdict_title": verdict_title,
        "verdict_body": verdict_body,
        "finding_groups": finding_groups,
        "severity_counts": dict(severity_counts),
        "category_counts": dict(category_counts),
        "defense": defense,
        "scan_status_meta": scan_status_meta,
        "takeaways": _takeaways(stats, finding_groups, defense),
        "key_findings_lines": [
            line
            for group in finding_groups[:25]
            for line in format_finding_group_lines(group, max_urls=25)
        ],
        "noise_note": summarize_finding_noise(stats.findings),
        "form_rows": form_rows,
        "param_rows": param_rows,
        "tech_list": list(stats.technologies.most_common(25)),
        "crawl_status": dict(stats.status_codes),
        "enum_status": dict(stats.enum_status_codes),
        "enum_hits": list(stats.enum_hit_urls),
        "sensitive": list(stats.sensitive_urls),
        "broken": list(stats.broken_links),
        "broken_summary": CrawlStats.summarize_broken_links(stats.broken_links),
        "route_templates": list(getattr(stats, "route_templates", []) or []),
        "request_ledger_count": len(getattr(stats, "request_ledger", []) or []),
        "historical": list(stats.historical_seed_urls),
        "subdomains": list(stats.subdomain_urls),
        "js_routes": list(stats.js_route_urls),
        "openapi_docs": list(stats.openapi_doc_urls),
        "openapi_endpoints": list(stats.openapi_endpoints),
        "api_endpoints": list(getattr(stats, "api_endpoints", []) or []),
        "api_docs": list(getattr(stats, "api_docs", []) or []),
        "api_graphql_operations": list(getattr(stats, "api_graphql_operations", []) or []),
        "rss": list(stats.rss_feed_urls),
        "s3": list(stats.s3_buckets),
        "gcs": list(stats.gcs_buckets),
        "vhosts": list(stats.vhost_hits),
        "login_surfaces": list(stats.login_surfaces),
        "websockets": list(stats.websocket_urls),
        "sourcemaps": list(stats.sourcemap_urls),
        "cookies": list(stats.cookie_inventory),
        "emails": list(stats.emails),
        "phones": list(stats.phones),
        "internal_hosts": list(stats.internal_hosts),
        "third_party": list(stats.third_party_scripts),
        "link_rels": list(stats.link_rels),
        "security_headers": dict(stats.security_headers_by_host),
        "comments": list(stats.interesting_comments),
        "dom_sinks": list(stats.dom_sinks),
        "cloud_urls": list(stats.cloud_service_urls),
        "sitemap_docs": list(stats.sitemap_doc_urls),
        "sitemap_urls": list(stats.sitemap_page_urls),
        "tls_sans": list(stats.tls_sans),
        "well_known": list(stats.well_known_hits),
        "file_metadata": list(stats.file_metadata),
        "discovered_sample": sorted(list(stats.discovered_urls))[:150],
        "discovered_total": len(stats.discovered_urls),
        "findings": list(stats.findings),
        "bytes_downloaded": snap.get("bytes_downloaded", 0),
        "elapsed": snap.get("elapsed_seconds", 0),
    }


def render_detailed_text(model: Dict[str, Any]) -> str:
    snap = model["snapshot"]
    lines: List[str] = []

    lines += ["=" * 70, "SECURITY ASSESSMENT REPORT — DETAILED", "=" * 70]
    lines.append("Document classification: Confidential — authorized testing only")
    lines.append(f"Target / in-scope URL:  {model['start_url']}")
    lines.append(f"Assessment duration:    {_format_duration(model['elapsed'])}")
    lines.append(f"Engagement profile:     {model['scan_setup']['rows'][0][1] if model['scan_setup']['rows'] else 'full'}")

    # ── PART A ───────────────────────────────────────────────────────────
    lines += _hrule("PART A — EXECUTIVE SUMMARY", "=")
    lines.append(f"  Overall risk posture: {model['verdict_title']}")
    lines.append(f"  {model['verdict_body']}")
    status_meta = model.get("scan_status_meta") or {}
    if status_meta.get("scan_status"):
        lines.append(
            f"  Report status: {status_meta.get('scan_status')} "
            f"(phase={status_meta.get('phase')}, "
            f"completion≈{status_meta.get('completion_percent')}%)"
        )
    lines.append("")
    lines.append("  Snapshot numbers:")
    lines.append(f"  • Pages crawled:          {snap.get('pages_crawled', 0):,}")
    lines.append(f"  • URLs discovered:        {model['discovered_total']:,}")
    if status_meta.get("directory_enum_message") and not status_meta.get("directory_enum_started"):
        lines.append(f"  • Hidden paths:           {status_meta['directory_enum_message']}")
    else:
        lines.append(f"  • Hidden paths found:     {len(model['enum_hits']):,}")
    lines.append(f"  • Security issue types:   {len(model['finding_groups']):,}")
    lines.append(f"  • Unique findings:        {len(model['findings']):,}")
    lines.append(f"  • Sensitive paths:        {len(model['sensitive']):,}")
    lines.append(f"  • Subdomains found:       {len(model['subdomains']):,}")
    lines.append(f"  • Cloud bucket hits:      {len(model['s3']) + len(model['gcs']):,}")
    lines.append(
        f"  • Broken links (unique):  "
        f"{(model.get('broken_summary') or {}).get('unique_urls', len(model['broken'])):,}"
        f"  (raw rows {len(model['broken']):,})"
    )
    lines.append(f"  • Data downloaded:        {_format_bytes(int(model.get('bytes_downloaded') or 0))}")
    lines.append(f"  • Note: {model['noise_note']}")
    lines.append("")
    lines.append("  Top takeaways:")
    for item in model["takeaways"]:
        lines.append(f"  • {item}")
    lines.append("")
    lines.append("  Key findings (with exact paths):")
    if model.get("key_findings_lines"):
        for line in model["key_findings_lines"]:
            if line.startswith("  "):
                lines.append(f"  {line}")
            else:
                lines.append(f"  • {line}")
    else:
        lines.append("  • (none)")

    # ── PART B ───────────────────────────────────────────────────────────
    lines += _hrule("PART B — DETAILED RESULTS BY AREA", "=")

    lines += _hrule("B1. Crawl & site map")
    lines.append(
        f"  Crawled {snap.get('pages_crawled', 0):,} page(s); "
        f"{snap.get('links_found', 0):,} link(s) observed; "
        f"{model['discovered_total']:,} unique URL(s) in the discovery set."
    )
    lines.append("  HTTP status codes (crawl):")
    lines.extend(_counter_lines(Counter(model["crawl_status"])))
    lines.append("  Sample discovered URLs:")
    lines.extend(_list_urls(model["discovered_sample"], limit=25))

    lines += _hrule("B2. Hidden paths (directory brute force)")
    tested = snap.get("enum_words_tested", 0)
    total = snap.get("enum_words_total", 0)
    if status_meta.get("directory_enum_message") and not status_meta.get("directory_enum_started"):
        lines.append(f"  {status_meta['directory_enum_message']}")
        lines.append("  Do not interpret zero hits as “0 hidden paths found” — enumeration has not run yet.")
    elif total:
        pct = min(100, int(tested * 100 / total)) if total else 0
        lines.append(f"  Wordlist progress: {tested:,} / {total:,} ({pct}%).")
        lines.append(f"  Hits: {len(model['enum_hits']):,}")
    else:
        lines.append("  Wordlist progress: not started or not applicable.")
        lines.append(f"  Hits: {len(model['enum_hits']):,}")
    lines.append("  Enum HTTP status codes:")
    lines.extend(_counter_lines(Counter(model["enum_status"])))
    lines.append("  Hidden paths found:")
    lines.extend(_list_urls(model["enum_hits"], limit=40))

    lines += _hrule("B3. Discovery sources")
    lines.append(f"  Historical seeds (Wayback / Common Crawl): {len(model['historical']):,}")
    lines.extend(_list_urls(model["historical"], limit=20))
    lines.append(f"  Subdomains: {len(model['subdomains']):,}")
    lines.extend(_list_urls(model["subdomains"], limit=30))
    lines.append(f"  JavaScript routes: {len(model['js_routes']):,}")
    lines.extend(_list_urls(model["js_routes"], limit=25))
    lines.append(f"  OpenAPI / Swagger docs: {len(model['openapi_docs']):,}")
    lines.extend(_list_urls(model["openapi_docs"], limit=15))
    lines.append(f"  OpenAPI endpoints parsed: {len(model['openapi_endpoints']):,}")
    lines.extend(_list_urls(model["openapi_endpoints"], limit=25))
    lines.append(f"  RSS / Atom feeds: {len(model['rss']):,}")
    lines.extend(_list_urls(model["rss"], limit=15))
    lines.append(f"  HTML forms discovered: {len(model['form_rows']):,}")
    if model["form_rows"]:
        for form in model["form_rows"][:15]:
            action = form.get("action") or "(same page)"
            method = (form.get("method") or "GET").upper()
            fields = form.get("fields") or form.get("inputs") or []
            inputs = ", ".join(str(x) for x in fields[:8])
            lines.append(f"  • [{method}] {action}  fields: {inputs or '(none named)'}")
        if len(model["form_rows"]) > 15:
            lines.append(f"  • … and {len(model['form_rows']) - 15} more forms (see appendix)")
    else:
        lines.append("  (none in this run)")
    lines.append(f"  Parameters discovered: {len(model['param_rows']):,}")
    if model["param_rows"]:
        for param in model["param_rows"][:20]:
            lines.append(
                f"  • {param.get('name', '?')} @ {param.get('url', '')} "
                f"({param.get('source', 'param')})"
            )
        if len(model["param_rows"]) > 20:
            lines.append(f"  • … and {len(model['param_rows']) - 20} more (see appendix)")
    else:
        lines.append("  (none in this run)")

    lines += _hrule("B4. Cloud storage & virtual hosts")
    lines.append(f"  S3 bucket hits: {len(model['s3']):,}")
    lines.extend(_list_urls(model["s3"], limit=30))
    lines.append(f"  GCS bucket hits: {len(model['gcs']):,}")
    lines.extend(_list_urls(model["gcs"], limit=30))
    lines.append(f"  Vhost hits: {len(model['vhosts']):,}")
    lines.extend(_list_urls(model["vhosts"], limit=30))

    lines += _hrule("B5. Sensitive paths")
    lines.extend(_list_urls(model["sensitive"], limit=40, empty="  (none flagged)"))

    lines += _hrule("B5b. Auth surfaces, cookies, WebSockets, source maps")
    lines.append(f"  Login / auth surfaces: {len(model.get('login_surfaces') or []):,}")
    lines.extend(_list_urls(model.get("login_surfaces") or [], limit=30, empty="  (none)"))
    cookies = model.get("cookies") or []
    lines.append(f"  Cookies inventoried: {len(cookies):,}")
    if cookies:
        for cookie in cookies[:40]:
            impact = cookie.get("impact") or ""
            role = cookie.get("role") or ""
            extra = ""
            if role or impact:
                extra = f" · role={role or '?'} · impact={impact or '?'}"
            lines.append(
                f"  • {cookie.get('name', '?')} — flags: {cookie.get('flags', '(none)')}{extra}"
            )
            summary = (cookie.get("summary") or "").strip()
            if summary:
                lines.append(f"      {summary}")
            if cookie.get("value_masked"):
                lines.append(f"      value: {cookie.get('value_masked')}")
        if len(cookies) > 40:
            lines.append(f"  • … and {len(cookies) - 40} more")
        stealable = sum(1 for c in cookies if c.get("impact") == "stealable_credential")
        mitigated = sum(1 for c in cookies if c.get("impact") == "mitigated_credential")
        none = sum(1 for c in cookies if c.get("impact") == "no_credential_impact")
        lines.append(
            f"  Cookie impact summary: stealable={stealable}, mitigated={mitigated}, "
            f"no_credential_impact={none}, other={len(cookies) - stealable - mitigated - none}"
        )
    else:
        lines.append("  (none observed)")
    lines.append(f"  WebSocket endpoints: {len(model.get('websockets') or []):,}")
    lines.extend(_list_urls(model.get("websockets") or [], limit=30, empty="  (none)"))
    lines.append(f"  Source map URLs: {len(model.get('sourcemaps') or []):,}")
    lines.extend(_list_urls(model.get("sourcemaps") or [], limit=30, empty="  (none)"))

    lines += _hrule("B5c. Extended recon inventory")
    lines.append(f"  Emails: {len(model.get('emails') or []):,}")
    lines.extend(_list_urls(model.get("emails") or [], limit=40, empty="  (none)"))
    lines.append(f"  Phones: {len(model.get('phones') or []):,}")
    lines.extend(_list_urls(model.get("phones") or [], limit=20, empty="  (none)"))
    lines.append(f"  Internal / staging hosts: {len(model.get('internal_hosts') or []):,}")
    lines.extend(_list_urls(model.get("internal_hosts") or [], limit=40, empty="  (none)"))
    lines.append(f"  TLS certificate names (SAN/CN): {len(model.get('tls_sans') or []):,}")
    lines.extend(_list_urls(model.get("tls_sans") or [], limit=40, empty="  (none)"))
    lines.append(f"  Sitemap docs: {len(model.get('sitemap_docs') or []):,}")
    lines.extend(_list_urls(model.get("sitemap_docs") or [], limit=10, empty="  (none)"))
    lines.append(f"  Sitemap page URLs: {len(model.get('sitemap_urls') or []):,}")
    lines.extend(_list_urls(model.get("sitemap_urls") or [], limit=40, empty="  (none)"))
    lines.append(f"  Well-known endpoints: {len(model.get('well_known') or []):,}")
    for wk in (model.get("well_known") or [])[:20]:
        lines.append(
            f"  • {wk.get('url', '')} — HTTP {wk.get('status', '?')} — {wk.get('evidence', '')}"
        )
    if not (model.get("well_known") or []):
        lines.append("  (none)")
    lines.append(f"  Cloud service URLs: {len(model.get('cloud_urls') or []):,}")
    lines.extend(_list_urls(model.get("cloud_urls") or [], limit=30, empty="  (none)"))
    lines.append(f"  Third-party scripts: {len(model.get('third_party') or []):,}")
    for row in (model.get("third_party") or [])[:30]:
        lines.append(f"  • {row.get('vendor', '?')} — {row.get('host', '')}")
    if not (model.get("third_party") or []):
        lines.append("  (none)")
    lines.append(f"  Link rel / Link headers: {len(model.get('link_rels') or []):,}")
    for row in (model.get("link_rels") or [])[:25]:
        lines.append(f"  • [{row.get('rel', '?')}] {row.get('url', '')}")
    if not (model.get("link_rels") or []):
        lines.append("  (none)")
    hdr_map = model.get("security_headers") or {}
    lines.append(f"  Security headers inventoried for {len(hdr_map):,} host(s)")
    for host, hdrs in list(hdr_map.items())[:5]:
        lines.append(f"  • {host}: {', '.join(sorted(hdrs.keys())[:12])}")
    lines.append(f"  Interesting comments: {len(model.get('comments') or []):,}")
    for comment in (model.get("comments") or [])[:15]:
        lines.append(f"  • {comment}")
    if not (model.get("comments") or []):
        lines.append("  (none)")
    lines.append(f"  DOM sinks (near user-input tokens): {len(model.get('dom_sinks') or []):,}")
    for sink in (model.get("dom_sinks") or [])[:15]:
        lines.append(f"  • {sink}")
    if not (model.get("dom_sinks") or []):
        lines.append("  (none)")
    lines.append(f"  File metadata (PDF/Office/images): {len(model.get('file_metadata') or []):,}")
    for row in (model.get("file_metadata") or [])[:25]:
        interesting = row.get("interesting") or {}
        preview = ", ".join(f"{k}={v}" for k, v in list(interesting.items())[:5]) or "(technical fields only)"
        lines.append(
            f"  • [{row.get('kind', '?')}/{row.get('engine', '?')}] {row.get('url', '')} — {preview}"
        )
    if not (model.get("file_metadata") or []):
        lines.append("  (none — enable downloads or crawl document/image URLs)")

    lines += _hrule("B6. Security findings (by issue type)")
    sev = model["severity_counts"]
    lines.append(
        f"  By severity: critical={sev.get('critical', 0)}, high={sev.get('high', 0)}, "
        f"medium={sev.get('medium', 0)}, low={sev.get('low', 0)}, info={sev.get('info', 0)}"
    )
    if not model["finding_groups"]:
        lines.append("  (no security findings recorded)")
    for index, group in enumerate(model["finding_groups"], 1):
        lines.append("")
        lines.append(f"  {index}. [{group['severity'].upper()}] {group['title']}")
        for line in format_finding_group_lines(group, max_urls=40)[1:]:
            lines.append(f"   {line}")
        lines.append(f"     What we found: {group['what']}")
        lines.append(f"     How an attacker could use this: {group['attacker']}")
        lines.append(f"     How to fix it: {group['fix']}")
        lines.append(f"     Seen {group['count']}× across {group['unique_hosts']} host(s).")

    lines += _hrule("B7. Defense verification")
    defense = model.get("defense")
    if defense:
        lines.append(f"  Verdict: {defense.get('verdict_title', '')}")
        lines.append(f"  {defense.get('verdict_body', '')}")
        lines.append(
            f"  Caught: {defense.get('caught_by_protection', 0)} · "
            f"Unchallenged gaps: {defense.get('completed_without_challenge', 0)} · "
            f"Catch rate: {defense.get('catch_rate_percent', 0)}%"
        )
        protections = defense.get("protections_seen") or defense.get("protections") or []
        if protections:
            if isinstance(protections, dict):
                protections = list(protections.keys())
            lines.append("  Protections sensed: " + ", ".join(str(p) for p in protections))
        missing = defense.get("security_headers_missing") or []
        if missing:
            lines.append("  Missing security headers (fingerprint): " + ", ".join(str(h) for h in missing))
    else:
        lines.append("  (defense verification not enabled or no data)")

    lines += _hrule("B8. Technology inventory")
    if model["tech_list"]:
        for name, count in model["tech_list"]:
            lines.append(f"  • {name} — {count} page(s)")
    else:
        lines.append("  (none detected)")

    lines += _hrule("B9. Broken links (sample)")
    if model["broken"]:
        for item in model["broken"][:30]:
            lines.append(f"  • {item.get('url', '')} — status {item.get('status', '?')}")
        if len(model["broken"]) > 30:
            lines.append(f"  • … and {len(model['broken']) - 30} more (see appendix)")
    else:
        lines.append("  (none in sample)")

    lines += _hrule("B10. What this scan was configured to do")
    lines.append(f"  {model['scan_setup']['narrative']}")
    lines.append("  Methods:")
    for action in model["scan_setup"]["actions"]:
        lines.append(f"  • {action}")
    lines.append("  Key settings:")
    for label, value in model["scan_setup"]["rows"][:18]:
        lines.append(f"  • {label}: {value}")
    if len(model["scan_setup"]["rows"]) > 18:
        lines.append("  • … full settings table is in the HTML report / appendix below")

    # ── PART C ───────────────────────────────────────────────────────────
    lines += _hrule("PART C — TECHNICAL APPENDIX", "=")

    lines += _hrule("C1. Full hidden-path list")
    lines.extend(_list_urls(model["enum_hits"], limit=250, empty="  (none)"))

    lines += _hrule("C2. Full sensitive-path list")
    lines.extend(_list_urls(model["sensitive"], limit=200, empty="  (none)"))

    lines += _hrule("C3. Full discovery lists")
    lines.append("  Historical seeds:")
    lines.extend(_list_urls(model["historical"], limit=100))
    lines.append("  Subdomains:")
    lines.extend(_list_urls(model["subdomains"], limit=200))
    lines.append("  JS routes:")
    lines.extend(_list_urls(model["js_routes"], limit=150))
    lines.append("  OpenAPI endpoints:")
    lines.extend(_list_urls(model["openapi_endpoints"], limit=150))
    lines.append("  S3 / GCS / Vhosts:")
    lines.extend(_list_urls(model["s3"] + model["gcs"] + model["vhosts"], limit=200))

    lines += _hrule("C4. Forms & parameters (extended)")
    for form in model["form_rows"][:60]:
        action = form.get("action") or "(same page)"
        method = (form.get("method") or "GET").upper()
        fields = form.get("fields") or form.get("inputs") or []
        inputs = ", ".join(str(x) for x in fields[:20])
        lines.append(f"  • [{method}] {action} :: {inputs}")
    if not model["form_rows"]:
        lines.append("  (no forms)")
    for param in model["param_rows"][:80]:
        lines.append(f"  • param {param.get('name', '?')} @ {param.get('url', '')}")
    if not model["param_rows"]:
        lines.append("  (no parameters)")

    lines += _hrule("C5. Raw finding table")
    if not model["findings"]:
        lines.append("  (none)")
    for item in model["findings"][:300]:
        lines.append(
            f"  • [{item.get('severity', 'info')}] {item.get('category', '')} | "
            f"{item.get('url', '')} | {item.get('detail', '')}"
        )
    if len(model["findings"]) > 300:
        lines.append(f"  • … and {len(model['findings']) - 300} more in JSON/SQLite exports")

    lines += _hrule("C6. Status-code tables")
    lines.append("  Crawl:")
    lines.extend(_counter_lines(Counter(model["crawl_status"]), limit=40))
    lines.append("  Enum:")
    lines.extend(_counter_lines(Counter(model["enum_status"]), limit=40))

    lines += _hrule("C7. Full settings snapshot")
    for label, value in model["scan_setup"]["rows"]:
        lines.append(f"  • {label}: {value}")

    lines += _hrule("C8. Limitations")
    lines.append("  • Automated assessment aid — not a full manual penetration test.")
    lines.append("  • False positives/negatives possible; verify before production changes.")
    lines.append("  • Stopping a large directory scan early reduces hidden-path coverage.")
    lines.append("  • Active probes (if enabled) must only run on authorized targets.")
    lines.append("")
    lines.append("=" * 70)
    lines.append("End of detailed security assessment report")
    lines.append("=" * 70)
    return "\n".join(lines)
