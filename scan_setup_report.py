"""Plain-English + settings snapshot of what a scan was configured to do."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Tuple


def _on(flag: Any) -> bool:
    return bool(flag)


def _yes_no(flag: Any) -> str:
    return "Yes" if _on(flag) else "No"


def _workers_label(meta: dict) -> str:
    crawl = int(meta.get("crawl_concurrency") or 0)
    enum = int(meta.get("enum_concurrency") or 0)
    download = int(meta.get("download_concurrency") or 0)
    return f"{crawl} crawl · {enum} enum · {download} download"


def _wordlist_name(meta: dict) -> str:
    path = (meta.get("wordlist_file") or "").strip()
    if not path:
        return "(none)"
    return os.path.basename(path)


def build_scan_setup(meta: Dict[str, Any] | None) -> Dict[str, Any]:
    """Return narrative paragraph, action bullets, and snapshot rows for reports."""
    meta = dict(meta or {})

    download = _on(meta.get("download_files"))
    security = _on(meta.get("security_scan"))
    vuln = _on(meta.get("vuln_scan"))
    active = _on(meta.get("vuln_active_probe"))
    enum_only = _on(meta.get("enum_only"))
    use_wordlist = _on(meta.get("use_wordlist"))
    mutation = _on(meta.get("mutation_enum"))
    deep = _on(meta.get("deep_mirror")) or _on(meta.get("selenium_fallback"))
    stealth_on = _on(meta.get("evasion_enabled")) and (meta.get("evasion_level") or "off") != "off"
    auth_set = bool((meta.get("auth_username") or "").strip() or (meta.get("cookie_string") or "").strip())
    proxy_set = bool((meta.get("proxy_url") or "").strip())
    login_set = _on(meta.get("use_selenium_login")) and bool((meta.get("login_url") or "").strip())

    # ── Plain-English summary ────────────────────────────────────────────
    if enum_only:
        mode_words = (
            "This run focused on guessing hidden folders and files (directory brute force), "
            "with little or no full-site link crawling."
        )
    elif download:
        mode_words = (
            "This run walked the website, looked for hidden paths, and saved pages/files locally "
            "so you can browse an offline copy."
        )
    else:
        mode_words = (
            "This run walked the website and looked for hidden paths, but did not download a full "
            "offline mirror of the site."
        )

    discovery_bits = []
    if _on(meta.get("wayback_seeds")) or _on(meta.get("common_crawl_seeds")):
        discovery_bits.append("old archived URLs")
    if _on(meta.get("subdomain_enum")):
        discovery_bits.append("other hostnames (subdomains)")
    if _on(meta.get("js_bundle_analysis")):
        discovery_bits.append("routes inside JavaScript")
    if _on(meta.get("openapi_parse")):
        discovery_bits.append("API documentation")
    if _on(meta.get("api_recon")):
        discovery_bits.append("API recon (routes / docs / optional probes)")
    if _on(meta.get("form_discovery")):
        discovery_bits.append("HTML forms")
    discovery_clause = (
        f" It also pulled extra starting points from {', '.join(discovery_bits)}."
        if discovery_bits
        else ""
    )

    if security and active:
        security_words = (
            " Security checks were on, including active injection probes (authorized targets only)."
        )
    elif security:
        security_words = (
            " Security checks were on (headers, secrets, sensitive paths, and common vulnerability patterns)."
        )
    else:
        security_words = " Security vulnerability checks were turned off for this run."

    stealth_words = (
        f" Requests used the stealth layer (level: {meta.get('evasion_level', 'basic')}) "
        "to look more like a normal browser and slow down if blocked."
        if stealth_on
        else " Request stealth was off or set to off."
    )

    workers = _workers_label(meta)
    parallel_words = f" Work was spread across async workers: {workers}."

    narrative = (
        f"{mode_words}{discovery_clause}{security_words}{stealth_words}{parallel_words} "
        "Only use these results for systems you own or have clear permission to test."
    )

    # ── Action bullets (what we actually attempted) ───────────────────────
    actions: List[str] = []
    if not enum_only:
        actions.append("Opened pages and followed links to map the site.")
        if deep:
            actions.append("Used a real browser (Chrome) for some pages so JavaScript-heavy sites show more links.")
    if use_wordlist or mutation:
        parts = []
        if use_wordlist:
            parts.append(f"wordlist ({_wordlist_name(meta)})")
        if mutation:
            parts.append("mutation paths on top of the wordlist")
        actions.append("Tried common/hidden folder and file names using " + " and ".join(parts) + ".")
    if meta.get("enum_word_limit"):
        actions.append(f"Capped directory guessing at about {int(meta['enum_word_limit']):,} wordlist entries.")
    if download:
        actions.append("Saved discovered files locally (mirror).")
        if _on(meta.get("mirror_page_assets")):
            actions.append("Also saved page components (CSS, JS, images, fonts) for offline viewing.")
    elif _on(meta.get("skip_enum_download")):
        actions.append("Skipped saving files during brute force (faster guessing).")
    if _on(meta.get("ignore_robots")):
        actions.append("Did not stop just because robots.txt said to stay away.")
    if _on(meta.get("bypass_forbidden")):
        actions.append("Still examined pages that returned 401/403 (forbidden / login required).")
    if _on(meta.get("s3_enum")) or _on(meta.get("gcs_enum")):
        actions.append("Checked for possible public cloud storage buckets (S3 / GCS).")
    if _on(meta.get("vhost_enum")):
        actions.append("Tried virtual-host name guessing (Host header fuzzing).")
    if security:
        bits = ["weak security headers", "leaked secrets", "sensitive paths"]
        if vuln:
            bits.append("common vulnerability patterns (SQLi, XSS, and similar signals)")
        if active:
            bits.append("active GET injection probes")
        actions.append("Checked for " + ", ".join(bits) + ".")
    if _on(meta.get("defense_verify")):
        actions.append("Recorded whether site protections challenged or blocked the scanner.")
    if not actions:
        actions.append("Ran with the selected profile defaults.")

    # ── Settings snapshot rows (no secrets) ───────────────────────────────
    rows: List[Tuple[str, str]] = [
        ("Engagement profile", str(meta.get("profile") or "full")),
        ("Download / mirror site", _yes_no(download)),
        ("Directory scan only (skip crawl)", _yes_no(enum_only)),
        ("Restrict to same domain", _yes_no(meta.get("restrict_domain", True))),
        ("Ignore robots.txt", _yes_no(meta.get("ignore_robots"))),
        ("Probe 401/403 pages", _yes_no(meta.get("bypass_forbidden"))),
        ("Browser deep render (Chrome)", _yes_no(deep)),
        ("Brute-force depth", str(meta.get("max_depth", ""))),
        ("Link depth limit (0 = unlimited)", str(meta.get("link_depth_limit", 0))),
        ("Use wordlist", _yes_no(use_wordlist)),
        ("Wordlist file", _wordlist_name(meta)),
        ("Mutation scan", _yes_no(mutation)),
        ("Max mutation candidates", f"{int(meta.get('mutation_max_candidates') or 0):,}"),
        ("Max enum words (0 = full list)", str(meta.get("enum_word_limit", 0))),
        ("Enum extensions", str(meta.get("enum_extensions") or "(default)")),
        ("Download file extensions filter", str(meta.get("extensions") or "all types")),
        ("Flat enum (no deep recursion)", _yes_no(meta.get("enum_flat_scan"))),
        ("Skip download during brute force", _yes_no(meta.get("skip_enum_download"))),
        ("Wayback / Common Crawl seeds", _yes_no(_on(meta.get("wayback_seeds")) or _on(meta.get("common_crawl_seeds")))),
        ("Subdomain enumeration", _yes_no(meta.get("subdomain_enum"))),
        ("OpenAPI / JS / forms discovery", _yes_no(
            _on(meta.get("openapi_parse")) or _on(meta.get("js_bundle_analysis")) or _on(meta.get("form_discovery"))
        )),
        ("Security scanning", _yes_no(security)),
        ("Vulnerability pattern checks", _yes_no(vuln)),
        ("Active injection probes", _yes_no(active)),
        ("Secret / API key scan", _yes_no(meta.get("secret_scan"))),
        ("Live secret validation", _yes_no(meta.get("secret_validate_live"))),
        ("Header / CORS / param checks", _yes_no(
            _on(meta.get("header_audit")) or _on(meta.get("cors_check")) or _on(meta.get("param_discovery"))
        )),
        ("Request stealth", f"{'On' if stealth_on else 'Off'} ({meta.get('evasion_level', 'off')})"),
        ("Stealth browser look", str(meta.get("evasion_browser") or "chrome")),
        ("Defense verification", _yes_no(meta.get("defense_verify"))),
        ("Parallel workers", workers),
        ("Proxy configured", _yes_no(proxy_set)),
        ("HTTP auth / cookies set", _yes_no(auth_set)),
        ("Browser login before crawl", _yes_no(login_set)),
        ("Search conclusion report", _yes_no(meta.get("search_conclusion_report", True))),
        ("HTML / JSON / CSV / SQLite exports", _yes_no(
            _on(meta.get("html_report"))
            or _on(meta.get("json_report"))
            or _on(meta.get("csv_export"))
            or _on(meta.get("sqlite_export"))
        )),
    ]

    return {
        "narrative": narrative,
        "actions": actions,
        "rows": rows,
    }


def config_to_report_meta(config) -> Dict[str, Any]:
    """Safe subset of CrawlConfig for reports (no passwords)."""
    ext = getattr(config, "extensions", None)
    if isinstance(ext, (list, tuple)):
        ext_text = ",".join(str(x) for x in ext) if ext else ""
    else:
        ext_text = str(ext or "")

    return {
        "profile": getattr(config, "profile", "full"),
        "download_files": getattr(config, "download_files", False),
        "enum_only": getattr(config, "enum_only", False),
        "restrict_domain": getattr(config, "restrict_domain", True),
        "ignore_robots": getattr(config, "ignore_robots", True),
        "bypass_forbidden": getattr(config, "bypass_forbidden", True),
        "deep_mirror": getattr(config, "deep_mirror", False),
        "selenium_fallback": getattr(config, "selenium_fallback", False),
        "max_depth": getattr(config, "max_depth", 3),
        "link_depth_limit": getattr(config, "link_depth_limit", 0),
        "use_wordlist": getattr(config, "use_wordlist", True),
        "wordlist_file": getattr(config, "wordlist_file", ""),
        "mutation_enum": getattr(config, "mutation_enum", True),
        "mutation_max_candidates": getattr(config, "mutation_max_candidates", 0),
        "enum_word_limit": getattr(config, "enum_word_limit", 0),
        "enum_extensions": getattr(config, "enum_extensions", ""),
        "extensions": ext_text,
        "enum_flat_scan": getattr(config, "enum_flat_scan", False),
        "skip_enum_download": getattr(config, "skip_enum_download", False),
        "mirror_page_assets": getattr(config, "mirror_page_assets", True),
        "wayback_seeds": getattr(config, "wayback_seeds", False),
        "common_crawl_seeds": getattr(config, "common_crawl_seeds", False),
        "subdomain_enum": getattr(config, "subdomain_enum", False),
        "openapi_parse": getattr(config, "openapi_parse", False),
        "api_recon": getattr(config, "api_recon", False),
        "api_recon_active": getattr(config, "api_recon_active", False),
        "api_recon_graphql": getattr(config, "api_recon_graphql", False),
        "js_bundle_analysis": getattr(config, "js_bundle_analysis", False),
        "form_discovery": getattr(config, "form_discovery", False),
        "form_submit_probe": getattr(config, "form_submit_probe", False),
        "rss_feeds": getattr(config, "rss_feeds", False),
        "s3_enum": getattr(config, "s3_enum", False),
        "gcs_enum": getattr(config, "gcs_enum", False),
        "vhost_enum": getattr(config, "vhost_enum", False),
        "security_scan": getattr(config, "security_scan", True),
        "vuln_scan": getattr(config, "vuln_scan", True),
        "vuln_active_probe": getattr(config, "vuln_active_probe", False),
        "secret_scan": getattr(config, "secret_scan", True),
        "secret_validate_live": getattr(config, "secret_validate_live", False),
        "header_audit": getattr(config, "header_audit", True),
        "cors_check": getattr(config, "cors_check", True),
        "param_discovery": getattr(config, "param_discovery", True),
        "evasion_enabled": getattr(config, "evasion_enabled", True),
        "evasion_level": getattr(config, "evasion_level", "basic"),
        "evasion_browser": getattr(config, "evasion_browser", "chrome"),
        "defense_verify": getattr(config, "defense_verify", True),
        "crawl_concurrency": getattr(config, "crawl_concurrency", 4),
        "enum_concurrency": getattr(config, "enum_concurrency", 35),
        "download_concurrency": getattr(config, "download_concurrency", 6),
        "proxy_url": getattr(config, "proxy_url", ""),
        "auth_username": getattr(config, "auth_username", ""),
        "cookie_string": "set" if (getattr(config, "cookie_string", "") or "").strip() else "",
        "use_selenium_login": getattr(config, "use_selenium_login", False),
        "login_url": getattr(config, "login_url", ""),
        "search_conclusion_report": getattr(config, "search_conclusion_report", True),
        "html_report": getattr(config, "html_report", True),
        "json_report": getattr(config, "json_report", True),
        "csv_export": getattr(config, "csv_export", True),
        "sqlite_export": getattr(config, "sqlite_export", True),
        "output_file": getattr(config, "output_file_path", ""),
        "download_dir": getattr(config, "download_dir", ""),
    }
