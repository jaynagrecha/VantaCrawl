"""Web scan settings catalog — mirrors desktop CrawlConfig + mode presets."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Repo root on sys.path so gui_presets / crawl_config import
ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from crawl_config import CrawlConfig  # noqa: E402
from evasion_layer import BROWSER_PROFILES, LEVELS  # noqa: E402
from gui_presets import (  # noqa: E402
    MODE_LABELS,
    MODE_PRESETS,
    MODES,
    SPEED_PROFILES,
    concurrency_for_speed,
)

# Keys the web UI can edit (identity paths filled by worker)
EDITABLE_DEFAULTS_SKIP = {
    "start_url",
    "wordlist_file",
    "output_file_path",
    "download_dir",
    "checkpoint_file",
    "enum_checkpoint_file",
    "false_positive_file",
    "subdomain_wordlist",
    "extra_wordlists",
    "vhost_wordlist",
    "api_postman_file",
    "api_har_file",
    "api_recon_wordlist",
    # Paths / lists that need upload UX (not free-text paths on Render)
}

_HUMAN = {
    "restrict_domain": ("Stay on start domain", "Do not follow links to other hostnames."),
    "scope_mode": (
        "Crawl scope mode",
        "exact-origin = scheme+host+port only; allowed-subdomains = start host and its subdomains; off = no host gate at enqueue.",
    ),
    "max_depth": ("Max crawl depth", "How many link hops from the start URL."),
    "link_depth_limit": ("Link depth limit", "Hard cap on link-following depth."),
    "max_values_per_parameter": (
        "Max values per query param",
        "Cap how many functional query values enter the fetch queue. All observed values "
        "are still inventoried as attack surface — power is not cut.",
    ),
    "max_query_variants_per_endpoint": (
        "Max query variants per endpoint",
        "Cap distinct query strings fetched per path+param-name template. Extra variants "
        "remain in the parameter inventory.",
    ),
    "max_instances_per_route_template": (
        "Max instances per route template",
        "Sample N URLs per route family (e.g. send-money-to-{destination}). Extra URLs stay inventoried.",
    ),
    "max_locales_per_route_template": (
        "Max locales per route template",
        "How many language path segments to fully crawl per template (default 2).",
    ),
    "same_locale_only": (
        "Same locale only",
        "When seed has a locale (e.g. /be/en/), prefer that locale for crawl queue; other locales inventoried.",
    ),
    "http_first_when_bm_ready": (
        "HTTP-first after BM cookies",
        "After Chrome warm-up obtains BM cookies, fetch HTML over HTTP and escalate to Chrome on challenge. "
        "Speeds crawl without removing browser capability.",
    ),
    "skip_static_page_enqueue": (
        "Skip static assets as pages",
        "Skip CSS/images/fonts/media/page-data.json as HTML BFS pages (still inventoried; mirror can download). "
        "JS bundles are still fetched for route and secret extractors.",
    ),
    "per_directory_wildcard": (
        "Per-directory soft-404 calibration",
        "Re-probe random nonexistent paths under each enum directory prefix.",
    ),
    "crawl_concurrency": ("Crawl concurrency", "Parallel page fetches."),
    "enum_concurrency": ("Enum concurrency", "Parallel directory brute-force probes."),
    "download_concurrency": ("Download concurrency", "Parallel file downloads."),
    "ignore_robots": ("Ignore robots.txt", "Skip robots.txt rules (authorized targets only)."),
    "bypass_forbidden": ("Bypass 401/403", "Continue when the server returns forbidden/unauthorized."),
    "directory_enum": (
        "Run directory enum",
        "Opt-in folder/file name probing (usually the slowest phase). Off by default in Full Audit; on in Deep Audit / Fast Scan.",
    ),
    "enum_only": ("Enum only", "Skip crawl; run directory enumeration suite only."),
    "enum_flat_scan": ("Flat enum", "Enumerate the root path only (no recursive folders). Disables branch depth."),
    "wayback_seeds": ("Wayback Machine seeds", "Pull historical URLs from archive.org."),
    "common_crawl_seeds": ("Common Crawl seeds", "Pull URLs from Common Crawl indexes."),
    "subdomain_enum": ("Subdomain enum", "Brute-force common subdomains."),
    "subdomain_enum_limit": ("Subdomain probe limit", "Max subdomain hosts to probe (default 500)."),
    "openapi_parse": ("OpenAPI / Swagger", "Parse API docs for paths and operations."),
    "api_recon": ("API recon", "Passive API surface discovery + well-known docs."),
    "api_recon_active": ("API active enum", "Light GET/HEAD probes under /api, /v1, etc."),
    "api_recon_graphql": ("GraphQL introspection", "Query __schema when a GraphQL endpoint is found."),
    "api_recon_word_limit": ("API word limit", "Max active API path probes (conservative default 3000)."),
    "api_auth_header_name": ("API auth header name", "e.g. Authorization"),
    "api_auth_header_value": ("API auth header value", "e.g. Bearer token (authorized targets only)."),
    "js_bundle_analysis": ("JS bundle analysis", "Extract routes and secrets from JavaScript."),
    "form_discovery": ("Form discovery", "Find HTML forms on crawled pages."),
    "form_submit_probe": ("Form GET probe", "Probe GET forms safely (authorized only)."),
    "rss_feeds": ("RSS / Atom feeds", "Discover and seed feed URLs."),
    "use_wordlist": ("Use wordlist", "Enable wordlist-based directory brute force."),
    "mutation_enum": ("Path mutations", "Generate mutated path candidates."),
    "mutation_builtin": ("Built-in mutations", "Use the built-in mutation dictionary."),
    "mutation_from_seeds": ("Mutate from seeds", "Mutate paths discovered during crawl."),
    "enum_word_limit": ("Wordlist limit", "Max words to try from the wordlist (0 = all)."),
    "mutation_max_candidates": ("Max mutations", "Cap on generated mutation candidates."),
    "wildcard_detection": ("Wildcard / soft-404 detection", "Baseline responses to reduce false positives."),
    "gobuster_style_extensions": ("Extension fuzzing", "Append common extensions while enumerating."),
    "smart_wordlist_order": ("Smart wordlist order", "Prioritize high-value paths first."),
    "enum_extensions": ("Extensions", "Comma-separated extensions to append (e.g. php,bak,env)."),
    "enum_status_blacklist": ("Status blacklist", "Comma-separated HTTP codes to ignore as hits."),
    "enum_follow_redirects": (
        "Follow redirects (score final)",
        "Resolve same-host 301/302 chains and score the final page (avoids HTTP→HTTPS→404 false hits).",
    ),
    "enum_redirect_max_hops": ("Redirect max hops", "Max same-host redirects to follow while scoring."),
    "enum_method": (
        "Enum HTTP method",
        "GET is browser-like (recommended). HEAD is lighter but often flagged by bot managers.",
    ),
    "api_recon_method": (
        "API recon HTTP method",
        "GET is recommended for active API probes (avoids HEAD bot rules).",
    ),
    "enum_auto_crawl_hits": ("Auto-crawl enum hits", "Enqueue discovered directories/files into the crawl."),
    "enum_auto_vuln_scan": ("Auto-scan enum hits", "Run security checks on enum hits."),
    "vhost_enum": ("Virtual host enum", "Probe Host-header vhosts."),
    "s3_enum": ("S3 bucket enum", "Guess public AWS S3 buckets for the domain."),
    "gcs_enum": ("GCS bucket enum", "Guess public Google Cloud Storage buckets."),
    "smart_false_positive": ("Smart false-positive filter", "Similarity / baseline filtering for enum hits."),
    "false_positive_learning": ("Learn false positives", "Remember rejected patterns across the run."),
    "security_scan": ("Security scan", "Enable the security assessment suite."),
    "vuln_scan": ("Vulnerability checks", "Look for common web issues."),
    "vuln_active_probe": ("Active probes", "Send safe injection probes (authorized only)."),
    "active_probe_mode": (
        "Active probe mode",
        "Safe = crawl-safe mini payloads. Extended = broader active coverage. Lab = deeper sequences (opt-in only).",
    ),
    "ssrf_callback_base": (
        "SSRF/XXE callback base",
        "Controlled callback host for OOB SSRF/XXE confirm (e.g. https://cb.example). Empty skips OOB confirm.",
    ),
    "oob_callback_poll_url": (
        "OOB callback poll URL",
        "Optional Interactsh / VantaCrawl callback poller endpoint for nonce correlation.",
    ),
    "redirect_proof_host": (
        "Open-redirect proof host",
        "Controlled external host used to confirm open redirects.",
    ),
    "traversal_canary_path": (
        "Traversal canary path",
        "Configured canary path for traversal confirmation. Empty skips canary probes.",
    ),
    "traversal_canary_expected_content": (
        "Traversal canary content",
        "Expected file content proving the canary was read. Required with canary path.",
    ),
    "traversal_fixture_installed": (
        "Traversal lab fixture installed (legacy)",
        "Legacy alias: derive default canary path/content from fixture root when path/content empty.",
    ),
    "secret_scan": ("Secret scan", "Hunt for API keys and credentials in content."),
    "secret_validate_live": (
        "Live secret validation",
        "Opt-in read-only checks (Stripe balance, GitHub /user, VT /users/me, …) to see if a found key is still active.",
    ),
    "secret_validate_max": (
        "Max live secret checks",
        "Cap on how many credentials to probe live per scan (avoids hammering vendor APIs).",
    ),
    "finding_impact_check": (
        "Finding impact checkers",
        "For each finding, classify real-world impact (confirmed / possible / mitigated / no impact) "
        "and attach validation status — same idea as cookie stealable-credential analysis.",
    ),
    "secret_org_hints": (
        "Org / brand aliases",
        "Comma-separated names for your org (e.g. Western Union, WU, westernunion). "
        "Used with the scan domain to label custom org API keys, secrets, and activation keys.",
    ),
    "header_audit": ("Security headers", "Audit missing security response headers."),
    "cors_check": ("CORS check", "Test Cross-Origin Resource Sharing misconfig."),
    "param_discovery": ("Parameter discovery", "Find query/body parameters for probing."),
    "tech_fingerprint": ("Tech fingerprint", "Identify frameworks and server software."),
    "sensitive_file_highlights": ("Sensitive files", "Highlight .env, .git, backups, etc."),
    "broken_link_report": ("Broken links", "Report dead links found while crawling."),
    "defense_verify": ("Defense verify", "Check WAF / security controls are present."),
    "active_probe_max_params": ("Max probe params", "Cap on query parameters actively probed."),
    "active_probe_max_forms": ("Max probe forms", "Cap on forms actively probed."),
    "download_files": ("Download files", "Save responses to the mirror folder."),
    "mirror_page_assets": ("Mirror assets", "Download CSS/JS/images for pages."),
    "preserve_structure": ("Preserve paths", "Keep site folder structure on disk."),
    "rewrite_local": ("Rewrite local links", "Rewrite HTML links for offline browsing."),
    "duplicate_content_detection": ("Duplicate content", "Skip downloading duplicate bodies."),
    "warc_export": ("WARC export", "Write a WARC archive of the session."),
    "skip_tracking_downloads": ("Skip trackers", "Skip tiny tracking pixels and beacons."),
    "evasion_enabled": ("Enable stealth", "Browser-like headers, pacing, and challenge awareness."),
    "evasion_level": ("Evasion level", "How aggressive the stealth layer should be."),
    "evasion_browser": ("Browser profile", "Which browser fingerprint to impersonate."),
    "evasion_ua_strategy": ("UA strategy", "How often to rotate the User-Agent."),
    "evasion_jitter_min_ms": ("Jitter min (ms)", "Minimum delay between requests."),
    "evasion_jitter_max_ms": ("Jitter max (ms)", "Maximum delay between requests."),
    "evasion_referer_chain": ("Referer chain", "Send realistic Referer headers."),
    "evasion_adaptive_backoff": ("Adaptive backoff", "Slow down when rate-limited or challenged."),
    "evasion_challenge_detect": ("Challenge detect", "Detect bot challenges and back off."),
    "evasion_decoy_requests": ("Decoy requests", "Occasional benign decoy fetches (noisier)."),
    "evasion_http2": ("Prefer HTTP/2", "Use HTTP/2 when the target supports it."),
    "evasion_language_rotate": ("Language rotate", "Rotate Accept-Language values."),
    "html_report": ("HTML report", "Write the interactive technical HTML search report."),
    "assessment_report": (
        "Assessment report",
        "Write the professional dual-audience assessment HTML (executive + engineer).",
    ),
    "json_report": ("JSON report", "Write machine-readable JSON output."),
    "csv_export": ("CSV export", "Export findings/URLs as CSV."),
    "sqlite_export": ("SQLite export", "Write a SQLite findings database."),
    "search_conclusion_report": ("Search conclusion", "Plain-language conclusion section."),
    "site_graph_export": ("Site graph", "Export a site map / graph view."),
    "profile": ("Content profile", "Desktop preset that tunes crawl/enum aggressiveness."),
    "branch_depth_limit": ("Branch depth limit", "Extra cap on branching depth (0 = off). Ignored when Flat enum is on."),
    "response_fingerprint": ("Response fingerprint", "Fingerprint bodies to spot soft-404 wildcards."),
    "legacy_wordlist_expansion": ("Legacy wordlist expansion", "Expand every word with every extension (slow)."),
    "extension_aware_wordlist": ("Extension-aware wordlist", "Smarter extension handling while enumerating."),
    "enum_status_whitelist": ("Status whitelist", "Only treat these codes as hits (comma-separated)."),
    "exclude_lengths": ("Exclude lengths", "Ignore responses with these Content-Lengths."),
    "exclude_body_hashes": ("Exclude body hashes", "Ignore responses matching these hashes."),
    "enum_prefixes": ("Enum prefixes", "Comma-separated path prefixes to enumerate under."),
    "auto_prefix_enum": ("Auto prefix enum", "Derive prefixes from discovered paths."),
    "enum_similarity_threshold": ("Similarity threshold", "Soft-404 similarity cutoff (higher = stricter)."),
    "status_code_report": ("Status-code reporting", "Record HTTP status detail on enum hits."),
    "queue_enum_for_crawl": ("Queue enum for crawl", "Feed enum hits into the crawl queue."),
    "skip_enum_download": ("Skip enum download", "Do not download bodies during brute force."),
    "resume_enum_checkpoint": ("Resume enum checkpoint", "Continue enum from the last checkpoint."),
    "enum_checkpoint_interval": ("Enum checkpoint interval", "Save enum progress every N words."),
    "broken_link_sample_size": ("Broken-link sample", "Max links to sample for broken-link checks."),
    "nuclei_scan": ("Nuclei scan", "Run Nuclei if installed on the worker (authorized only)."),
    "nuclei_severity": ("Nuclei severity", "Comma-separated severities to include."),
    "save_server_side_as_txt": ("Save PHP/ASP as .txt", "Store server-side scripts as text in the mirror."),
    "extensions": ("Download extensions", "Only download these extensions (comma-separated, empty = all)."),
    "incremental_mirror": ("Incremental mirror", "Skip unchanged files via ETag / Last-Modified."),
    "selenium_fallback": ("Selenium fallback", "Render pages in Chrome when plain HTTP fails (needs Chrome)."),
    "deep_mirror": ("Deep mirror", "Render all HTML in Chrome for offline fidelity (slow)."),
    "browser_primary": (
        "Chrome-first HTML",
        "Use real headless Chrome for HTML page navigations (live browser JA4/cookies; needs Chrome; slower). "
        "Also auto-enabled when Akamai/Cloudflare Bot Manager is detected. "
        "Directory enum and API probes still use the HTTP client (Chrome cannot efficiently probe thousands of paths).",
    ),
    "browser_on_challenge": (
        "Chrome on challenge",
        "If HTTP/curl_cffi hits a WAF/challenge page, retry that URL in real Chrome and sync cookies.",
    ),
    "bm_cookie_wait_seconds": (
        "BM cookie wait (Chrome)",
        "Seconds to wait after Chrome page load for Akamai BM cookies (_abck/bm_sz). "
        "Too low → Akamai may log NoScript / javascript fingerprint not received.",
    ),
    "auto_sync_cookies": (
        "Auto-sync cookies",
        "Automatically copy per-host cookies from Chrome into the HTTP jar "
        "(required so HTTP follow-ups carry BM session cookies).",
    ),
    "screenshot_capture": ("Screenshot capture", "Capture page screenshots (needs Chrome)."),
    "proxy_url": ("Proxy URL", "Optional HTTP(S) proxy, e.g. http://user:pass@host:8080"),
    "auth_username": ("Basic auth username", "HTTP basic authentication username."),
    "auth_password": ("Basic auth password", "HTTP basic authentication password."),
    "cookie_string": (
        "Cookie string",
        "Paste a raw Cookie header from your browser so probes look logged-in. "
        "Chrome: DevTools → Application → Cookies → copy name=value pairs joined with '; '. "
        "Or DevTools → Network → any request → Request Headers → Cookie.",
    ),
    "evasion_chrome_tls": (
        "Chrome TLS impersonation",
        "Use curl_cffi to match real Chrome JA3/HTTP2 (falls back to httpx if unavailable).",
    ),
    "use_selenium_login": ("Browser login first", "Open a browser login flow before crawling (needs Chrome)."),
    "login_url": ("Login URL", "Page where the login form lives."),
    "login_username": ("Login username", "Username / email for the login form."),
    "login_password": ("Login password", "Password for the login form."),
    "resume_checkpoint": ("Resume crawl checkpoint", "Continue from the last crawl checkpoint."),
    "checkpoint_interval": ("Crawl checkpoint interval", "Save crawl progress every N pages."),
    "disk_space_guard_mb": ("Disk space guard (MB)", "Stop downloads if free disk falls below this."),
    "distributed_redis_url": ("Distributed Redis URL", "Optional Redis URL for distributed queue mode."),
    "schedule_interval_hours": ("Rescan interval (hours)", "0 = once. Web SaaS stores this; dedicated scheduler is a follow-up."),
    "burp_export": ("Burp XML export", "Write Burp-style findings XML."),
    "zap_export": ("ZAP JSON export", "Write OWASP ZAP-style findings JSON."),
    "priority_html_first": ("Priority HTML queue", "Fetch HTML pages before other assets."),
}

_UA_STRATEGIES = (
    ("sticky_session", "Sticky session - one UA for the whole run"),
    ("sticky_host", "Sticky host - one UA per hostname (recommended)"),
    ("rotate", "Rotate - change UA more often"),
)

_ENUM_METHODS = (
    ("GET", "GET - browser-like (recommended; avoids HEAD bot rules)"),
    ("HEAD", "HEAD - lighter probes (often flagged by bot managers)"),
)

_SCOPE_MODES = (
    ("exact-origin", "Exact origin - scheme + host + port only"),
    ("allowed-subdomains", "Allowed subdomains - start host and its subdomains (default)"),
    ("off", "Off - no host gate at enqueue"),
)

_ACTIVE_PROBE_MODES = (
    ("passive", "Passive - discovery only, no active injection"),
    ("safe", "Safe - crawl-safe mini payloads (default)"),
    ("extended", "Extended - broader active coverage"),
    ("lab", "Lab - deeper sequences (opt-in / authorized only)"),
)

_EXTENSION_PRESETS = (
    ("php,asp,aspx,bak,old,txt,zip,sql,config,env", "Common web + backups"),
    ("php,asp,aspx,jsp,cgi", "Script extensions only"),
    ("bak,old,txt,zip,sql,tar,gz,7z", "Backup / archive focus"),
    ("env,config,yml,yaml,json,ini,conf", "Config / secrets focus"),
    ("", "None (path names only)"),
)

_DOWNLOAD_EXTENSION_PRESETS = (
    ("", "All extensions (default)"),
    ("html,htm,css,js,json,xml,txt", "Web documents"),
    ("pdf,doc,docx,xls,xlsx,csv", "Office / documents"),
    ("jpg,jpeg,png,gif,webp,svg,ico", "Images"),
    ("zip,tar,gz,7z,rar,sql,bak", "Archives / dumps"),
)

_STATUS_BLACKLIST_PRESETS = (
    ("404", "Ignore 404 only"),
    ("404,400", "Ignore 404 and 400"),
    ("404,400,429", "Ignore 404, 400, 429"),
    ("404,403", "Ignore 404 and 403"),
    ("", "None (treat all statuses)"),
)

_STATUS_WHITELIST_PRESETS = (
    ("", "No whitelist (default — use blacklist)"),
    ("200", "200 only"),
    ("200,301,302", "200 + redirects"),
    ("200,301,302,401,403", "200 / redirects / auth walls"),
    ("200,403", "200 and 403"),
)

_EXCLUDE_LENGTH_PRESETS = (
    ("", "None (default)"),
    ("0", "Ignore empty bodies (0)"),
    ("0,43", "Ignore empty + tiny soft-404s"),
)

_ENUM_PREFIX_PRESETS = (
    ("", "Auto / none (default)"),
    ("/,/admin/,/api/,/backup/", "Common high-value prefixes"),
    ("/,/api/,/v1/,/v2/,/graphql/", "API-focused"),
    ("/,/wp-admin/,/wp-content/,/wp-includes/", "WordPress-ish"),
)

_API_AUTH_HEADER_PRESETS = (
    ("Authorization", "Authorization (default)"),
    ("X-API-Key", "X-API-Key"),
    ("X-Auth-Token", "X-Auth-Token"),
    ("Api-Key", "Api-Key"),
    ("", "None / custom"),
)

_REDIRECT_PROOF_PRESETS = (
    ("redirect-proof.vantacrawl-lab.example", "Built-in lab proof host (default)"),
    ("example.com", "example.com"),
    ("https://example.com", "https://example.com"),
    ("", "Empty (skip external proof host)"),
)

_SSRF_CALLBACK_PRESETS = (
    ("", "Empty - skip OOB confirm (default)"),
    ("https://oast.example", "https://oast.example (placeholder)"),
    ("http://127.0.0.1:8080", "Local listener http://127.0.0.1:8080"),
)

_OOB_POLL_PRESETS = (
    ("", "Empty - no poller (default)"),
    ("https://poll.oast.example/poll", "Interactsh-style poll URL (placeholder)"),
)

_TRAVERSAL_CANARY_PATH_PRESETS = (
    ("", "Empty - skip canary probes (default)"),
    ("etc/passwd", "etc/passwd (Unix lab)"),
    ("windows/win.ini", "windows/win.ini (Windows lab)"),
    ("var/www/html/canary.txt", "var/www/html/canary.txt"),
)

_TRAVERSAL_CANARY_CONTENT_PRESETS = (
    ("", "Empty - skip canary confirm (default)"),
    ("root:x:0:0:", "Unix passwd marker (root:x:0:0:)"),
    ("for 16-bit app support", "win.ini marker"),
    ("VANTA_TRAVERSAL_CANARY", "Lab canary token"),
)

_SECRET_ORG_HINT_PRESETS = (
    ("", "None (auto from start URL)"),
)

_PROXY_URL_PRESETS = (
    ("", "None (direct)"),
    ("http://127.0.0.1:8080", "Local HTTP proxy :8080"),
    ("http://127.0.0.1:8888", "Local HTTP proxy :8888"),
    ("socks5://127.0.0.1:1080", "Local SOCKS5 :1080"),
)


def _preset_pairs(*pairs: tuple[str, str]) -> List[Dict[str, str]]:
    return [{"value": value, "label": label} for value, label in pairs]


def _number_presets(*pairs: tuple[str | int | float, str]) -> List[Dict[str, str]]:
    return [{"value": str(value), "label": label} for value, label in pairs]


def _field(
    key: str,
    *,
    control: str = "auto",
    options: List[Dict[str, str]] | None = None,
    presets: List[Dict[str, str]] | None = None,
) -> Dict[str, Any]:
    label, help_text = _HUMAN.get(key, (key.replace("_", " ").title(), ""))
    return {
        "key": key,
        "label": label,
        "help": help_text,
        "control": control,
        "options": options or [],
        "presets": presets or [],
    }


def setting_fields() -> Dict[str, Dict[str, Any]]:
    browser_opts = [{"value": name, "label": name.title()} for name in BROWSER_PROFILES]
    browser_opts.append({"value": "random", "label": "Random (pick per session)"})
    level_labels = {
        "off": "Off - no stealth layer",
        "basic": "Basic - light headers / pacing",
        "stealth": "Stealth - recommended default",
        "aggressive": "Aggressive - max impersonation / jitter",
    }
    fields = {
        # --- Core ---
        "profile": _field(
            "profile",
            control="select",
            options=[
                {"value": "full", "label": "Full - balanced desktop default"},
                {"value": "quick", "label": "Quick - lighter discovery"},
                {"value": "stealth", "label": "Stealth - slower, quieter"},
                {"value": "gobuster", "label": "Gobuster-style - enum-heavy"},
            ],
        ),
        "scope_mode": _field(
            "scope_mode",
            control="select",
            options=_preset_pairs(*_SCOPE_MODES),
        ),
        "max_depth": _field(
            "max_depth",
            control="number_with_presets",
            presets=_number_presets(
                (1, "1 - shallow"),
                (2, "2 - light"),
                (3, "3 - default"),
                (5, "5 - deeper"),
                (8, "8 - deep"),
                (0, "0 - uncapped / rely on other limits"),
            ),
        ),
        "link_depth_limit": _field(
            "link_depth_limit",
            control="number_with_presets",
            presets=_number_presets(
                (0, "0 - off (default)"),
                (2, "2"),
                (3, "3"),
                (5, "5"),
                (10, "10"),
            ),
        ),
        "branch_depth_limit": _field(
            "branch_depth_limit",
            control="number_with_presets",
            presets=_number_presets(
                (0, "0 - off (default)"),
                (1, "1"),
                (2, "2"),
                (3, "3"),
                (5, "5"),
            ),
        ),
        "max_values_per_parameter": _field(
            "max_values_per_parameter",
            control="number_with_presets",
            presets=_number_presets((1, "1"), (2, "2 - default"), (3, "3"), (5, "5"), (10, "10")),
        ),
        "max_query_variants_per_endpoint": _field(
            "max_query_variants_per_endpoint",
            control="number_with_presets",
            presets=_number_presets((1, "1"), (2, "2"), (3, "3 - default"), (5, "5"), (10, "10")),
        ),
        "max_instances_per_route_template": _field(
            "max_instances_per_route_template",
            control="number_with_presets",
            presets=_number_presets((1, "1"), (2, "2 - default"), (3, "3"), (5, "5"), (10, "10")),
        ),
        "max_locales_per_route_template": _field(
            "max_locales_per_route_template",
            control="number_with_presets",
            presets=_number_presets((1, "1"), (2, "2 - default"), (3, "3"), (5, "5")),
        ),
        "crawl_concurrency": _field(
            "crawl_concurrency",
            control="number_with_presets",
            presets=_number_presets(
                (1, "1 - serial"),
                (2, "2 - gentle"),
                (4, "4 - default"),
                (8, "8 - faster"),
                (12, "12 - aggressive"),
            ),
        ),
        "enum_concurrency": _field(
            "enum_concurrency",
            control="number_with_presets",
            presets=_number_presets(
                (10, "10 - gentle"),
                (20, "20"),
                (35, "35 - default"),
                (50, "50"),
                (80, "80 - aggressive"),
            ),
        ),
        "download_concurrency": _field(
            "download_concurrency",
            control="number_with_presets",
            presets=_number_presets((2, "2"), (4, "4"), (6, "6 - default"), (10, "10"), (16, "16")),
        ),
        # --- Discovery ---
        "subdomain_enum_limit": _field(
            "subdomain_enum_limit",
            control="number_with_presets",
            presets=_number_presets(
                (100, "100 - light"),
                (250, "250"),
                (500, "500 - default"),
                (1000, "1000"),
                (5000, "5000 - heavy"),
            ),
        ),
        "api_recon_word_limit": _field(
            "api_recon_word_limit",
            control="number_with_presets",
            presets=_number_presets(
                (500, "500 - light"),
                (1000, "1000"),
                (3000, "3000 - default"),
                (5000, "5000"),
                (10000, "10000 - heavy"),
            ),
        ),
        "api_recon_method": _field(
            "api_recon_method",
            control="select",
            options=_preset_pairs(*_ENUM_METHODS),
        ),
        "api_auth_header_name": _field(
            "api_auth_header_name",
            control="text_with_presets",
            presets=_preset_pairs(*_API_AUTH_HEADER_PRESETS),
        ),
        # --- Directory enum ---
        "enum_method": _field(
            "enum_method",
            control="select",
            options=_preset_pairs(*_ENUM_METHODS),
        ),
        "enum_extensions": _field(
            "enum_extensions",
            control="text_with_presets",
            presets=_preset_pairs(*_EXTENSION_PRESETS),
        ),
        "enum_status_blacklist": _field(
            "enum_status_blacklist",
            control="text_with_presets",
            presets=_preset_pairs(*_STATUS_BLACKLIST_PRESETS),
        ),
        "enum_status_whitelist": _field(
            "enum_status_whitelist",
            control="text_with_presets",
            presets=_preset_pairs(*_STATUS_WHITELIST_PRESETS),
        ),
        "exclude_lengths": _field(
            "exclude_lengths",
            control="text_with_presets",
            presets=_preset_pairs(*_EXCLUDE_LENGTH_PRESETS),
        ),
        "enum_prefixes": _field(
            "enum_prefixes",
            control="text_with_presets",
            presets=_preset_pairs(*_ENUM_PREFIX_PRESETS),
        ),
        "enum_word_limit": _field(
            "enum_word_limit",
            control="number_with_presets",
            presets=_number_presets(
                (0, "0 - entire wordlist (default)"),
                (500, "500"),
                (2000, "2000"),
                (5000, "5000"),
                (20000, "20000"),
            ),
        ),
        "mutation_max_candidates": _field(
            "mutation_max_candidates",
            control="number_with_presets",
            presets=_number_presets(
                (5000, "5000 - light"),
                (20000, "20000"),
                (50000, "50000 - default"),
                (100000, "100000"),
            ),
        ),
        "enum_redirect_max_hops": _field(
            "enum_redirect_max_hops",
            control="number_with_presets",
            presets=_number_presets((1, "1"), (3, "3"), (5, "5 - default"), (8, "8"), (10, "10")),
        ),
        "enum_similarity_threshold": _field(
            "enum_similarity_threshold",
            control="number_with_presets",
            presets=_number_presets(
                (30, "30 - looser"),
                (40, "40"),
                (50, "50 - default"),
                (70, "70 - stricter"),
                (85, "85 - very strict"),
            ),
        ),
        "enum_checkpoint_interval": _field(
            "enum_checkpoint_interval",
            control="number_with_presets",
            presets=_number_presets(
                (1000, "1000"),
                (2500, "2500"),
                (5000, "5000 - default"),
                (10000, "10000"),
            ),
        ),
        # --- Security ---
        "active_probe_mode": _field(
            "active_probe_mode",
            control="select",
            options=_preset_pairs(*_ACTIVE_PROBE_MODES),
        ),
        "ssrf_callback_base": _field(
            "ssrf_callback_base",
            control="text_with_presets",
            presets=_preset_pairs(*_SSRF_CALLBACK_PRESETS),
        ),
        "oob_callback_poll_url": _field(
            "oob_callback_poll_url",
            control="text_with_presets",
            presets=_preset_pairs(*_OOB_POLL_PRESETS),
        ),
        "redirect_proof_host": _field(
            "redirect_proof_host",
            control="text_with_presets",
            presets=_preset_pairs(*_REDIRECT_PROOF_PRESETS),
        ),
        "traversal_canary_path": _field(
            "traversal_canary_path",
            control="text_with_presets",
            presets=_preset_pairs(*_TRAVERSAL_CANARY_PATH_PRESETS),
        ),
        "traversal_canary_expected_content": _field(
            "traversal_canary_expected_content",
            control="text_with_presets",
            presets=_preset_pairs(*_TRAVERSAL_CANARY_CONTENT_PRESETS),
        ),
        "secret_validate_max": _field(
            "secret_validate_max",
            control="number_with_presets",
            presets=_number_presets((5, "5"), (10, "10"), (25, "25 - default"), (50, "50"), (100, "100")),
        ),
        "secret_org_hints": _field(
            "secret_org_hints",
            control="text_with_presets",
            presets=_preset_pairs(*_SECRET_ORG_HINT_PRESETS),
        ),
        "broken_link_sample_size": _field(
            "broken_link_sample_size",
            control="number_with_presets",
            presets=_number_presets(
                (0, "0 - off"),
                (10, "10 - light"),
                (30, "30 - default"),
                (50, "50"),
                (100, "100"),
            ),
        ),
        "active_probe_max_params": _field(
            "active_probe_max_params",
            control="number_with_presets",
            presets=_number_presets((3, "3"), (5, "5"), (8, "8 - default"), (12, "12"), (20, "20")),
        ),
        "active_probe_max_forms": _field(
            "active_probe_max_forms",
            control="number_with_presets",
            presets=_number_presets((1, "1"), (2, "2"), (3, "3 - default"), (5, "5"), (10, "10")),
        ),
        "nuclei_severity": _field(
            "nuclei_severity",
            control="select",
            options=[
                {"value": "critical", "label": "critical"},
                {"value": "high,critical", "label": "high, critical"},
                {"value": "medium,high,critical", "label": "medium, high, critical (default)"},
                {"value": "low,medium,high,critical", "label": "low through critical"},
                {"value": "info,low,medium,high,critical", "label": "all severities"},
            ],
        ),
        # --- Download / mirror ---
        "extensions": _field(
            "extensions",
            control="text_with_presets",
            presets=_preset_pairs(*_DOWNLOAD_EXTENSION_PRESETS),
        ),
        "bm_cookie_wait_seconds": _field(
            "bm_cookie_wait_seconds",
            control="number_with_presets",
            presets=_number_presets(
                (0, "0 - body-only / no BM wait"),
                (6, "6 - faster"),
                (12, "12 - default"),
                (20, "20 - patient"),
                (30, "30 - slow targets"),
            ),
        ),
        # --- Connection & auth ---
        "proxy_url": _field(
            "proxy_url",
            control="text_with_presets",
            presets=_preset_pairs(*_PROXY_URL_PRESETS),
        ),
        "auth_password": _field("auth_password", control="password"),
        "login_password": _field("login_password", control="password"),
        "api_auth_header_value": _field("api_auth_header_value", control="password"),
        # --- Operations ---
        "checkpoint_interval": _field(
            "checkpoint_interval",
            control="number_with_presets",
            presets=_number_presets((10, "10"), (25, "25"), (50, "50 - default"), (100, "100"), (250, "250")),
        ),
        "disk_space_guard_mb": _field(
            "disk_space_guard_mb",
            control="number_with_presets",
            presets=_number_presets(
                (100, "100 MB"),
                (250, "250 MB"),
                (500, "500 MB - default"),
                (1000, "1 GB"),
                (2000, "2 GB"),
            ),
        ),
        "schedule_interval_hours": _field(
            "schedule_interval_hours",
            control="number_with_presets",
            presets=_number_presets(
                (0, "0 - run once (default)"),
                (1, "1 hour"),
                (6, "6 hours"),
                (12, "12 hours"),
                (24, "24 hours"),
                (168, "Weekly (168h)"),
            ),
        ),
        # --- Stealth ---
        "evasion_level": _field(
            "evasion_level",
            control="select",
            options=[{"value": level, "label": level_labels.get(level, level)} for level in LEVELS],
        ),
        "evasion_browser": _field("evasion_browser", control="select", options=browser_opts),
        "evasion_ua_strategy": _field(
            "evasion_ua_strategy",
            control="select",
            options=_preset_pairs(*_UA_STRATEGIES),
        ),
        "evasion_jitter_min_ms": _field(
            "evasion_jitter_min_ms",
            control="number_with_presets",
            presets=_number_presets((0, "0"), (25, "25"), (50, "50 - default"), (100, "100"), (200, "200")),
        ),
        "evasion_jitter_max_ms": _field(
            "evasion_jitter_max_ms",
            control="number_with_presets",
            presets=_number_presets(
                (100, "100"),
                (250, "250"),
                (400, "400 - default"),
                (800, "800"),
                (1500, "1500 - slow"),
            ),
        ),
    }
    # Defaults for every editable key so the UI always has a human label
    cfg = CrawlConfig(start_url="https://example.com")
    for key in cfg.__dataclass_fields__:
        if key in EDITABLE_DEFAULTS_SKIP or key in fields:
            continue
        value = getattr(cfg, key)
        if isinstance(value, bool):
            fields[key] = _field(key, control="checkbox")
        elif isinstance(value, int) and not isinstance(value, bool):
            fields[key] = _field(key, control="number")
        elif isinstance(value, float):
            fields[key] = _field(key, control="number")
        elif isinstance(value, str):
            fields[key] = _field(key, control="text")
        else:
            fields[key] = _field(key, control="text")
    return fields


def default_settings() -> Dict[str, Any]:
    cfg = CrawlConfig(start_url="https://example.com")
    data = {k: getattr(cfg, k) for k in cfg.__dataclass_fields__}
    for key in EDITABLE_DEFAULTS_SKIP:
        data.pop(key, None)
    data.pop("custom_headers", None)
    data.pop("blocked_content_types", None)
    # UI-friendly string for list-typed extensions
    ext = data.get("extensions")
    if isinstance(ext, list):
        data["extensions"] = ",".join(str(x) for x in ext)
    elif ext is None:
        data["extensions"] = ""
    # Never ship default secrets into the browser form
    data["auth_password"] = ""
    data["login_password"] = ""
    return data


SETTING_GROUPS: List[Dict[str, Any]] = [
    {
        "id": "core",
        "title": "Core",
        "keys": [
            "profile",
            "restrict_domain",
            "scope_mode",
            "max_depth",
            "link_depth_limit",
            "max_values_per_parameter",
            "max_query_variants_per_endpoint",
            "max_instances_per_route_template",
            "max_locales_per_route_template",
            "same_locale_only",
            "http_first_when_bm_ready",
            "skip_static_page_enqueue",
            "per_directory_wildcard",
            "branch_depth_limit",
            "crawl_concurrency",
            "enum_concurrency",
            "download_concurrency",
            "ignore_robots",
            "bypass_forbidden",
            "enum_only",
            "enum_flat_scan",
            "priority_html_first",
        ],
    },
    {
        "id": "discovery",
        "title": "Discovery",
        "keys": [
            "wayback_seeds",
            "common_crawl_seeds",
            "subdomain_enum",
            "subdomain_enum_limit",
            "openapi_parse",
            "api_recon",
            "api_recon_active",
            "api_recon_graphql",
            "api_recon_method",
            "api_recon_word_limit",
            "api_auth_header_name",
            "api_auth_header_value",
            "js_bundle_analysis",
            "form_discovery",
            "form_submit_probe",
            "rss_feeds",
        ],
    },
    {
        "id": "enum",
        "title": "Directory enum",
        "keys": [
            "directory_enum",
            "use_wordlist",
            "mutation_enum",
            "mutation_builtin",
            "mutation_from_seeds",
            "enum_word_limit",
            "mutation_max_candidates",
            "wildcard_detection",
            "response_fingerprint",
            "gobuster_style_extensions",
            "legacy_wordlist_expansion",
            "extension_aware_wordlist",
            "smart_wordlist_order",
            "enum_extensions",
            "enum_status_blacklist",
            "enum_status_whitelist",
            "enum_follow_redirects",
            "enum_redirect_max_hops",
            "exclude_lengths",
            "exclude_body_hashes",
            "enum_prefixes",
            "auto_prefix_enum",
            "enum_method",
            "enum_similarity_threshold",
            "status_code_report",
            "queue_enum_for_crawl",
            "skip_enum_download",
            "enum_auto_crawl_hits",
            "enum_auto_vuln_scan",
            "vhost_enum",
            "s3_enum",
            "gcs_enum",
            "smart_false_positive",
            "false_positive_learning",
            "resume_enum_checkpoint",
            "enum_checkpoint_interval",
        ],
    },
    {
        "id": "security",
        "title": "Security",
        "keys": [
            "security_scan",
            "vuln_scan",
            "vuln_active_probe",
            "active_probe_mode",
            "ssrf_callback_base",
            "oob_callback_poll_url",
            "redirect_proof_host",
            "traversal_canary_path",
            "traversal_canary_expected_content",
            "traversal_fixture_installed",
            "secret_scan",
            "secret_validate_live",
            "secret_validate_max",
            "finding_impact_check",
            "secret_org_hints",
            "header_audit",
            "cors_check",
            "param_discovery",
            "tech_fingerprint",
            "sensitive_file_highlights",
            "broken_link_report",
            "broken_link_sample_size",
            "defense_verify",
            "active_probe_max_params",
            "active_probe_max_forms",
            "nuclei_scan",
            "nuclei_severity",
        ],
    },
    {
        "id": "download",
        "title": "Download / mirror",
        "keys": [
            "download_files",
            "mirror_page_assets",
            "preserve_structure",
            "rewrite_local",
            "save_server_side_as_txt",
            "extensions",
            "duplicate_content_detection",
            "incremental_mirror",
            "warc_export",
            "skip_tracking_downloads",
            "selenium_fallback",
            "deep_mirror",
            "browser_primary",
            "browser_on_challenge",
            "bm_cookie_wait_seconds",
            "auto_sync_cookies",
            "screenshot_capture",
        ],
    },
    {
        "id": "connection",
        "title": "Connection & auth",
        "keys": [
            "proxy_url",
            "auth_username",
            "auth_password",
            "cookie_string",
            "use_selenium_login",
            "login_url",
            "login_username",
            "login_password",
        ],
    },
    {
        "id": "operations",
        "title": "Operations",
        "keys": [
            "resume_checkpoint",
            "checkpoint_interval",
            "disk_space_guard_mb",
            "distributed_redis_url",
            "schedule_interval_hours",
        ],
    },
    {
        "id": "stealth",
        "title": "Stealth",
        "keys": [
            "evasion_enabled",
            "evasion_level",
            "evasion_browser",
            "evasion_ua_strategy",
            "evasion_jitter_min_ms",
            "evasion_jitter_max_ms",
            "evasion_referer_chain",
            "evasion_language_rotate",
            "evasion_adaptive_backoff",
            "evasion_challenge_detect",
            "evasion_decoy_requests",
            "evasion_http2",
            "evasion_chrome_tls",
        ],
    },
    {
        "id": "reports",
        "title": "Reports & exports",
        "keys": [
            "assessment_report",
            "html_report",
            "json_report",
            "csv_export",
            "sqlite_export",
            "search_conclusion_report",
            "site_graph_export",
            "burp_export",
            "zap_export",
        ],
    },
]


def available_wordlists() -> List[Dict[str, str]]:
    """Bundled Wordlist/ files the web UI can select without uploading."""
    folder = ROOT / "Wordlist"
    items: List[Dict[str, str]] = []
    if not folder.is_dir():
        return items
    for path in sorted(folder.glob("*.txt")):
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        items.append(
            {
                "id": path.name,
                "label": f"{path.name} ({max(1, size // 1024)} KB)",
                "path": str(path.resolve()),
            }
        )
    return items


def resolve_catalog_wordlist(wordlist_id: str) -> Optional[str]:
    """Return absolute path to a bundled Wordlist/ file, or None."""
    chosen = (wordlist_id or "").strip()
    if not chosen or chosen in ("__upload__", "upload"):
        return None
    match = next((w for w in available_wordlists() if w["id"] == chosen), None)
    if not match:
        return None
    path = Path(match["path"])
    return str(path) if path.is_file() else None


def ensure_wordlist_path(config: Optional[Dict[str, Any]] = None) -> str:
    """Pick a usable directory wordlist path.

    Catalog selections must use the stable Wordlist/ tree (not ephemeral job uploads/).
    If a stale uploads/ copy vanished after cancel/restart, re-bind by wordlist_id or basename.
    """
    from crawl_config import DEFAULT_DIR_WORDLIST

    cfg = dict(config or {})
    path = str(cfg.get("wordlist_file") or "").strip()
    wid = str(cfg.get("wordlist_id") or "").strip()

    if path and Path(path).is_file():
        return path

    resolved = resolve_catalog_wordlist(wid)
    if resolved:
        return resolved

    if path:
        resolved = resolve_catalog_wordlist(Path(path).name)
        if resolved:
            return resolved

    if Path(DEFAULT_DIR_WORDLIST).is_file():
        return str(Path(DEFAULT_DIR_WORDLIST).resolve())
    return path or str(DEFAULT_DIR_WORDLIST)


def meta_payload() -> Dict[str, Any]:
    mode_keys = [m for m in MODES if m in MODE_PRESETS] or list(MODE_PRESETS.keys())
    return {
        "modes": {
            key: {"label": MODE_LABELS.get(key, key), "preset": MODE_PRESETS.get(key, {})}
            for key in mode_keys
        },
        "speeds": SPEED_PROFILES,
        "default_settings": default_settings(),
        "setting_groups": SETTING_GROUPS,
        "setting_fields": setting_fields(),
        "wordlists": available_wordlists(),
    }


__all__ = [
    "EDITABLE_DEFAULTS_SKIP",
    "MODE_PRESETS",
    "SETTING_GROUPS",
    "available_wordlists",
    "concurrency_for_speed",
    "default_settings",
    "ensure_wordlist_path",
    "meta_payload",
    "resolve_catalog_wordlist",
    "setting_fields",
]
