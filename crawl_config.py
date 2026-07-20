"""Central configuration for full-featured crawl runs."""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from typing import ClassVar, Dict, List, Optional

from crawler_common import get_project_paths


BASE_DIR, DEFAULT_OUTPUT, DEFAULT_DOWNLOAD = get_project_paths()
DEFAULT_DIR_WORDLIST = os.path.join(BASE_DIR, "Wordlist", "directory-list-2.3-big.txt")
DEFAULT_SUBDOMAIN_WORDLIST = os.path.join(BASE_DIR, "Wordlist", "subdomains-top1million-110000.txt")


@dataclass
class CrawlConfig:
    start_url: str
    wordlist_file: str = DEFAULT_DIR_WORDLIST
    output_file_path: str = DEFAULT_OUTPUT
    download_dir: str = DEFAULT_DOWNLOAD

    restrict_domain: bool = True
    download_files: bool = False
    extensions: Optional[List[str]] = None
    max_depth: int = 3
    preserve_structure: bool = True
    rewrite_local: bool = True
    mirror_page_assets: bool = True  # download CSS/JS/images for offline HTML views
    ignore_robots: bool = True
    save_server_side_as_txt: bool = True
    bypass_forbidden: bool = True
    enum_concurrency: int = 35
    download_concurrency: int = 6
    link_depth_limit: int = 0

    proxy_url: str = ""
    auth_username: str = ""
    auth_password: str = ""
    custom_headers: Dict[str, str] = field(default_factory=dict)
    cookie_string: str = ""

    resume_checkpoint: bool = False
    checkpoint_file: str = ""
    checkpoint_interval: int = 50

    wayback_seeds: bool = True
    common_crawl_seeds: bool = True
    subdomain_enum: bool = True
    subdomain_wordlist: str = DEFAULT_SUBDOMAIN_WORDLIST
    openapi_parse: bool = True
    # API recon module — passive+docs when on; active/GraphQL/import via sub-flags
    api_recon: bool = True
    api_recon_active: bool = True
    api_recon_graphql: bool = True
    api_recon_word_limit: int = 3000
    api_recon_wordlist: str = ""
    api_recon_method: str = "HEAD"
    api_auth_header_name: str = "Authorization"
    api_auth_header_value: str = ""
    api_postman_file: str = ""
    api_har_file: str = ""
    js_bundle_analysis: bool = True
    form_discovery: bool = True
    form_submit_probe: bool = False
    rss_feeds: bool = True

    smart_false_positive: bool = True
    extension_aware_wordlist: bool = True
    status_code_report: bool = True
    branch_depth_limit: int = 0
    extra_wordlists: List[str] = field(default_factory=list)
    skip_enum_download: bool = False
    queue_enum_for_crawl: bool = True
    enum_word_limit: int = 0

    # Gobuster-beater enum engine
    enum_only: bool = False
    enum_flat_scan: bool = False
    gobuster_style_extensions: bool = True
    legacy_wordlist_expansion: bool = False
    enum_status_whitelist: str = ""
    enum_status_blacklist: str = "404"
    enum_extensions: str = "php,asp,aspx,bak,old,txt,zip,sql,config,env"
    exclude_lengths: str = ""
    exclude_body_hashes: str = ""
    wildcard_detection: bool = True
    response_fingerprint: bool = True
    smart_wordlist_order: bool = True
    enum_prefixes: str = ""
    auto_prefix_enum: bool = True
    enum_method: str = "HEAD"
    vhost_enum: bool = False
    vhost_wordlist: str = ""
    s3_enum: bool = False
    gcs_enum: bool = False
    enum_auto_crawl_hits: bool = True
    enum_auto_vuln_scan: bool = True
    false_positive_learning: bool = True
    false_positive_file: str = ""
    resume_enum_checkpoint: bool = False
    enum_checkpoint_file: str = ""
    enum_checkpoint_interval: int = 5000

    # Mutation scanning (merged on top of wordlist when both enabled)
    use_wordlist: bool = True
    mutation_enum: bool = True
    mutation_only: bool = False  # deprecated; kept for config compat — ignored by engine
    mutation_builtin: bool = True
    mutation_from_seeds: bool = True
    mutation_max_candidates: int = 50000

    duplicate_content_detection: bool = True
    warc_export: bool = True
    incremental_mirror: bool = True
    priority_html_first: bool = True

    security_scan: bool = True
    param_discovery: bool = True
    header_audit: bool = True
    secret_scan: bool = True
    cors_check: bool = True
    vuln_scan: bool = True
    vuln_active_probe: bool = True  # safer baseline-compared probes; authorized targets only
    active_probe_max_params: int = 8
    active_probe_max_forms: int = 3

    html_report: bool = True
    assessment_report: bool = True
    report_title: str = ""  # optional scan/job title used in report filenames
    json_report: bool = True
    sqlite_export: bool = True
    csv_export: bool = True
    search_conclusion_report: bool = True
    screenshot_capture: bool = False
    tech_fingerprint: bool = True
    broken_link_report: bool = True
    sensitive_file_highlights: bool = True

    profile: str = "full"
    disk_space_guard_mb: int = 500
    distributed_redis_url: str = ""

    selenium_fallback: bool = False
    deep_mirror: bool = False

    crawl_concurrency: int = 4
    enum_similarity_threshold: int = 50
    broken_link_sample_size: int = 30
    skip_tracking_downloads: bool = True
    blocked_content_types: List[str] = field(default_factory=list)

    # Exports & integrations
    site_graph_export: bool = True
    burp_export: bool = True
    zap_export: bool = True
    nuclei_scan: bool = False
    nuclei_severity: str = "medium,high,critical"

    # Auth login wizard (optional pre-crawl)
    login_url: str = ""
    login_username: str = ""
    login_password: str = ""
    use_selenium_login: bool = False

    # Scheduler (CLI / saved config)
    schedule_interval_hours: float = 0

    # Stealth / authorized-lab request evasion
    evasion_enabled: bool = True
    evasion_level: str = "stealth"  # off | basic | stealth | aggressive
    evasion_browser: str = "chrome"  # chrome | firefox | safari | edge | random
    evasion_ua_strategy: str = "sticky_host"  # sticky_session | sticky_host | rotate
    evasion_jitter_min_ms: int = 50
    evasion_jitter_max_ms: int = 400
    evasion_referer_chain: bool = True
    evasion_language_rotate: bool = True
    evasion_adaptive_backoff: bool = True
    evasion_challenge_detect: bool = True
    evasion_decoy_requests: bool = False
    evasion_http2: bool = True

    # Defense verification (catch vs unchallenged — not CAPTCHA solving)
    defense_verify: bool = True

    def __post_init__(self):
        if not self.checkpoint_file:
            self.checkpoint_file = os.path.join(BASE_DIR, "crawl_checkpoint.json")
        if not self.enum_checkpoint_file:
            self.enum_checkpoint_file = os.path.join(BASE_DIR, "enum_checkpoint.json")
        if not self.false_positive_file:
            self.false_positive_file = os.path.join(BASE_DIR, "false_positives.json")
        self.apply_profile()

    def parsed_enum_extensions(self) -> List[str]:
        raw = self.enum_extensions or ",".join(
            ext.lstrip(".") for ext in (".php", ".asp", ".aspx", ".bak", ".old", ".txt", ".zip", ".sql", ".config", ".env")
        )
        return [part.strip().lstrip(".") for part in raw.split(",") if part.strip()]

    # Identity / paths / already-built scan state — do not overwrite on Pause→Resume
    _LIVE_FROZEN_FIELDS: ClassVar[frozenset] = frozenset(
        {
            "start_url",
            "wordlist_file",
            "extra_wordlists",
            "output_file_path",
            "download_dir",
            "checkpoint_file",
            "enum_checkpoint_file",
            "false_positive_file",
            "resume_checkpoint",
            "resume_enum_checkpoint",
            "login_url",
            "login_username",
            "login_password",
            "use_selenium_login",
            "schedule_interval_hours",
            "distributed_redis_url",
        }
    )

    def apply_live_settings(self, source: "CrawlConfig") -> List[str]:
        """Copy mutable GUI settings onto this running config. Returns changed field names."""
        changed: List[str] = []
        for item in fields(self):
            name = item.name
            if name in self._LIVE_FROZEN_FIELDS:
                continue
            old = getattr(self, name)
            new = getattr(source, name)
            if old != new:
                setattr(self, name, new)
                changed.append(name)
        return changed

    def apply_profile(self):
        if self.profile == "quick":
            self.max_depth = min(self.max_depth, 1)
            self.subdomain_enum = False
            self.wayback_seeds = False
            self.common_crawl_seeds = False
            self.warc_export = False
            self.screenshot_capture = False
            self.security_scan = False
            self.form_submit_probe = False
        elif self.profile == "stealth":
            self.enum_concurrency = min(self.enum_concurrency, 20)
            self.download_concurrency = min(self.download_concurrency, 2)
            self.crawl_concurrency = min(self.crawl_concurrency, 2)
            self.evasion_enabled = True
            self.evasion_level = "stealth"
            self.evasion_ua_strategy = "sticky_host"
            self.evasion_jitter_min_ms = max(self.evasion_jitter_min_ms, 40)
            self.evasion_jitter_max_ms = max(self.evasion_jitter_max_ms, 250)
            self.evasion_referer_chain = True
            self.evasion_adaptive_backoff = True
            self.evasion_challenge_detect = True
            self.evasion_decoy_requests = False
            if not self.enum_word_limit:
                self.enum_word_limit = 25000
        elif self.profile == "gobuster":
            self.enum_only = True
            self.enum_flat_scan = True
            self.gobuster_style_extensions = True
            self.legacy_wordlist_expansion = False
            self.extension_aware_wordlist = False
            # Enum parallelism comes from GUI Speed / spins — do not force 80 here
            self.wildcard_detection = True
            self.response_fingerprint = True
            self.smart_wordlist_order = True
            self.smart_false_positive = True
            self.max_depth = 0
            self.download_files = False
            self.subdomain_enum = False
            self.wayback_seeds = True
            self.security_scan = False
            self.enum_auto_vuln_scan = True
            self.enum_auto_crawl_hits = True
            self.queue_enum_for_crawl = True

    def httpx_proxy(self) -> Optional[str]:
        return self.proxy_url.strip() or None

    def httpx_auth(self):
        if self.auth_username:
            return (self.auth_username, self.auth_password or "")
        return None

    def merged_headers(self, base_headers: dict) -> dict:
        headers = dict(base_headers)
        headers.update(self.custom_headers)
        return headers

    def report_dir(self) -> str:
        path = os.path.join(BASE_DIR, "Reports")
        os.makedirs(path, exist_ok=True)
        return path
