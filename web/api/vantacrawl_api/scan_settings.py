"""Web scan settings catalog — mirrors desktop CrawlConfig + mode presets."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List

# Repo root on sys.path so gui_presets / crawl_config import
ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from crawl_config import CrawlConfig  # noqa: E402
from gui_presets import (  # noqa: E402
    MODE_LABELS,
    MODE_PRESETS,
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
    "distributed_redis_url",
    "login_password",
    "auth_password",
}


def default_settings() -> Dict[str, Any]:
    cfg = CrawlConfig(start_url="https://example.com")
    data = {k: getattr(cfg, k) for k in cfg.__dataclass_fields__}
    for key in EDITABLE_DEFAULTS_SKIP:
        data.pop(key, None)
    # Don't ship secrets/placeholders
    data.pop("custom_headers", None)
    return data


SETTING_GROUPS: List[Dict[str, Any]] = [
    {
        "id": "core",
        "title": "Core",
        "keys": [
            "restrict_domain",
            "max_depth",
            "link_depth_limit",
            "crawl_concurrency",
            "enum_concurrency",
            "download_concurrency",
            "ignore_robots",
            "bypass_forbidden",
            "enum_only",
            "enum_flat_scan",
        ],
    },
    {
        "id": "discovery",
        "title": "Discovery",
        "keys": [
            "wayback_seeds",
            "common_crawl_seeds",
            "subdomain_enum",
            "openapi_parse",
            "js_bundle_analysis",
            "form_discovery",
            "form_submit_probe",
            "rss_feeds",
            "use_wordlist",
            "mutation_enum",
            "mutation_builtin",
            "mutation_from_seeds",
            "enum_word_limit",
            "mutation_max_candidates",
        ],
    },
    {
        "id": "enum",
        "title": "Directory enum",
        "keys": [
            "wildcard_detection",
            "gobuster_style_extensions",
            "smart_wordlist_order",
            "enum_extensions",
            "enum_status_blacklist",
            "enum_method",
            "enum_auto_crawl_hits",
            "enum_auto_vuln_scan",
            "vhost_enum",
            "s3_enum",
            "gcs_enum",
            "smart_false_positive",
            "false_positive_learning",
        ],
    },
    {
        "id": "security",
        "title": "Security",
        "keys": [
            "security_scan",
            "vuln_scan",
            "vuln_active_probe",
            "secret_scan",
            "header_audit",
            "cors_check",
            "param_discovery",
            "tech_fingerprint",
            "sensitive_file_highlights",
            "broken_link_report",
            "defense_verify",
            "active_probe_max_params",
            "active_probe_max_forms",
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
            "duplicate_content_detection",
            "warc_export",
            "skip_tracking_downloads",
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
            "evasion_adaptive_backoff",
            "evasion_challenge_detect",
            "evasion_decoy_requests",
            "evasion_http2",
        ],
    },
    {
        "id": "reports",
        "title": "Reports",
        "keys": [
            "html_report",
            "json_report",
            "csv_export",
            "sqlite_export",
            "search_conclusion_report",
            "site_graph_export",
        ],
    },
]


def meta_payload() -> Dict[str, Any]:
    return {
        "modes": {
            key: {"label": MODE_LABELS.get(key, key), "preset": MODE_PRESETS.get(key, {})}
            for key in MODE_PRESETS
        },
        "speeds": SPEED_PROFILES,
        "default_settings": default_settings(),
        "setting_groups": SETTING_GROUPS,
    }
