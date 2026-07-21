"""UX mode presets — map Run modes to CrawlConfig defaults (all features retained)."""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

MODES = ("fast_scan", "site_map", "full_audit", "deep_audit")

MODE_LABELS = {
    "fast_scan": "Fast Scan — quick hidden-path hunt (capped wordlist)",
    "site_map": "Site Map — crawl and mirror",
    "full_audit": "Full Audit — crawl + security (directory enum opt-in)",
    "deep_audit": "Deep Audit — crawl + security + heavy directory enum",
}

# Parallelism sweet-spot profiles (asyncio in-flight limits, not OS threads)
SPEED_PROFILES: Dict[str, Dict[str, Any]] = {
    "gentle": {
        "label": "Gentle — easy on the target",
        "crawl": 2,
        "enum": 15,
        "download": 3,
    },
    "balanced": {
        "label": "Balanced — sweet spot (recommended)",
        "crawl": 4,
        "enum": 35,
        "download": 6,
    },
    "fast": {
        "label": "Fast — sturdy lab hosts",
        "crawl": 6,
        "enum": 55,
        "download": 10,
    },
    "aggressive": {
        "label": "Aggressive — max parallel",
        "crawl": 10,
        "enum": 80,
        "download": 16,
    },
}

SPEED_ORDER = ("gentle", "balanced", "fast", "aggressive")

MODE_PRESETS: Dict[str, Dict[str, Any]] = {
    "fast_scan": {
        "profile": "gobuster",
        "enum_only": True,
        "directory_enum": True,
        "enum_flat_scan": True,
        "download_files": False,
        "use_wordlist": True,
        "mutation_enum": True,
        "mutation_builtin": True,
        "mutation_from_seeds": True,
        "wildcard_detection": True,
        "gobuster_style_extensions": True,
        "legacy_wordlist_expansion": False,
        "smart_wordlist_order": True,
        "security_scan": False,
        "enum_auto_vuln_scan": True,
        "wayback_seeds": False,
        "subdomain_enum": False,
        "evasion_enabled": True,
        "evasion_level": "basic",
        "evasion_decoy_requests": False,
        "enum_word_limit": 20000,
        "mutation_max_candidates": 3000,
        "evasion_jitter_min_ms": 0,
        "evasion_jitter_max_ms": 40,
        "speed": "fast",
    },
    "site_map": {
        "profile": "full",
        "enum_only": False,
        "directory_enum": False,
        "download_files": True,
        "use_wordlist": False,
        "mutation_enum": False,
        "wildcard_detection": True,
        "security_scan": False,
        "wayback_seeds": True,
        "subdomain_enum": False,
        "search_conclusion_report": False,
        "evasion_level": "basic",
        "enum_word_limit": 5000,
        "evasion_decoy_requests": False,
        "mirror_page_assets": True,
        "speed": "balanced",
        # Mirror-biased tweak on top of Balanced
        "crawl_concurrency": 5,
        "enum_concurrency": 20,
        "download_concurrency": 8,
    },
    # Default audit: crawl + security; directory enum is opt-in (slowest phase)
    "full_audit": {
        "profile": "full",
        "enum_only": False,
        "directory_enum": False,
        "download_files": False,
        "use_wordlist": False,
        "mutation_enum": False,
        "mutation_builtin": True,
        "mutation_from_seeds": True,
        "security_scan": True,
        "vuln_scan": True,
        "search_conclusion_report": True,
        "enum_auto_vuln_scan": True,
        "enum_flat_scan": True,
        "auto_prefix_enum": False,
        "wayback_seeds": False,
        "common_crawl_seeds": False,
        "subdomain_enum": False,
        "api_recon": True,
        "api_recon_active": True,
        "api_recon_graphql": True,
        "api_recon_word_limit": 800,
        "evasion_enabled": True,
        "evasion_level": "basic",
        "evasion_decoy_requests": False,
        "enum_word_limit": 3000,
        "mutation_max_candidates": 1500,
        "max_depth": 2,
        "link_depth_limit": 5,
        "broken_link_sample_size": 10,
        "evasion_jitter_min_ms": 0,
        "evasion_jitter_max_ms": 60,
        "defense_verify": True,
        "vuln_active_probe": True,
        "speed": "fast",
    },
    # Opt-in heavy directory enum — prefixes × depth × large wordlist
    "deep_audit": {
        "profile": "full",
        "enum_only": False,
        "directory_enum": True,
        "download_files": False,
        "use_wordlist": True,
        "mutation_enum": True,
        "mutation_builtin": True,
        "mutation_from_seeds": True,
        "security_scan": True,
        "vuln_scan": True,
        "search_conclusion_report": True,
        "enum_auto_vuln_scan": True,
        "enum_flat_scan": False,
        "auto_prefix_enum": True,
        "wayback_seeds": True,
        "common_crawl_seeds": True,
        "subdomain_enum": False,
        "api_recon": True,
        "api_recon_active": True,
        "api_recon_graphql": True,
        "api_recon_word_limit": 3000,
        "evasion_enabled": True,
        "evasion_level": "basic",
        "evasion_decoy_requests": False,
        "browser_primary": True,
        "browser_on_challenge": True,
        "auto_sync_cookies": True,
        "enum_word_limit": 15000,
        "mutation_max_candidates": 5000,
        "max_depth": 3,
        "link_depth_limit": 0,
        "broken_link_sample_size": 30,
        "evasion_jitter_min_ms": 0,
        "evasion_jitter_max_ms": 60,
        "defense_verify": True,
        "vuln_active_probe": True,
        "speed": "balanced",
    },
}


def concurrency_for_speed(speed: str) -> Tuple[int, int, int]:
    profile = SPEED_PROFILES.get(speed) or SPEED_PROFILES["balanced"]
    return int(profile["crawl"]), int(profile["enum"]), int(profile["download"])


def match_speed_profile(crawl: int, enum: int, download: int) -> Optional[str]:
    for key in SPEED_ORDER:
        p = SPEED_PROFILES[key]
        if p["crawl"] == crawl and p["enum"] == enum and p["download"] == download:
            return key
    return None


def apply_speed_profile(app, speed: str):
    """Set crawl / enum / download spins from a named speed profile."""
    if speed not in SPEED_PROFILES:
        speed = "balanced"
    crawl, enum, download = concurrency_for_speed(speed)
    applying = getattr(app, "_applying_speed", False)
    app._applying_speed = True
    try:
        if hasattr(app, "crawl_concurrency_spin"):
            app.crawl_concurrency_spin.setValue(crawl)
        if hasattr(app, "enum_concurrency_spin"):
            app.enum_concurrency_spin.setValue(enum)
        if hasattr(app, "download_concurrency_spin"):
            app.download_concurrency_spin.setValue(download)
        if hasattr(app, "speed_combo"):
            idx = app.speed_combo.findData(speed)
            if idx < 0:
                idx = app.speed_combo.findText(SPEED_PROFILES[speed]["label"])
            if idx >= 0:
                app.speed_combo.setCurrentIndex(idx)
    finally:
        app._applying_speed = applying


def apply_mode_preset(app, mode: str):
    """Apply preset values to GUI widgets (does not hide expert controls)."""
    preset = MODE_PRESETS.get(mode, {})
    mapping = {
        "enum_only_cb": "enum_only",
        "directory_enum_cb": "directory_enum",
        "enum_flat_cb": "enum_flat_scan",
        "download_radio": "download_files",
        "crawl_only_radio": lambda p: not p.get("download_files", False),
        "use_wordlist_cb": "use_wordlist",
        "mutation_enum_cb": "mutation_enum",
        "mutation_builtin_cb": "mutation_builtin",
        "mutation_seeds_cb": "mutation_from_seeds",
        "wildcard_cb": "wildcard_detection",
        "enum_follow_redirects_cb": "enum_follow_redirects",
        "gobuster_ext_cb": "gobuster_style_extensions",
        "ext_wordlist_cb": "legacy_wordlist_expansion",
        "smart_wl_cb": "smart_wordlist_order",
        "auto_prefix_cb": "auto_prefix_enum",
        "security_cb": "security_scan",
        "vuln_cb": "vuln_scan",
        "enum_auto_vuln_cb": "enum_auto_vuln_scan",
        "wayback_cb": "wayback_seeds",
        "cc_cb": "common_crawl_seeds",
        "subdomain_cb": "subdomain_enum",
        "api_recon_cb": "api_recon",
        "api_active_cb": "api_recon_active",
        "api_graphql_cb": "api_recon_graphql",
        "search_conclusion_cb": "search_conclusion_report",
        "evasion_enabled_cb": "evasion_enabled",
        "evasion_referer_cb": "evasion_referer_chain",
        "evasion_lang_cb": "evasion_language_rotate",
        "evasion_backoff_cb": "evasion_adaptive_backoff",
        "evasion_challenge_cb": "evasion_challenge_detect",
        "evasion_decoy_cb": "evasion_decoy_requests",
        "evasion_http2_cb": "evasion_http2",
        "defense_verify_cb": "defense_verify",
        "mirror_assets_cb": "mirror_page_assets",
        "vuln_probe_cb": "vuln_active_probe",
    }
    if "profile" in preset and hasattr(app, "profile_combo"):
        idx = app.profile_combo.findText(preset["profile"])
        if idx >= 0:
            app.profile_combo.setCurrentIndex(idx)
    if "evasion_level" in preset and hasattr(app, "evasion_level_combo"):
        idx = app.evasion_level_combo.findText(preset["evasion_level"])
        if idx >= 0:
            app.evasion_level_combo.setCurrentIndex(idx)
    for widget_name, key in mapping.items():
        widget = getattr(app, widget_name, None)
        if widget is None:
            continue
        if callable(key):
            val = key(preset)
        else:
            val = preset.get(key)
        if val is None:
            continue
        if hasattr(widget, "setChecked"):
            widget.setChecked(bool(val))

    if "enum_word_limit" in preset and hasattr(app, "enum_word_limit_spin"):
        app.enum_word_limit_spin.setValue(int(preset["enum_word_limit"]))
    if "api_recon_word_limit" in preset and hasattr(app, "api_word_limit_spin"):
        app.api_word_limit_spin.setValue(int(preset["api_recon_word_limit"]))
    if "mutation_max_candidates" in preset and hasattr(app, "mutation_max_spin"):
        app.mutation_max_spin.setValue(int(preset["mutation_max_candidates"]))
    if "evasion_jitter_min_ms" in preset and hasattr(app, "evasion_jitter_min_spin"):
        app.evasion_jitter_min_spin.setValue(int(preset["evasion_jitter_min_ms"]))
    if "evasion_jitter_max_ms" in preset and hasattr(app, "evasion_jitter_max_spin"):
        app.evasion_jitter_max_spin.setValue(int(preset["evasion_jitter_max_ms"]))
    if "max_depth" in preset and hasattr(app, "depth_spin"):
        app.depth_spin.setValue(int(preset["max_depth"]))
    if "link_depth_limit" in preset and hasattr(app, "link_depth_spin"):
        app.link_depth_spin.setValue(int(preset["link_depth_limit"]))
    if "broken_link_sample_size" in preset and hasattr(app, "broken_sample_spin"):
        app.broken_sample_spin.setValue(int(preset["broken_link_sample_size"]))

    speed = preset.get("speed", "balanced")
    apply_speed_profile(app, speed)

    # Optional mode-specific overrides (e.g. Site Map download bias)
    app._applying_speed = True
    try:
        if "crawl_concurrency" in preset and hasattr(app, "crawl_concurrency_spin"):
            app.crawl_concurrency_spin.setValue(int(preset["crawl_concurrency"]))
        if "enum_concurrency" in preset and hasattr(app, "enum_concurrency_spin"):
            app.enum_concurrency_spin.setValue(int(preset["enum_concurrency"]))
        if "download_concurrency" in preset and hasattr(app, "download_concurrency_spin"):
            app.download_concurrency_spin.setValue(int(preset["download_concurrency"]))
    finally:
        app._applying_speed = False

    if hasattr(app, "_sync_speed_combo_from_spins"):
        app._sync_speed_combo_from_spins()

    app._sync_wordlist_controls()
