"""Expert settings catalog — dropdowns and prefills across all groups."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "web" / "api"
if str(API) not in sys.path:
    sys.path.insert(0, str(API))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vantacrawl_api.scan_settings import SETTING_GROUPS, default_settings, setting_fields  # noqa: E402


REQUIRED_SELECTS = {
    "profile",
    "scope_mode",
    "active_probe_mode",
    "enum_method",
    "api_recon_method",
    "nuclei_severity",
    "evasion_level",
    "evasion_browser",
    "evasion_ua_strategy",
}

REQUIRED_TEXT_PRESETS = {
    "enum_extensions",
    "enum_status_blacklist",
    "enum_status_whitelist",
    "exclude_lengths",
    "enum_prefixes",
    "extensions",
    "api_auth_header_name",
    "ssrf_callback_base",
    "oob_callback_poll_url",
    "redirect_proof_host",
    "traversal_canary_path",
    "traversal_canary_expected_content",
    "proxy_url",
    "secret_org_hints",
}

REQUIRED_NUMBER_PRESETS = {
    "max_depth",
    "crawl_concurrency",
    "enum_concurrency",
    "download_concurrency",
    "secret_validate_max",
    "broken_link_sample_size",
    "active_probe_max_params",
    "active_probe_max_forms",
    "bm_cookie_wait_seconds",
    "checkpoint_interval",
    "disk_space_guard_mb",
    "schedule_interval_hours",
    "evasion_jitter_min_ms",
    "evasion_jitter_max_ms",
    "subdomain_enum_limit",
    "api_recon_word_limit",
}


def test_every_group_has_at_least_one_dropdown_or_preset() -> None:
    fields = setting_fields()
    for group in SETTING_GROUPS:
        keys = group["keys"]
        enriched = [
            k
            for k in keys
            if fields.get(k, {}).get("control")
            in {"select", "text_with_presets", "number_with_presets"}
        ]
        # Reports is almost all booleans — still OK if empty, but every other group must have UX helpers.
        if group["id"] == "reports":
            continue
        assert enriched, f"group {group['id']} has no select/preset fields"


def test_required_controls_and_nonempty_choices() -> None:
    fields = setting_fields()
    for key in REQUIRED_SELECTS:
        meta = fields[key]
        assert meta["control"] == "select", key
        assert meta["options"], key
        values = [o["value"] for o in meta["options"]]
        assert len(values) == len(set(values)), f"duplicate options for {key}"
    for key in REQUIRED_TEXT_PRESETS:
        meta = fields[key]
        assert meta["control"] == "text_with_presets", key
        assert meta["presets"], key
    for key in REQUIRED_NUMBER_PRESETS:
        meta = fields[key]
        assert meta["control"] == "number_with_presets", key
        assert meta["presets"], key
        for preset in meta["presets"]:
            float(preset["value"])  # numeric-parseable


def test_active_probe_and_scope_mode_options() -> None:
    fields = setting_fields()
    modes = {o["value"] for o in fields["active_probe_mode"]["options"]}
    assert modes == {"passive", "safe", "extended", "lab"}
    scopes = {o["value"] for o in fields["scope_mode"]["options"]}
    assert scopes == {"exact-origin", "allowed-subdomains", "off"}


def test_defaults_match_select_and_number_presets_where_applicable() -> None:
    fields = setting_fields()
    defaults = default_settings()
    for key in ("active_probe_mode", "scope_mode", "profile", "nuclei_severity", "enum_method"):
        current = str(defaults[key])
        values = {o["value"] for o in fields[key]["options"]}
        assert current in values, f"default {key}={current!r} missing from options"
    for key in ("secret_validate_max", "active_probe_max_params", "active_probe_max_forms", "max_depth"):
        current = str(int(defaults[key]))
        values = {p["value"] for p in fields[key]["presets"]}
        assert current in values, f"default {key}={current!r} missing from number presets"
