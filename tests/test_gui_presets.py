from gui_presets import (
    SPEED_PROFILES,
    concurrency_for_speed,
    match_speed_profile,
)


def test_balanced_sweet_spot():
    crawl, enum, download = concurrency_for_speed("balanced")
    assert crawl == 4
    assert enum == 35
    assert download == 6


def test_match_speed_profile():
    p = SPEED_PROFILES["fast"]
    assert match_speed_profile(p["crawl"], p["enum"], p["download"]) == "fast"
    assert match_speed_profile(4, 35, 7) is None


def test_mode_presets_have_speed():
    from gui_presets import MODE_PRESETS, MODES

    assert MODE_PRESETS["fast_scan"]["speed"] == "fast"
    assert MODE_PRESETS["full_audit"]["speed"] == "fast"
    assert MODE_PRESETS["site_map"]["download_concurrency"] == 8
    assert "deep_audit" in MODES
    assert MODE_PRESETS["deep_audit"]["speed"] == "balanced"


def test_full_audit_is_practical_deep_is_opt_in_heavy():
    from gui_presets import MODE_PRESETS

    full = MODE_PRESETS["full_audit"]
    deep = MODE_PRESETS["deep_audit"]
    assert full["enum_flat_scan"] is True
    assert full["auto_prefix_enum"] is False
    assert full["enum_word_limit"] <= 3000
    assert full["wayback_seeds"] is False
    assert deep["enum_flat_scan"] is False
    assert deep["auto_prefix_enum"] is True
    assert deep["enum_word_limit"] >= 15000
    assert deep["wayback_seeds"] is True
