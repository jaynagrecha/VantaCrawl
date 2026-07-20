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
    from gui_presets import MODE_PRESETS

    assert MODE_PRESETS["fast_scan"]["speed"] == "fast"
    assert MODE_PRESETS["full_audit"]["speed"] == "balanced"
    assert MODE_PRESETS["site_map"]["download_concurrency"] == 8
