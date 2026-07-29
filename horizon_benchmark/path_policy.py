"""Benchmark-only Horizon path policy (fixture demotions).

Production verifier packages must not import fixture routes from here.
Inventory uses these demotions so incomplete XSS subtypes are not counted as
supported_active merely because the XSS family is executable.
"""

from __future__ import annotations

from typing import Dict

# Keys are Horizon Catalog fixture paths. Values are demotion reasons.
PARTIAL_OR_PASSIVE_PATHS: Dict[str, str] = {
    "/xss/angular": "browser_framework_sink_not_fully_executable",
    "/xss/postmessage": "postmessage_channel_not_fully_executable",
    "/xss/markdown": "markdown_renderer_path_partial",
    "/xss/stored": "stored_xss_requires_multi_request_state",
    "/xss/base-tag": "base_tag_sink_partial",
    "/xss/dangling": "dangling_markup_partial",
    "/xss/svg": "svg_context_partial",
    "/xss/dom": "dom_xss_without_clobber_ladder",
}


def path_demotion_reason(path: str) -> str:
    return PARTIAL_OR_PASSIVE_PATHS.get((path or "").strip(), "")
