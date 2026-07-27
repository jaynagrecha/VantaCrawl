"""Checkpoint save/load for pause and resume."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Tuple


def save_checkpoint(
    path: str,
    visited: List[str],
    discovered: List[str],
    queue: List[str],
    enum_stack: Optional[List] = None,
    start_url: str = "",
    link_depths: Optional[Dict[str, int]] = None,
):
    payload = {
        "start_url": start_url,
        "visited": visited,
        "discovered": discovered,
        "queue": queue,
        "enum_stack": enum_stack or [],
        "link_depths": link_depths or {},
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)
    os.replace(tmp, path)


def load_checkpoint(path: str) -> Optional[Dict[str, Any]]:
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None


def restore_sets(data: Dict[str, Any]) -> Tuple[set, set, list, dict]:
    visited = set(data.get("visited", []))
    discovered = set(data.get("discovered", []))
    queue = list(data.get("queue", []))
    link_depths = dict(data.get("link_depths", {}))
    return visited, discovered, queue, link_depths


def save_enum_checkpoint(
    path: str,
    start_url: str,
    word_index: int,
    path_segments: List[str],
    depth: int,
    found_urls: List[str],
    *,
    enumeration_state: str = "",
    remaining_base_words: int = 0,
    resume_allowed: Optional[bool] = None,
):
    payload = {
        "start_url": start_url,
        "word_index": int(word_index or 0),
        "last_attempted_word_index": int(word_index or 0),
        "path_segments": path_segments,
        "depth": depth,
        "found_urls": found_urls,
        "enumeration_state": enumeration_state
        or ("completed" if remaining_base_words <= 0 else "in_progress"),
        "remaining_base_words": int(remaining_base_words or 0),
        "resume_allowed": (
            bool(resume_allowed)
            if resume_allowed is not None
            else bool(remaining_base_words > 0)
        ),
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)
    os.replace(tmp, path)


def load_enum_checkpoint(path: str) -> Optional[Dict[str, Any]]:
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
