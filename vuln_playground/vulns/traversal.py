"""Path traversal / LFI-style canary sinks."""

from __future__ import annotations

import html
from pathlib import Path
from typing import Dict

from http_util import page, send
from registry import register

ROOT = Path(__file__).resolve().parents[1]
CANARY = ROOT / "fixtures" / "canary.txt"
NOTE = ROOT / "fixtures" / "notes" / "note.txt"
CANARY_CONTENT = CANARY.read_text(encoding="utf-8").strip() if CANARY.exists() else "PLAYGROUND_CANARY_TOKEN"


@register(
    "/trav/view",
    title="Traversal / file view",
    family="traversal",
    expected="canary_file_confirmed when canary configured; else differential on ..",
    tags=["active", "lab"],
)
def trav_view(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    file_param = params.get("file", "note.txt")
    text = "not found"
    status = 404
    if "canary.txt" in file_param or "PLAYGROUND_CANARY" in file_param or "fixtures" in file_param:
        text = f"file content {CANARY_CONTENT}"
        status = 200
    elif file_param in ("note.txt", "notes/note.txt") or file_param.endswith("note.txt"):
        text = NOTE.read_text(encoding="utf-8") if NOTE.exists() else "note: hello"
        status = 200
    elif ".." in file_param or "%2e%2e" in file_param.lower():
        text = f"normalized path error for {file_param}"
        status = 400
    send(handler, status, page("Traversal", f"<pre>{html.escape(text)}</pre>"), head_only=head_only)


@register(
    "/trav/download",
    title="Traversal download alias",
    family="traversal",
    expected="directory_traversal / canary on path",
    tags=["active"],
)
def trav_download(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    path = params.get("path", "note.txt")
    return trav_view(handler, {"file": path}, head_only=head_only)
